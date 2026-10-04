package verify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	configadapter "github.com/nilstate/scafld/v2/internal/adapters/config"
	"github.com/nilstate/scafld/v2/internal/adapters/corebundle"
	"github.com/nilstate/scafld/v2/internal/adapters/git"
	"github.com/nilstate/scafld/v2/internal/adapters/process"
	appacceptance "github.com/nilstate/scafld/v2/internal/app/acceptance"
	appverify "github.com/nilstate/scafld/v2/internal/app/verify"
	"github.com/nilstate/scafld/v2/internal/core/execution"
	"github.com/nilstate/scafld/v2/internal/core/receipt"
	"github.com/nilstate/scafld/v2/internal/core/reviewevidence"
	"github.com/nilstate/scafld/v2/internal/core/runartifact"
	"github.com/nilstate/scafld/v2/internal/core/trust"
	"github.com/nilstate/scafld/v2/internal/platform/processguard"
)

// Options configures the verify CLI adapter.
type Options struct {
	Root           string
	ReceiptPath    string
	TrustedKeys    string
	Target         string
	MaterialRef    string
	AcceptanceRoot string
	MaterialOnly   bool
	JSON           bool
	CI             bool
	SelfCheck      bool
}

// Handler returns a CLI-compatible verify handler.
func Handler() func(context.Context, []string, io.Writer, io.Writer) int {
	return func(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
		opts, err := Parse(args)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if opts.SelfCheck {
			report, err := SelfCheck(ctx, opts.Root)
			if err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 2
			}
			fmt.Fprint(stdout, RenderSelfCheck(report))
			return 0
		}
		out, err := Run(ctx, opts)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if !out.Passed {
			fmt.Fprintf(stderr, "verify failed: %s\n", out.Reason)
			return 3
		}
		if out.Reason == "material verified" {
			fmt.Fprintln(stdout, "verify material passed")
			return 0
		}
		fmt.Fprintln(stdout, "verify passed")
		return 0
	}
}

// Run loads the receipt and trusted keys, composes ports, and verifies.
func Run(ctx context.Context, opts Options) (appverify.Result, error) {
	if opts.Root == "" {
		opts.Root = "."
	}
	cfg, err := configadapter.LoadBase(ctx, opts.Root)
	if err != nil {
		return appverify.Result{}, fmt.Errorf("load config: %w", err)
	}
	target := strings.TrimSpace(opts.Target)
	ci := opts.CI || truthy(os.Getenv("CI"))
	if ci && target == "" {
		return appverify.Result{Passed: false, Reason: "missing target in CI policy"}, nil
	}
	trustedKeysPath := firstNonEmpty(opts.TrustedKeys, os.Getenv("SCAFLD_TRUSTED_KEYS"))
	if ci && trustedKeysPath == "" {
		return appverify.Result{Passed: false, Reason: "missing CI trusted keys path"}, nil
	}
	if trustedKeysPath == "" {
		trustedKeysPath = cfg.Verify.TrustedKeysPath
	}
	trusted, err := loadTrustedKeys(resolveRootPath(opts.Root, trustedKeysPath))
	if err != nil {
		return appverify.Result{}, err
	}
	receiptPath := firstNonEmpty(opts.ReceiptPath, os.Getenv("SCAFLD_RECEIPT_PATH"), cfg.Verify.ReceiptPath)
	if receiptPath == "" {
		return appverify.Result{}, errors.New("receipt path is required")
	}
	envelope, err := loadReceipt(resolveRootPath(opts.Root, receiptPath))
	if err != nil {
		return appverify.Result{}, err
	}
	execCfg := configadapter.EffectiveExecution(opts.Root, cfg.Execution)
	acceptanceRoot := opts.Root
	acceptanceEnv := execCfg.ProcessEnv()
	acceptanceEnvMode := execution.EnvModeInherit
	cleanupAcceptanceEnv := func() {}
	materialRef := strings.TrimSpace(opts.MaterialRef)
	acceptanceRootFlag := strings.TrimSpace(opts.AcceptanceRoot)
	if opts.MaterialOnly && acceptanceRootFlag != "" {
		return appverify.Result{Passed: false, Reason: "material-only verify does not accept acceptance-root"}, nil
	}
	var materialCommit string
	if materialRef != "" {
		materialCommit, err = git.Adapter{Root: opts.Root}.ResolveCommit(ctx, materialRef)
		if err != nil {
			return appverify.Result{}, fmt.Errorf("resolve material ref: %w", err)
		}
	}
	if !opts.MaterialOnly && materialRef != "" && acceptanceRootFlag == "" {
		rootHead, ok, err := git.Adapter{Root: opts.Root}.ResolveHead(ctx)
		if err != nil {
			return appverify.Result{}, fmt.Errorf("resolve root HEAD: %w", err)
		}
		if !ok || rootHead != materialCommit {
			return appverify.Result{Passed: false, Reason: "material-ref requires acceptance-root unless --material-only"}, nil
		}
		acceptanceRootFlag = opts.Root
	}
	if acceptanceRootFlag != "" {
		if materialRef == "" {
			return appverify.Result{Passed: false, Reason: "acceptance-root requires material-ref"}, nil
		}
		acceptanceRoot = acceptanceRootFlag
		acceptanceHead, ok, err := git.Adapter{Root: acceptanceRoot}.ResolveHead(ctx)
		if err != nil {
			return appverify.Result{}, fmt.Errorf("resolve acceptance root HEAD: %w", err)
		}
		if !ok || acceptanceHead != materialCommit {
			return appverify.Result{Passed: false, Reason: "acceptance-root HEAD does not match material-ref"}, nil
		}
		acceptanceState, err := git.Adapter{Root: acceptanceRoot}.ExactStatus(ctx)
		if err != nil {
			return appverify.Result{Passed: false, Reason: "acceptance-root is not exact material: " + err.Error()}, nil
		}
		if len(acceptanceState.Changed) != 0 {
			return appverify.Result{Passed: false, Reason: "acceptance-root is not exact material: " + strings.Join(acceptanceState.Changed, ",")}, nil
		}
		acceptanceEnv, cleanupAcceptanceEnv, err = isolatedAcceptanceEnv(acceptanceEnv)
		if err != nil {
			return appverify.Result{}, err
		}
		defer cleanupAcceptanceEnv()
		restoreProcessAccess, err := processguard.DisableDumpable()
		if err != nil {
			return appverify.Result{}, err
		}
		defer restoreProcessAccess()
		acceptanceEnvMode = execution.EnvModeExact
	}
	runner := process.Runner{DiagnosticsDir: runartifact.CommandDiagnosticsDir(opts.Root, "verify"), DiagnosticName: "verify-acceptance"}
	return appverify.Run(ctx, envelope, trusted, appverify.Policy{
		TargetCommit:    target,
		MaterialRef:     materialRef,
		MaterialOnly:    opts.MaterialOnly,
		CI:              ci,
		MinIndependence: cfg.Verify.MinIndependence,
	}, appverify.Ports{
		Snapshotter:       gitSnapshotter{adapter: git.Adapter{Root: opts.Root}},
		AcceptanceRunner:  acceptanceRunner{runner: runner, root: acceptanceRoot, env: acceptanceEnv, envMode: acceptanceEnvMode, timeout: execCfg.AbsoluteTimeout(), idleTimeout: execCfg.IdleTimeout()},
		AncestryChecker:   git.Adapter{Root: opts.Root},
		SignatureVerifier: signatureVerifier{},
	})
}

type gitSnapshotter struct{ adapter git.Adapter }

func (g gitSnapshotter) Snapshot(ctx context.Context, input appverify.SnapshotInput) (appverify.Snapshot, error) {
	snapshot, err := g.adapter.Snapshot(ctx, git.SnapshotInput{Scope: input.Scope, BaseRef: input.BaseRef, TargetRef: input.TargetRef})
	if err != nil {
		return appverify.Snapshot{}, err
	}
	return snapshotForVerify(snapshot), nil
}

func snapshotForVerify(snapshot git.Snapshot) appverify.Snapshot {
	digests := make(map[string]string, len(snapshot.FileDigests))
	ignoredSet := make(map[string]struct{}, len(snapshot.IgnoredUnreviewed))
	for _, item := range snapshot.IgnoredUnreviewed {
		ignoredSet[item.Path] = struct{}{}
	}
	for _, item := range snapshot.FileDigests {
		digests[item.Path] = item.SHA256
		if item.Status == "gitlink" || reviewevidence.PinnedEvidenceExclusionReason(item.Path) != "" {
			ignoredSet[item.Path] = struct{}{}
		}
	}
	for _, item := range snapshot.DeletedPaths {
		if reviewevidence.PinnedEvidenceExclusionReason(item.Path) != "" {
			ignoredSet[item.Path] = struct{}{}
		}
	}
	ignored := make([]string, 0, len(ignoredSet))
	for path := range ignoredSet {
		ignored = append(ignored, path)
	}
	sort.Strings(ignored)
	return appverify.Snapshot{TreeSHA: snapshot.TreeSHA, BaseCommit: snapshot.BaseCommit, FileDigests: digests, Ignored: ignored}
}

type acceptanceRunner struct {
	runner      appacceptance.Runner
	root        string
	env         []string
	envMode     execution.EnvMode
	timeout     time.Duration
	idleTimeout time.Duration
}

func (a acceptanceRunner) RunAcceptance(ctx context.Context, criteria []receipt.Acceptance) ([]appverify.AcceptanceResult, error) {
	out := make([]appverify.AcceptanceResult, 0, len(criteria))
	for _, criterion := range criteria {
		// Manual evidence is intentionally non-replayable. Finalize validates it
		// through the lifecycle ledger and signs the disposition plus evidence
		// metadata into the receipt; verify preserves that signed result while
		// rerunning every executable criterion.
		if criterion.ExpectedKind == "manual" {
			out = append(out, appverify.AcceptanceResult{
				ID: criterion.ID, Status: criterion.Status, ExitCode: criterion.ExitCode,
			})
			continue
		}
		evaluated := appacceptance.Evaluate(ctx, a.runner, appacceptance.EvaluateInput{
			Criteria:    []appacceptance.Criterion{{ID: criterion.ID, Command: criterion.Command, ExpectedKind: criterion.ExpectedKind}},
			WorkDir:     a.root,
			Env:         a.env,
			EnvMode:     a.envMode,
			Timeout:     a.timeout,
			IdleTimeout: a.idleTimeout,
		})
		if len(evaluated.Results) == 0 {
			continue
		}
		result := evaluated.Results[0]
		out = append(out, appverify.AcceptanceResult{ID: result.ID, Status: result.Status, ExitCode: result.ExitCode})
	}
	return out, nil
}

type signatureVerifier struct{}

func (signatureVerifier) Verify(envelope receipt.Envelope, trusted trust.TrustedKeys) error {
	key, err := trusted.ActiveKeyAt(envelope.Signature.KeyID, envelope.Body.MintedAt)
	if err != nil {
		return err
	}
	pub, err := key.PublicKeyBytes()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature.Sig)
	if err != nil {
		return err
	}
	canonical, err := receipt.CanonicalBody(envelope.Body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
		return errors.New("invalid ed25519 signature")
	}
	return nil
}

func loadReceipt(path string) (receipt.Envelope, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return receipt.Envelope{}, fmt.Errorf("read receipt: %w", err)
	}
	return receipt.DecodeEnvelope(data)
}

func loadTrustedKeys(path string) (trust.TrustedKeys, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return trust.TrustedKeys{}, fmt.Errorf("read trusted keys: %w", err)
	}
	return trust.ParseTrustedKeys(data)
}

func resolveRootPath(root string, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(root, filepath.FromSlash(path))
}

func isolatedAcceptanceEnv(overrides []string) ([]string, func(), error) {
	home, err := os.MkdirTemp("", "scafld-verify-home-")
	if err != nil {
		return nil, nil, fmt.Errorf("create isolated acceptance home: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(home) }
	values := map[string]string{
		"CI":            firstNonEmpty(os.Getenv("CI"), "true"),
		"HOME":          home,
		"PATH":          os.Getenv("PATH"),
		"SCAFLD_VERIFY": "1",
		"TMPDIR":        os.TempDir(),
	}
	for _, item := range overrides {
		key, value, ok := strings.Cut(item, "=")
		key = strings.TrimSpace(key)
		if ok && key != "" {
			values[key] = value
		}
	}
	for _, key := range acceptanceSecretEnvKeys {
		delete(values, key)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env, cleanup, nil
}

var acceptanceSecretEnvKeys = []string{
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"ACTIONS_RUNTIME_TOKEN",
	"GH_TOKEN",
	"GITHUB_TOKEN",
}

// Parse parses verify command arguments.
func Parse(args []string) (Options, error) {
	var opts Options
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			opts.JSON = true
		case arg == "--ci":
			opts.CI = true
		case arg == "--self-check":
			opts.SelfCheck = true
		case arg == "--material-only":
			opts.MaterialOnly = true
		case arg == "--target":
			if i+1 >= len(args) {
				return Options{}, errors.New("--target requires a value")
			}
			opts.Target = args[i+1]
			i++
		case strings.HasPrefix(arg, "--target="):
			opts.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--material-ref":
			if i+1 >= len(args) {
				return Options{}, errors.New("--material-ref requires a value")
			}
			opts.MaterialRef = args[i+1]
			i++
		case strings.HasPrefix(arg, "--material-ref="):
			opts.MaterialRef = strings.TrimPrefix(arg, "--material-ref=")
		case arg == "--acceptance-root":
			if i+1 >= len(args) {
				return Options{}, errors.New("--acceptance-root requires a value")
			}
			opts.AcceptanceRoot = args[i+1]
			i++
		case strings.HasPrefix(arg, "--acceptance-root="):
			opts.AcceptanceRoot = strings.TrimPrefix(arg, "--acceptance-root=")
		case arg == "--root":
			if i+1 >= len(args) {
				return Options{}, errors.New("--root requires a value")
			}
			opts.Root = args[i+1]
			i++
		case strings.HasPrefix(arg, "--root="):
			opts.Root = strings.TrimPrefix(arg, "--root=")
		case arg == "--trusted-keys":
			if i+1 >= len(args) {
				return Options{}, errors.New("--trusted-keys requires a value")
			}
			opts.TrustedKeys = args[i+1]
			i++
		case strings.HasPrefix(arg, "--trusted-keys="):
			opts.TrustedKeys = strings.TrimPrefix(arg, "--trusted-keys=")
		case strings.HasPrefix(arg, "-"):
			return Options{}, fmt.Errorf("unknown verify argument %q", arg)
		default:
			if opts.ReceiptPath != "" {
				return Options{}, errors.New("verify accepts one receipt path")
			}
			opts.ReceiptPath = arg
		}
	}
	return opts, nil
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

const verifyWorkflowRel = ".github/workflows/scafld-verify.yml"

// SelfCheckReport is the offline wiring state scafld can confirm locally. It
// never asserts that any merge gate is active: requiring the verify check is a
// GitHub branch-protection setting scafld cannot read or set.
type SelfCheckReport struct {
	Policy            string
	WorkflowInstalled bool
	WorkflowPath      string
	TrustedKeysPath   string
	TrustedKeysStatus string
	KeyLifecycle      trust.KeyLifecycleSummary
	SigningKeyPath    string
	SigningKeyStatus  string
	SigningKeyMode    string
	// Gap is set when the declared policy implies a CI workflow that is not installed.
	Gap string
}

// SelfCheck reports, without contacting any network or service, the local
// verify wiring: the configured verify.policy and whether the CI workflow file
// is present. It reads reporting metadata only and never touches a receipt.
func SelfCheck(ctx context.Context, root string) (SelfCheckReport, error) {
	if root == "" {
		root = "."
	}
	cfg, err := configadapter.LoadBase(ctx, root)
	if err != nil {
		return SelfCheckReport{}, fmt.Errorf("load config: %w", err)
	}
	workflowPath := filepath.Join(root, filepath.FromSlash(verifyWorkflowRel))
	_, statErr := os.Stat(workflowPath)
	report := SelfCheckReport{
		Policy:            cfg.Verify.Policy,
		WorkflowInstalled: statErr == nil,
		WorkflowPath:      verifyWorkflowRel,
		TrustedKeysPath:   cfg.Verify.TrustedKeysPath,
	}
	report.TrustedKeysStatus, report.KeyLifecycle = inspectTrustedKeys(root, cfg.Verify.TrustedKeysPath, time.Now().UTC())
	report.SigningKeyPath, report.SigningKeyStatus, report.SigningKeyMode = inspectSigningKey()
	if !report.WorkflowInstalled && (cfg.Verify.Policy == "advisory" || cfg.Verify.Policy == "required") {
		report.Gap = fmt.Sprintf("verify.policy is %q but %s is not installed; run scafld init --ci to add it", cfg.Verify.Policy, verifyWorkflowRel)
	}
	return report, nil
}

// RenderSelfCheck renders a SelfCheckReport for humans. It states plainly what
// scafld can and cannot confirm and never claims a merge gate is enforced.
func RenderSelfCheck(report SelfCheckReport) string {
	var b strings.Builder
	b.WriteString("scafld verify self-check (offline)\n")
	fmt.Fprintf(&b, "verify.policy: %s\n", report.Policy)
	if report.WorkflowInstalled {
		fmt.Fprintf(&b, "CI workflow: installed (%s)\n", report.WorkflowPath)
	} else {
		fmt.Fprintf(&b, "CI workflow: not installed (%s); run scafld init --ci to add the PR merge gate\n", report.WorkflowPath)
	}
	fmt.Fprintf(&b, "trusted keys: %s (%s)\n", report.TrustedKeysStatus, report.TrustedKeysPath)
	fmt.Fprintf(&b, "key lifecycle: active=%d revoked=%d expired=%d\n", report.KeyLifecycle.Active, report.KeyLifecycle.Revoked, report.KeyLifecycle.Expired)
	if report.SigningKeyMode != "" {
		fmt.Fprintf(&b, "signing key: %s (%s, mode %s)\n", report.SigningKeyStatus, report.SigningKeyPath, report.SigningKeyMode)
	} else {
		fmt.Fprintf(&b, "signing key: %s (%s)\n", report.SigningKeyStatus, report.SigningKeyPath)
	}
	if report.Gap != "" {
		fmt.Fprintf(&b, "gap: %s\n", report.Gap)
	}
	b.WriteString("note: requiring this check before merge is a GitHub branch-protection setting that scafld cannot read or set; confirm it in your repository settings.\n")
	b.WriteString("scafld confirms local wiring only and does not assert that any merge gate is active.\n")
	return b.String()
}

func inspectTrustedKeys(root string, configuredPath string, now time.Time) (string, trust.KeyLifecycleSummary) {
	if strings.TrimSpace(configuredPath) == "" {
		return "not configured", trust.KeyLifecycleSummary{}
	}
	path := resolveRootPath(root, configuredPath)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return "missing", trust.KeyLifecycleSummary{}
		}
		return "unreadable: " + err.Error(), trust.KeyLifecycleSummary{}
	}
	keys, err := trust.ParseTrustedKeys(data)
	if err != nil {
		return "invalid: " + err.Error(), trust.KeyLifecycleSummary{}
	}
	return "valid", keys.LifecycleSummary(now)
}

func inspectSigningKey() (path string, status string, mode string) {
	path, err := corebundle.HostPrivateKeyPath()
	if err != nil {
		return "", "unresolved: " + err.Error(), ""
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return path, "missing", ""
		}
		return path, "unreadable: " + err.Error(), ""
	}
	perm := info.Mode().Perm()
	mode = perm.String()
	if runtime.GOOS != "windows" && perm&0o077 != 0 {
		return path, "present but permissions are too broad", mode
	}
	return path, "present", mode
}
