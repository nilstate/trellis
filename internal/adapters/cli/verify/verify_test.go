package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"os"
	"os/exec"
	"path/filepath"

	gitadapter "github.com/nilstate/scafld/v2/internal/adapters/git"
	"github.com/nilstate/scafld/v2/internal/core/receipt"
	"github.com/nilstate/scafld/v2/internal/core/trust"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"receipt.json", "--target", "main", "--material-ref", "head", "--acceptance-root", "head-worktree", "--material-only", "--ci"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ReceiptPath != "receipt.json" || opts.Target != "main" || opts.MaterialRef != "head" || opts.AcceptanceRoot != "head-worktree" || !opts.MaterialOnly || !opts.CI {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestIsolatedAcceptanceEnvOmitsCredentialVariables(t *testing.T) {
	t.Parallel()
	env, cleanup, err := isolatedAcceptanceEnv([]string{
		"GITHUB_TOKEN=config-secret",
		"GH_TOKEN=config-secret",
		"ACTIONS_RUNTIME_TOKEN=config-secret",
		"SCAFLD_TEST_MARKER=present",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		for _, secret := range acceptanceSecretEnvKeys {
			if key == secret {
				t.Fatalf("secret variable %s is present in acceptance environment", key)
			}
		}
	}
	if !slices.Contains(env, "SCAFLD_TEST_MARKER=present") {
		t.Fatal("non-secret configured environment variable was lost")
	}
}

func TestSnapshotForVerifyPreservesDigestsAndFinalizeExclusionParity(t *testing.T) {
	t.Parallel()

	snapshot := snapshotForVerify(gitadapter.Snapshot{
		TreeSHA:    "tree",
		BaseCommit: "base",
		FileDigests: []gitadapter.FileDigest{
			{Path: "api", Status: "gitlink", SHA256: "api-sha"},
			{Path: "README.md", Status: "modified", SHA256: "readme-sha"},
			{Path: "AGENTS.md", Status: "modified", SHA256: "agents-sha"},
			{Path: "nested/CLAUDE.md", Status: "modified", SHA256: "claude-sha"},
			{Path: "GEMINI.md", Status: "added", SHA256: "gemini-sha"},
			{Path: ".scafld/config.yaml", Status: "modified", SHA256: "config-sha"},
		},
		DeletedPaths:      []gitadapter.DeletedPath{{Path: "docs/AGENTS.md"}, {Path: "docs/ordinary.md"}},
		IgnoredUnreviewed: []gitadapter.IgnoredPath{{Path: "secret.env", Reason: "ignored"}},
	})

	if got, want := snapshot.Ignored, []string{".scafld/config.yaml", "AGENTS.md", "GEMINI.md", "api", "docs/AGENTS.md", "nested/CLAUDE.md", "secret.env"}; !equalStrings(got, want) {
		t.Fatalf("ignored = %v, want %v", got, want)
	}
	wantDigests := map[string]string{
		"api": "api-sha", "README.md": "readme-sha", "AGENTS.md": "agents-sha",
		"nested/CLAUDE.md": "claude-sha", "GEMINI.md": "gemini-sha", ".scafld/config.yaml": "config-sha",
	}
	if len(snapshot.FileDigests) != len(wantDigests) {
		t.Fatalf("file digests = %v, want all present files retained", snapshot.FileDigests)
	}
	for path, want := range wantDigests {
		if snapshot.FileDigests[path] != want {
			t.Fatalf("file digest %s = %q, want %q", path, snapshot.FileDigests[path], want)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestAcceptanceRunnerPreservesSignedManualEvidenceWithoutExecuting(t *testing.T) {
	t.Parallel()

	results, err := (acceptanceRunner{}).RunAcceptance(context.Background(), []receipt.Acceptance{{
		ID:                 "dogfood",
		ExpectedKind:       "manual",
		Status:             "pass",
		EvidenceSHA256:     strings.Repeat("a", 64),
		EvidenceActor:      "operator",
		EvidenceRecordedAt: "2026-08-29T00:00:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "dogfood" || results[0].Status != "pass" {
		t.Fatalf("results = %+v, want signed manual pass", results)
	}
}

func TestSelfCheckReportsWiringWithoutClaimingEnforcement(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"--self-check", "--root", "."})
	if err != nil || !opts.SelfCheck {
		t.Fatalf("Parse(--self-check) opts=%+v err=%v", opts, err)
	}

	// Default workspace: no workflow, policy local, no gap, and no enforcement claim.
	root := t.TempDir()
	report, err := SelfCheck(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.WorkflowInstalled || report.Policy != "local" || report.Gap != "" {
		t.Fatalf("default self-check report = %+v, want local/uninstalled/no-gap", report)
	}
	text := RenderSelfCheck(report)
	for _, want := range []string{"not installed", "scafld init --ci", "trusted keys:", "signing key:", "cannot read or set", "does not assert that any merge gate is active"} {
		if !strings.Contains(text, want) {
			t.Fatalf("self-check text missing %q:\n%s", want, text)
		}
	}

	// required policy without an installed workflow is surfaced as a gap, not hidden.
	gapRoot := t.TempDir()
	writeVerifyPolicyConfig(t, gapRoot, "required")
	gapReport, err := SelfCheck(context.Background(), gapRoot)
	if err != nil {
		t.Fatal(err)
	}
	if gapReport.Gap == "" || !strings.Contains(RenderSelfCheck(gapReport), "gap:") {
		t.Fatalf("required policy without workflow did not surface a gap: %+v", gapReport)
	}

	// An installed workflow is reported as installed.
	wfRoot := t.TempDir()
	writeVerifyWorkflow(t, wfRoot)
	wfReport, err := SelfCheck(context.Background(), wfRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !wfReport.WorkflowInstalled || !strings.Contains(RenderSelfCheck(wfReport), "installed (") {
		t.Fatalf("installed workflow not reported: %+v", wfReport)
	}

	// Handler path exits zero and prints the report.
	var stdout, stderr bytes.Buffer
	code := Handler()(context.Background(), []string{"--self-check", "--root", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("self-check exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "verify.policy: local") {
		t.Fatalf("handler stdout missing policy line:\n%s", stdout.String())
	}
}

func TestSelfCheckReportsTrustedKeyLifecycle(t *testing.T) {
	root := t.TempDir()
	activePub, _, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatal(err)
	}
	revokedPub, _, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("b", 64)))
	if err != nil {
		t.Fatal(err)
	}
	expiredPub, _, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("c", 64)))
	if err != nil {
		t.Fatal(err)
	}
	keys := trust.TrustedKeys{Version: trust.TrustedKeysVersion, Keys: []trust.TrustedKey{
		verifyTrustedKey(t, activePub),
		func() trust.TrustedKey {
			key := verifyTrustedKey(t, revokedPub)
			key.RevokedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			return key
		}(),
		func() trust.TrustedKey {
			key := verifyTrustedKey(t, expiredPub)
			key.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			return key
		}(),
	}}
	writeTrustedKeys(t, root, keys)

	report, err := SelfCheck(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.TrustedKeysStatus != "valid" {
		t.Fatalf("trusted key status = %q", report.TrustedKeysStatus)
	}
	if report.KeyLifecycle.Active != 1 || report.KeyLifecycle.Revoked != 1 || report.KeyLifecycle.Expired != 1 {
		t.Fatalf("lifecycle = %+v", report.KeyLifecycle)
	}
	text := RenderSelfCheck(report)
	if !strings.Contains(text, "key lifecycle: active=1 revoked=1 expired=1") {
		t.Fatalf("rendered lifecycle missing:\n%s", text)
	}
}

func writeVerifyPolicyConfig(t *testing.T, root string, policy string) {
	t.Helper()
	dir := filepath.Join(root, ".scafld")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("verify:\n  policy: "+policy+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeVerifyWorkflow(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scafld-verify.yml"), []byte("name: scafld-verify\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunMissingTargetFailsClosedInCI(t *testing.T) {
	t.Parallel()

	result, err := Run(context.Background(), Options{Root: t.TempDir(), ReceiptPath: "missing.json", CI: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed || !strings.Contains(result.Reason, "missing target") {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunMissingTrustedKeysFailsClosedInCI(t *testing.T) {
	t.Parallel()

	result, err := Run(context.Background(), Options{Root: t.TempDir(), ReceiptPath: "missing.json", Target: "main", CI: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed || !strings.Contains(result.Reason, "trusted keys") {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunUsesReceiptPathFromEnvironment(t *testing.T) {
	// Hermetic: clear the ambient CI env (GitHub Actions sets CI=true) so this
	// exercises the non-CI receipt-path resolution, not the CI-policy branch.
	t.Setenv("CI", "")
	t.Setenv("SCAFLD_RECEIPT_PATH", "env-receipt.json")

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".scafld"), 0o755); err != nil {
		t.Fatal(err)
	}
	keys := trust.TrustedKeys{Version: trust.TrustedKeysVersion}
	keysJSON, err := trust.MarshalTrustedKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".scafld", "trusted-keys.json"), keysJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Run(context.Background(), Options{Root: root})
	if err == nil || !strings.Contains(err.Error(), "env-receipt.json") {
		t.Fatalf("verify must resolve SCAFLD_RECEIPT_PATH before config default, got %v", err)
	}
}

func TestSignatureVerifierRejectsRevokedAtAndExpiredKeys(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("z", 64)))
	if err != nil {
		t.Fatal(err)
	}
	baseKey := verifyTrustedKey(t, pub)
	for _, tt := range []struct {
		name string
		key  func(trust.TrustedKey) trust.TrustedKey
		want string
	}{
		{name: "revoked_at", want: "revoked", key: func(key trust.TrustedKey) trust.TrustedKey {
			key.RevokedAt = "2026-06-03T00:00:00Z"
			return key
		}},
		{name: "expires_at", want: "expired", key: func(key trust.TrustedKey) trust.TrustedKey {
			key.ExpiresAt = "2026-06-03T00:00:00Z"
			return key
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := minimalReceiptBody()
			body.MintedAt = "2026-06-03T00:00:00Z"
			envelope := signVerifyReceipt(t, body, baseKey.KeyID, priv)
			keys := trust.TrustedKeys{Version: trust.TrustedKeysVersion, Keys: []trust.TrustedKey{tt.key(baseKey)}}
			if err := (signatureVerifier{}).Verify(envelope, keys); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Verify error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestTamperedTreeVerifyExitsNonzero(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	gitCmd(t, root, "init")
	gitCmd(t, root, "config", "user.name", "scafld")
	gitCmd(t, root, "config", "user.email", "scafld@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", "a.go")
	gitCmd(t, root, "commit", "-m", "base")
	head := gitCmd(t, root, "rev-parse", "HEAD")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyIDFromRawEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keys := trust.TrustedKeys{Version: trust.TrustedKeysVersion, Keys: []trust.TrustedKey{{
		KeyID:     keyID,
		Alg:       trust.AlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}}}
	keysJSON, err := trust.MarshalTrustedKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".scafld"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".scafld", "trusted-keys.json"), keysJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	body := receipt.Body{
		SchemaVersion:             receipt.SchemaVersion,
		TaskID:                    "task",
		SessionID:                 "session",
		Verdict:                   "pass",
		SnapshotMode:              receipt.SnapshotModeWorkingTree,
		BaseCommit:                head,
		HeadCommit:                head,
		Scope:                     []string{"a.go"},
		TreeSHA:                   "tampered-tree-sha",
		FileDigests:               map[string]string{"a.go": "sha"},
		IgnoredUnreviewed:         []string{},
		ReviewedContextProvenance: []receipt.Provenance{{Kind: "evidence_file", Path: "a.go", SHA256: "sha"}},
		Reviewer:                  receipt.Reviewer{Provider: "codex"},
		HostUnderReview:           receipt.HostUnderReview{Agent: "codex"},
		Independence:              receipt.Independence{Level: receipt.IndependenceLevelIsolationOnly, Downgraded: receipt.IndependenceDowngradeSameVendor},
		SpecFingerprint:           "spec",
		AcceptanceDeclared:        false,
		Acceptance:                []receipt.Acceptance{},
		OpenBlockers:              []receipt.Blocker{},
		MutationGuard:             receipt.MutationGuard{Status: "clean"},
		LedgerHead:                "ledger",
		MintedAt:                  "2026-06-03T00:00:00Z",
	}
	canonical, err := receipt.CanonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope := receipt.Envelope{Body: body, Signature: receipt.DetachedSignature{
		Alg:   receipt.SignatureAlgorithm,
		KeyID: keyID,
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
	}}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(receiptPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	exit := Handler()(context.Background(), []string{"--root", root, receiptPath, "--target", head, "--trusted-keys", filepath.Join(root, ".scafld", "trusted-keys.json")}, &stdout, &stderr)
	if exit == 0 || !strings.Contains(stderr.String(), "file digest mismatch") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestMaterialRefVerifyRunsAcceptanceInSeparateCleanSanitizedRoot(t *testing.T) {
	fixture := newMaterialRefVerifyFixture(t)
	var stdout, stderr bytes.Buffer
	exit := Handler()(context.Background(), []string{
		"--root", fixture.root,
		fixture.receiptPath,
		"--target", fixture.base,
		"--material-ref", fixture.head,
		"--acceptance-root", fixture.acceptanceRoot,
		"--trusted-keys", fixture.trustedKeysPath,
	}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "verify passed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestMaterialRefVerifyRequiresAcceptanceRootForFullVerify(t *testing.T) {
	fixture := newMaterialRefVerifyFixture(t)
	var stdout, stderr bytes.Buffer
	exit := Handler()(context.Background(), []string{
		"--root", fixture.root,
		fixture.receiptPath,
		"--target", fixture.base,
		"--material-ref", fixture.head,
		"--trusted-keys", fixture.trustedKeysPath,
	}, &stdout, &stderr)
	if exit != 3 || !strings.Contains(stderr.String(), "material-ref requires acceptance-root") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestMaterialRefVerifyRejectsNonExactAcceptanceRoot(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   string
	}{
		{name: "dirty tracked file", want: "app.txt", mutate: func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "app.txt"), []byte("dirty\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "ignored file", want: "ignored.txt", mutate: func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "ignored.txt"), []byte("ignored\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "scafld runtime path", want: ".scafld/specs/active/runtime.md", mutate: func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, ".scafld", "specs", "active", "runtime.md")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("runtime\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "skip worktree", want: "evidence_integrity", mutate: func(t *testing.T, root string) {
			t.Helper()
			gitCmd(t, root, "update-index", "--skip-worktree", "app.txt")
			if err := os.WriteFile(filepath.Join(root, "app.txt"), []byte("hidden\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "assume unchanged", want: "evidence_integrity", mutate: func(t *testing.T, root string) {
			t.Helper()
			gitCmd(t, root, "update-index", "--assume-unchanged", "app.txt")
			if err := os.WriteFile(filepath.Join(root, "app.txt"), []byte("hidden\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newMaterialRefVerifyFixture(t)
			tt.mutate(t, fixture.acceptanceRoot)
			var stdout, stderr bytes.Buffer
			exit := Handler()(context.Background(), []string{
				"--root", fixture.root,
				fixture.receiptPath,
				"--target", fixture.base,
				"--material-ref", fixture.head,
				"--acceptance-root", fixture.acceptanceRoot,
				"--trusted-keys", fixture.trustedKeysPath,
			}, &stdout, &stderr)
			if exit != 3 || !strings.Contains(stderr.String(), "acceptance-root is not exact material") || !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
			}
		})
	}
}

func TestMaterialOnlyVerifyDoesNotRequireAcceptanceRoot(t *testing.T) {
	fixture := newMaterialRefVerifyFixture(t)
	var stdout, stderr bytes.Buffer
	exit := Handler()(context.Background(), []string{
		"--root", fixture.root,
		fixture.receiptPath,
		"--target", fixture.base,
		"--material-ref", fixture.head,
		"--material-only",
		"--trusted-keys", fixture.trustedKeysPath,
	}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "verify material passed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

type materialRefVerifyFixture struct {
	root            string
	base            string
	head            string
	acceptanceRoot  string
	receiptPath     string
	trustedKeysPath string
}

func newMaterialRefVerifyFixture(t *testing.T) materialRefVerifyFixture {
	t.Helper()
	root := t.TempDir()
	gitCmd(t, root, "init")
	gitCmd(t, root, "config", "user.name", "scafld")
	gitCmd(t, root, "config", "user.email", "scafld@example.invalid")
	if err := os.MkdirAll(filepath.Join(root, ".scafld"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := "version: \"1\"\nexecution:\n  env:\n    GITHUB_TOKEN: config-leak\n    ACTIONS_RUNTIME_TOKEN: config-leak\n"
	if err := os.WriteFile(filepath.Join(root, ".scafld", "config.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-m", "base")
	base := gitCmd(t, root, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(root, "app.txt"), []byte("head\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-m", "head")
	head := gitCmd(t, root, "rev-parse", "HEAD")
	acceptanceRoot := filepath.Join(t.TempDir(), "head-worktree")
	gitCmd(t, root, "worktree", "add", "--detach", acceptanceRoot, head)
	gitCmd(t, root, "checkout", base)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := verifyTrustedKey(t, pub)
	writeTrustedKeys(t, root, trust.TrustedKeys{Version: trust.TrustedKeysVersion, Keys: []trust.TrustedKey{key}})

	headSum := sha256.Sum256([]byte("head\n"))
	body := minimalReceiptBody()
	body.SnapshotMode = receipt.SnapshotModeBaseDelta
	body.BaseRef = base
	body.BaseCommit = base
	body.HeadCommit = head
	body.Scope = []string{"app.txt"}
	body.FileDigests = map[string]string{"app.txt": fmt.Sprintf("%x", headSum)}
	body.ReviewedContextProvenance = []receipt.Provenance{{Kind: "evidence_file", Path: "app.txt", SHA256: fmt.Sprintf("%x", headSum)}}
	body.Acceptance = []receipt.Acceptance{{
		ID:           "ac1",
		Command:      `test "$(cat app.txt)" = "head" && test -z "${SECRET_TOKEN:-}" && test -z "${GITHUB_TOKEN:-}" && test -z "${ACTIONS_RUNTIME_TOKEN:-}" && if [ -e /proc/$PPID/environ ]; then ! cat /proc/$PPID/environ >/dev/null 2>&1; fi`,
		ExpectedKind: "exit_code_zero",
		Status:       "pass",
		ExitCode:     0,
	}}
	envelope := signVerifyReceipt(t, body, key.KeyID, priv)
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(receiptPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_TOKEN", "leak")
	t.Setenv("GITHUB_TOKEN", "leak")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "leak")
	return materialRefVerifyFixture{
		root:            root,
		base:            base,
		head:            head,
		acceptanceRoot:  acceptanceRoot,
		receiptPath:     receiptPath,
		trustedKeysPath: filepath.Join(root, ".scafld", "trusted-keys.json"),
	}
}

func gitCmd(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeTrustedKeys(t *testing.T, root string, keys trust.TrustedKeys) {
	t.Helper()
	data, err := trust.MarshalTrustedKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".scafld"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".scafld", "trusted-keys.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func verifyTrustedKey(t *testing.T, pub ed25519.PublicKey) trust.TrustedKey {
	t.Helper()
	keyID, err := trust.KeyIDFromRawEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return trust.TrustedKey{
		KeyID:     keyID,
		Alg:       trust.AlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}

func signVerifyReceipt(t *testing.T, body receipt.Body, keyID string, privateKey ed25519.PrivateKey) receipt.Envelope {
	t.Helper()
	canonical, err := receipt.CanonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	return receipt.Envelope{Body: body, Signature: receipt.DetachedSignature{
		Alg:   receipt.SignatureAlgorithm,
		KeyID: keyID,
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}}
}

func minimalReceiptBody() receipt.Body {
	return receipt.Body{
		SchemaVersion:             receipt.SchemaVersion,
		TaskID:                    "task",
		SessionID:                 "session",
		Verdict:                   "pass",
		SnapshotMode:              receipt.SnapshotModeWorkingTree,
		BaseCommit:                "base",
		HeadCommit:                "head",
		Scope:                     []string{"."},
		TreeSHA:                   "tree",
		FileDigests:               map[string]string{"a.go": "sha"},
		IgnoredUnreviewed:         []string{},
		ReviewedContextProvenance: []receipt.Provenance{{Kind: "evidence_file", Path: "a.go", SHA256: "sha"}},
		Reviewer:                  receipt.Reviewer{Provider: "codex"},
		HostUnderReview:           receipt.HostUnderReview{Agent: "codex"},
		Independence:              receipt.Independence{Level: receipt.IndependenceLevelIsolationOnly, Downgraded: receipt.IndependenceDowngradeSameVendor},
		SpecFingerprint:           "spec",
		AcceptanceDeclared:        false,
		Acceptance:                []receipt.Acceptance{},
		OpenBlockers:              []receipt.Blocker{},
		MutationGuard:             receipt.MutationGuard{Status: "clean"},
		LedgerHead:                "ledger",
		MintedAt:                  "2026-06-03T00:00:00Z",
	}
}
