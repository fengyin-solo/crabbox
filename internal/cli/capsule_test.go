package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseActionsRunRefFromURL(t *testing.T) {
	ref, err := parseActionsRunRef("https://github.com/example-org/my-app/actions/runs/123456/attempts/2", "")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Repo.Slug() != "example-org/my-app" || ref.RunID != "123456" || ref.Attempt != 2 {
		t.Fatalf("unexpected ref: %#v", ref)
	}
}

func TestCapsuleFromActionsStripsConfiguredExternalDesktopSecretFromGitHubCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell gh fixture")
	}
	for _, name := range []string{
		"CRABBOX_PROVIDER",
		"CRABBOX_TARGET",
		"CRABBOX_TARGET_OS",
		"CRABBOX_EXTERNAL_COMMAND",
		"CRABBOX_EXTERNAL_ROUTING_FILE",
		"CRABBOX_EXTERNAL_DESKTOP_USERNAME",
		"CRABBOX_EXTERNAL_DESKTOP_PASSWORD_ENV",
	} {
		t.Setenv(name, "")
	}

	dir := t.TempDir()
	gh := filepath.Join(dir, "gh")
	script := `#!/bin/sh
set -eu
if [ "${TEST_CAPSULE_DESKTOP_SECRET+x}" = x ]; then echo leaked-desktop-secret >&2; exit 89; fi
if [ "${GH_TOKEN:-}" != capsule-token ]; then echo missing-gh-token >&2; exit 90; fi
if [ "${GH_CONFIG_DIR:-}" != capsule-gh-config ]; then echo missing-gh-config >&2; exit 91; fi
if [ "${GH_HOST:-}" != github.example.test ]; then echo missing-gh-host >&2; exit 92; fi
if [ "${TEST_CAPSULE_KEEP:-}" != preserved ]; then echo missing-unrelated-env >&2; exit 93; fi
printf '%s\n' "$*" >> "$TEST_CAPSULE_GH_LOG"
if [ "$1" = run ] && [ "$2" = view ]; then
  case " $* " in
    *" --log-failed "*) printf 'Go\tTest\tpanic: capsule fixture\n' ;;
    *) printf '%s\n' '{"attempt":1,"conclusion":"failure","headBranch":"main","headSha":"abc123","jobs":[{"conclusion":"failure","name":"Go","status":"completed","steps":[{"conclusion":"failure","name":"Test","number":1,"status":"completed"}]}],"name":"CI","status":"completed","url":"https://github.com/example-org/my-app/actions/runs/123","workflowName":"CI"}' ;;
  esac
elif [ "$1" = api ]; then
  case "$2" in
    *'/artifacts?'*) printf '%s\n' '{"total_count":0,"artifacts":[]}' ;;
    *) printf '%s\n' '{"path":".github/workflows/ci.yml"}' ;;
  esac
else
  echo "unexpected gh args: $*" >&2
  exit 94
fi
`
	if err := os.WriteFile(gh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := `provider: external
target: macos
external:
  connection:
    desktop:
      username: screen-user
      passwordEnv: TEST_CAPSULE_DESKTOP_SECRET
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "gh.log")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CRABBOX_CONFIG", configPath)
	t.Setenv("TEST_CAPSULE_DESKTOP_SECRET", "must-not-reach-gh")
	t.Setenv("GH_TOKEN", "capsule-token")
	t.Setenv("GH_CONFIG_DIR", "capsule-gh-config")
	t.Setenv("GH_HOST", "github.example.test")
	t.Setenv("TEST_CAPSULE_KEEP", "preserved")
	t.Setenv("TEST_CAPSULE_GH_LOG", logPath)

	outputDir := filepath.Join(t.TempDir(), "capsule")
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err := app.Run(context.Background(), []string{
		"capsule", "from-actions",
		"https://github.com/example-org/my-app/actions/runs/123",
		"--replay", "go test ./...",
		"--output", outputDir,
	})
	if err != nil {
		t.Fatalf("capsule from-actions failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outputDir, capsuleManifestFileName)); err != nil {
		t.Fatalf("capsule manifest: %v", err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	for _, want := range []string{"--json", "api repos/example-org/my-app/actions/runs/123\n", "/artifacts?", "--log-failed"} {
		if !strings.Contains(log, want) {
			t.Fatalf("gh log missing %q:\n%s", want, log)
		}
	}
}

func TestParseActionsRunRefRequiresRepoForNumericID(t *testing.T) {
	if _, err := parseActionsRunRef("123456", ""); err == nil {
		t.Fatal("expected numeric run id without --repo to fail")
	}
	ref, err := parseActionsRunRef("123456", "example-org/my-app")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Repo.Slug() != "example-org/my-app" || ref.RunID != "123456" {
		t.Fatalf("unexpected ref: %#v", ref)
	}
}

func TestParseActionsRunRefRejectsInvalidIDsAndAttempts(t *testing.T) {
	for _, value := range []string{
		"0",
		"-1",
		"https://github.com/example-org/my-app/actions/runs/not-a-number",
		"https://github.com/example-org/my-app/actions/runs/123/attempts/0",
		"https://github.com/example-org/my-app/actions/runs/123/attempts/nope",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseActionsRunRef(value, "example-org/my-app"); err == nil {
				t.Fatal("expected invalid run ref to fail")
			}
		})
	}
}

func TestSelectCapsuleFailurePrefersFailedJobAndStep(t *testing.T) {
	job, step, matched := selectCapsuleFailure([]capsuleJobView{
		{Name: "Docs", Conclusion: "success"},
		{Name: "Go", Conclusion: "failure", Steps: []capsuleStepView{
			{Name: "Set up", Conclusion: "success"},
			{Name: "Test", Conclusion: "failure"},
		}},
	}, "")
	if !matched || job.Name != "Go" || step.Name != "Test" {
		t.Fatalf("matched=%t job=%#v step=%#v", matched, job, step)
	}
}

func TestSelectCapsuleFailureReportsMissingPreferredJob(t *testing.T) {
	job, step, matched := selectCapsuleFailure([]capsuleJobView{
		{Name: "Docs", Conclusion: "success"},
		{Name: "Go", Conclusion: "failure", Steps: []capsuleStepView{{Name: "Test", Conclusion: "failure"}}},
	}, "Windows")
	if matched {
		t.Fatalf("matched missing job with job=%#v step=%#v", job, step)
	}
}

func TestBuildActionsCapsuleManifestKeepsSmallContract(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123"}
	view := capsuleRunView{
		URL:          "https://github.com/example-org/my-app/actions/runs/123",
		Attempt:      2,
		WorkflowName: "CI",
		HeadSHA:      "abc123",
		Conclusion:   "failure",
	}
	job := capsuleJobView{Name: "Go", Conclusion: "failure"}
	step := capsuleStepView{Name: "Test", Conclusion: "failure"}
	manifest := buildActionsCapsuleManifest(ref, view, ".github/workflows/ci.yml", job, step, "Replay CI Go Test", "go test ./...", "semantically_identical", "FAIL", capsuleArtifactRef{}, nil)
	if manifest.Class != repoBuildReplayClass || manifest.Source.Kind != "github_actions" {
		t.Fatalf("unexpected class/source: %#v", manifest)
	}
	if manifest.Replay.Command != "go test ./..." || manifest.Replay.CommandMode != "shell" {
		t.Fatalf("unexpected replay: %#v", manifest.Replay)
	}
	if manifest.Oracle.FailureSignature != "FAIL" || !strings.Contains(manifest.Oracle.SuccessCondition, "same failure signature") {
		t.Fatalf("unexpected oracle: %#v", manifest.Oracle)
	}
	if manifest.Safety.ActionProfile != "build_debug_v1" || manifest.Extensions[repoBuildReplayClass] == nil {
		t.Fatalf("foundation fields missing: %#v", manifest)
	}
	if manifest.Source.Attempt != 2 || !strings.Contains(manifest.Inputs.ActionsRunDigest, "attempt-2") {
		t.Fatalf("attempt was not resolved into manifest identity: source=%#v inputs=%#v", manifest.Source, manifest.Inputs)
	}
}

func TestBuildActionsCapsuleManifestAllowsExitOnlyOracle(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123"}
	manifest := buildActionsCapsuleManifest(ref, capsuleRunView{}, "", capsuleJobView{Name: "Go"}, capsuleStepView{Name: "Test"}, "Replay", "go test ./...", "", "", capsuleArtifactRef{}, nil)
	if manifest.Oracle.FailureSignature != "" {
		t.Fatalf("unexpected fallback failure signature: %#v", manifest.Oracle)
	}
	if manifest.Oracle.SuccessCondition != "The replay command exits non-zero." {
		t.Fatalf("unexpected success condition: %q", manifest.Oracle.SuccessCondition)
	}
	if manifest.Replay.NondeterminismBudget != "exit code must remain non-zero" {
		t.Fatalf("unexpected nondeterminism budget: %q", manifest.Replay.NondeterminismBudget)
	}
}

func TestCapsuleManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, capsuleManifestFileName)
	manifest := capsuleManifest{
		CapsuleVersion: capsuleVersion,
		CapsuleID:      "sha256:test",
		Class:          repoBuildReplayClass,
		ClassVersion:   repoBuildReplayVersion,
		Scenario:       "test",
		Replay:         capsuleReplayContract{Command: "go test ./...", CommandMode: "shell", RequiredQuality: "semantically_identical"},
	}
	if err := writeCapsuleManifest(path, manifest); err != nil {
		t.Fatal(err)
	}
	got, err := readCapsuleManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.CapsuleID != manifest.CapsuleID || got.Replay.Command != manifest.Replay.Command {
		t.Fatalf("got=%#v want=%#v", got, manifest)
	}
}

func TestCapsuleFilesRepairPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	dir := filepath.Join(t.TempDir(), "capsule")
	logsDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, logsDir} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(logsDir, "failed.log")
	manifestPath := filepath.Join(dir, capsuleManifestFileName)
	for _, path := range []string{logPath, manifestPath} {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ensurePrivateCapsuleDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateCapsuleDir(logsDir); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateCapsuleFile(logPath, []byte("secret log")); err != nil {
		t.Fatal(err)
	}
	if err := writeCapsuleManifest(manifestPath, capsuleManifest{CapsuleVersion: capsuleVersion}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, logsDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != privateCapsuleDirMode {
			t.Fatalf("directory %s mode=%#o, want %#o", path, got, privateCapsuleDirMode)
		}
	}
	for _, path := range []string{logPath, manifestPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != privateCapsuleFileMode {
			t.Fatalf("file %s mode=%#o, want %#o", path, got, privateCapsuleFileMode)
		}
	}
}

func TestWriteCapsuleManifestDoesNotChangeExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, capsuleManifestFileName)
	if err := writeCapsuleManifest(path, capsuleManifest{CapsuleVersion: capsuleVersion}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing parent mode=%#o, want unchanged 0755", got)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != privateCapsuleFileMode {
		t.Fatalf("manifest mode=%#o, want %#o", got, privateCapsuleFileMode)
	}
}

func TestCapsuleFailureSignatureUsesLastLogLine(t *testing.T) {
	got := capsuleFailureSignature("Go\tTest\tfirst\nGo\tTest\tpanic: broken\nGo\tTest\tCleaning up orphan processes\n")
	if got != "panic: broken" {
		t.Fatalf("signature=%q", got)
	}
}

func TestCapsuleFailureSignatureStripsGitHubPrefixes(t *testing.T) {
	got := capsuleFailureSignature("Plugin\tCheck\t2026-05-16T05:20:06.2281757Z Error: missing plugin\nPlugin\tCheck\t2026-05-16T05:20:07.0000000Z ##[error]Process completed with exit code 1.\n")
	if got != "Error: missing plugin" {
		t.Fatalf("signature=%q", got)
	}
}

func TestCapsuleFailureSignatureStripsShortGitHubTimestamp(t *testing.T) {
	got := capsuleFailureSignature("Plugin\tCheck\t2026-01-01T00:00:00Z Error\n")
	if got != "Error" {
		t.Fatalf("signature=%q", got)
	}
}

func TestCapsuleFailureSignatureForSelectionFiltersJobAndStep(t *testing.T) {
	log := strings.Join([]string{
		"Go\tTest\tpanic: selected",
		"Worker\tCheck\tpanic: other",
	}, "\n")
	got := capsuleFailureSignatureForSelection(log, "Go", "Test")
	if got != "panic: selected" {
		t.Fatalf("signature=%q", got)
	}
	if got := capsuleFailureSignatureForSelection(log, "Docs", "Test"); got != "" {
		t.Fatalf("unexpected unmatched signature=%q", got)
	}
}

func TestCapsuleFailureSignatureForSelectionFallsBackToJob(t *testing.T) {
	log := strings.Join([]string{
		"Go\tUNKNOWN STEP\t\ufeff2026-05-16T05:20:06.2281757Z Error: selected",
		"Worker\tUNKNOWN STEP\t2026-05-16T05:20:07.0000000Z Error: other",
	}, "\n")
	got := capsuleFailureSignatureForSelection(log, "Go", "Test")
	if got != "Error: selected" {
		t.Fatalf("signature=%q", got)
	}
}

func TestCapsuleFailureSignatureSkipsGenericFailSummaries(t *testing.T) {
	got := capsuleFailureSignature("Go\tTest\tassertion failed: wanted true\nGo\tTest\tFAIL\tgithub.com/example-org/my-app\t0.1s\n")
	if got != "assertion failed: wanted true" {
		t.Fatalf("signature=%q", got)
	}
}

func TestCapsuleFailureSignaturePreservesTabbedMessages(t *testing.T) {
	got := capsuleFailureSignature("Go\tTest\tError:\twant\tgot\n")
	if got != "Error:\twant\tgot" {
		t.Fatalf("signature=%q", got)
	}
}

func TestSafePathComponent(t *testing.T) {
	got := safePathComponent("Example Org/My App Actions 123")
	if strings.ContainsAny(got, "/ ") || got != "example-org-my-app-actions-123" {
		t.Fatalf("safe component=%q", got)
	}
}

func TestDefaultCapsuleOutputNameIncludesAttempt(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123", Attempt: 2}
	if got := defaultCapsuleOutputName(ref, capsuleJobView{}, capsuleStepView{}, false); got != "example-org-my-app-actions-123-attempt-2" {
		t.Fatalf("output name=%q", got)
	}
}

func TestDefaultCapsuleOutputNameOmitsFirstAttempt(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123", Attempt: 1}
	if got := defaultCapsuleOutputName(ref, capsuleJobView{}, capsuleStepView{}, false); got != "example-org-my-app-actions-123" {
		t.Fatalf("output name=%q", got)
	}
}

func TestDefaultCapsuleOutputNameDisambiguatesSelectedFailure(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123", Attempt: 1}
	got := defaultCapsuleOutputName(ref, capsuleJobView{Name: "Windows"}, capsuleStepView{Name: "Test"}, true)
	if got != "example-org-my-app-actions-123-windows-test" {
		t.Fatalf("output name=%q", got)
	}
}

func TestCapsuleIDDigestIncludesAttempt(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123", Attempt: 1}
	one := capsuleIDDigest(ref, "abc", "go test ./...", "Go\nTest\nFAIL")
	ref.Attempt = 2
	two := capsuleIDDigest(ref, "abc", "go test ./...", "Go\nTest\nFAIL")
	if one == two {
		t.Fatal("attempt-specific captures should not share capsule ids")
	}
}

func TestCapsuleIDDigestIncludesSelectedFailure(t *testing.T) {
	ref := actionsRunRef{Repo: GitHubRepo{Owner: "example-org", Name: "my-app"}, RunID: "123", Attempt: 1}
	one := capsuleIDDigest(ref, "abc", "go test ./...", "Go\nTest\nFAIL")
	two := capsuleIDDigest(ref, "abc", "go test ./...", "Windows\nTest\nFAIL")
	if one == two {
		t.Fatal("different selected failures should not share capsule ids")
	}
}

func TestAppendActionsArtifactRefsSkipsExpiredAndPreservesPages(t *testing.T) {
	got := appendActionsArtifactRefs(nil, []actionsArtifact{
		{Name: "page-1", SizeInBytes: 10, ArchiveDownloadURL: "https://example.com/1"},
		{Name: "expired", Expired: true, SizeInBytes: 20, ArchiveDownloadURL: "https://example.com/expired"},
	})
	got = appendActionsArtifactRefs(got, []actionsArtifact{
		{Name: "page-2", SizeInBytes: 30, ArchiveDownloadURL: "https://example.com/2"},
	})
	if len(got) != 2 || got[0].Name != "page-1" || got[1].Name != "page-2" {
		t.Fatalf("artifacts=%#v", got)
	}
}

func TestRemoteReplayExitCodeClassifiesExpectedFailure(t *testing.T) {
	tests := []struct {
		message string
		want    int
	}{
		{message: "remote command exited 17", want: 17},
		{message: "blacksmith testbox run exited 23", want: 23},
		{message: "islo run exited 4", want: 4},
		{message: "delegated provider command exited 5", want: 5},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			code, ok := remoteReplayExitCode(ExitError{Code: tt.want, Message: tt.message})
			if !ok || code != tt.want {
				t.Fatalf("code=%d ok=%t want=%d", code, ok, tt.want)
			}
		})
	}
}

func TestRemoteReplayExitCodeRejectsConfigAndProviderErrors(t *testing.T) {
	for _, message := range []string{
		"missing config",
		"blacksmith failed: exit status 1",
		"e2b run failed: process failed before command",
		"e2b run failed: setup command exited 1",
	} {
		t.Run(message, func(t *testing.T) {
			if _, ok := remoteReplayExitCode(ExitError{Code: 2, Message: message}); ok {
				t.Fatalf("configuration/provider error %q should not be treated as reproduced failure", message)
			}
		})
	}
}

func TestCapsuleReplayFailureOutcomeChecksSignature(t *testing.T) {
	outcome, note, reproduced := capsuleReplayFailureOutcome("panic: broken", "setup\npanic: broken\n", 2)
	if !reproduced || outcome != capsuleOutcomeFailReproduced || !strings.Contains(note, "matched failure_signature") {
		t.Fatalf("outcome=%s reproduced=%t note=%q", outcome, reproduced, note)
	}

	outcome, note, reproduced = capsuleReplayFailureOutcome("panic: broken", "different failure\n", 2)
	if reproduced || outcome != capsuleOutcomeFailNew || !strings.Contains(note, "failure_signature was not present") {
		t.Fatalf("outcome=%s reproduced=%t note=%q", outcome, reproduced, note)
	}

	outcome, _, reproduced = capsuleReplayFailureOutcome("", "", 2)
	if !reproduced || outcome != capsuleOutcomeFailReproduced {
		t.Fatalf("blank signature outcome=%s reproduced=%t", outcome, reproduced)
	}
}

func evidenceTestCapsule(dir string, refs []capsuleArtifactRef, replayCommand, failureSignature string) capsuleManifest {
	return capsuleManifest{
		CapsuleVersion: capsuleVersion,
		CapsuleID:      "sha256:evidence-test",
		Class:          repoBuildReplayClass,
		ClassVersion:   repoBuildReplayVersion,
		Scenario:       "evidence verification test",
		Oracle:         capsuleOracle{Type: "deterministic_rerun", FailureSignature: failureSignature},
		Replay: capsuleReplayContract{
			Command:         replayCommand,
			CommandMode:     "shell",
			RequiredQuality: "semantically_identical",
		},
		Artifacts: capsuleArtifacts{Logs: refs},
	}
}

func writeEvidenceTestCapsule(t *testing.T, dir string, manifest capsuleManifest) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, capsuleManifestFileName)
	if err := writeCapsuleManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}

func writeCapsuleEvidenceFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func capsuleEvidenceRefFor(name, relPath, content string) capsuleArtifactRef {
	return capsuleArtifactRef{
		Name:   name,
		Path:   relPath,
		Size:   int64(len(content)),
		Digest: "sha256:" + sha256String(content),
	}
}

func TestVerifyCapsuleEvidenceVerifiesIntactEvidence(t *testing.T) {
	dir := t.TempDir()
	content := "Go\tTest\tpanic: fixture\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

	results := verifyCapsuleEvidence(manifest, dir)
	if len(results) != 1 {
		t.Fatalf("results=%#v", results)
	}
	result := results[0]
	if result.Status != capsuleEvidenceVerified || result.Reason != "" {
		t.Fatalf("expected verified result, got %#v", result)
	}
	if got := capsuleEvidenceByStatus(results, capsuleEvidenceInvalid); len(got) != 0 {
		t.Fatalf("unexpected invalid evidence: %#v", got)
	}
}

func TestVerifyCapsuleEvidenceAcceptsSymlinkInsideCapsule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symbolic link fixture")
	}
	dir := t.TempDir()
	content := "panic: linked inside\n"
	writeCapsuleEvidenceFile(t, dir, "logs/actual.log", content)
	link := filepath.Join(dir, "logs", "failed.log")
	if err := os.Symlink("actual.log", link); err != nil {
		t.Fatal(err)
	}
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

	results := verifyCapsuleEvidence(manifest, dir)
	if len(results) != 1 || results[0].Status != capsuleEvidenceVerified {
		t.Fatalf("results=%#v", results)
	}
}

func TestVerifyCapsuleEvidenceRejectsTamperedContent(t *testing.T) {
	dir := t.TempDir()
	original := "original-log!"
	tampered := "tampered-log!"
	if len(original) != len(tampered) {
		t.Fatal("fixture must keep size constant to isolate digest mismatch")
	}
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", tampered)
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", original)
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

	results := verifyCapsuleEvidence(manifest, dir)
	if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid {
		t.Fatalf("results=%#v", results)
	}
	if !strings.Contains(results[0].Reason, "sha256 digest mismatch") {
		t.Fatalf("reason=%q", results[0].Reason)
	}
	formatted := formatCapsuleEvidenceFailures(results)
	for _, want := range []string{"failed-actions-log", "logs/failed.log", "digest mismatch"} {
		if !strings.Contains(formatted, want) {
			t.Fatalf("failure output %q missing %q", formatted, want)
		}
	}
}

func TestVerifyCapsuleEvidenceRejectsTruncatedFile(t *testing.T) {
	dir := t.TempDir()
	original := "panic: full original failure line\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", original[:8])
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", original)
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

	results := verifyCapsuleEvidence(manifest, dir)
	if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid {
		t.Fatalf("results=%#v", results)
	}
	if !strings.Contains(results[0].Reason, "size mismatch") {
		t.Fatalf("truncation should report size mismatch, reason=%q", results[0].Reason)
	}
}

func TestVerifyCapsuleEvidenceRejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	content := "panic: missing\n"
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

	results := verifyCapsuleEvidence(manifest, dir)
	if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid {
		t.Fatalf("results=%#v", results)
	}
	if !strings.Contains(results[0].Reason, "does not exist") {
		t.Fatalf("reason=%q", results[0].Reason)
	}
}

func TestVerifyCapsuleEvidenceRejectsUnsafePaths(t *testing.T) {
	for _, tc := range []struct {
		path        string
		fragment    string
		pathVisible string
	}{
		{"../outside.log", "escape", "../outside.log"},
		{"logs/../../outside.log", "escape", "logs/../../outside.log"},
		{"/tmp/capsule-evidence.log", "absolute", "/tmp/capsule-evidence.log"},
		{`logs\failed.log`, "backslash", `failed.log`},
		{`C:\logs\failed.log`, "backslash", `failed.log`},
		{"C:/logs/failed.log", "drive", "C:/logs/failed.log"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			dir := t.TempDir()
			content := "x"
			ref := capsuleEvidenceRefFor("failed-actions-log", tc.path, content)
			manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

			results := verifyCapsuleEvidence(manifest, dir)
			if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid {
				t.Fatalf("results=%#v", results)
			}
			if !strings.Contains(results[0].Reason, tc.fragment) {
				t.Fatalf("path=%q reason=%q want fragment %q", tc.path, results[0].Reason, tc.fragment)
			}
			if !strings.Contains(results[0].Reason, tc.pathVisible) {
				t.Fatalf("reason must name the offending path: %q", results[0].Reason)
			}
		})
	}
}

func TestVerifyCapsuleEvidenceRejectsUnsafeSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symbolic link fixture")
	}
	content := "external secret evidence\n"

	t.Run("link to outside file", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		outsideFile := filepath.Join(outside, "secret.log")
		if err := os.WriteFile(outsideFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideFile, filepath.Join(dir, "logs", "failed.log")); err != nil {
			t.Fatal(err)
		}
		ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
		results := verifyCapsuleEvidence(evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""), dir)
		if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid || !strings.Contains(results[0].Reason, "outside the capsule directory") {
			t.Fatalf("results=%#v", results)
		}
	})

	t.Run("parent directory link to outside", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "failed.log"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
			t.Fatal(err)
		}
		ref := capsuleEvidenceRefFor("failed-actions-log", "linked/failed.log", content)
		results := verifyCapsuleEvidence(evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""), dir)
		if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid || !strings.Contains(results[0].Reason, "outside the capsule directory") {
			t.Fatalf("results=%#v", results)
		}
	})

	t.Run("link to directory", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "logs-link")); err != nil {
			t.Fatal(err)
		}
		ref := capsuleEvidenceRefFor("failed-actions-log", "logs-link", content)
		results := verifyCapsuleEvidence(evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""), dir)
		if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid || !strings.Contains(results[0].Reason, "directory") {
			t.Fatalf("results=%#v", results)
		}
	})

	t.Run("plain directory path", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		ref := capsuleEvidenceRefFor("logs-dir", "logs", content)
		results := verifyCapsuleEvidence(evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""), dir)
		if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid || !strings.Contains(results[0].Reason, "directory") {
			t.Fatalf("results=%#v", results)
		}
	})
}

func TestVerifyCapsuleEvidenceRejectsInvalidDigestFormat(t *testing.T) {
	dir := t.TempDir()
	content := "panic: fixture\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	good := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
	for _, digest := range []string{
		"sha256:zz",
		"sha256:abc",
		"sha256:" + strings.Repeat("g", 64),
		"md5:" + strings.Repeat("a", 32),
		"not-a-digest",
	} {
		t.Run(digest, func(t *testing.T) {
			ref := good
			ref.Digest = digest
			results := verifyCapsuleEvidence(evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""), dir)
			if len(results) != 1 || results[0].Status != capsuleEvidenceInvalid {
				t.Fatalf("results=%#v", results)
			}
			if !strings.Contains(results[0].Reason, "invalid digest") {
				t.Fatalf("digest=%q reason=%q", digest, results[0].Reason)
			}
		})
	}
}

func TestVerifyCapsuleEvidenceMarksLegacyCapsuleUnverified(t *testing.T) {
	dir := t.TempDir()
	content := "legacy captured log\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	ref := capsuleArtifactRef{Name: "failed-actions-log", Path: "logs/failed.log", Size: int64(len(content))}
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")

	results := verifyCapsuleEvidence(manifest, dir)
	if len(results) != 1 || results[0].Status != capsuleEvidenceUnverified {
		t.Fatalf("results=%#v", results)
	}
	if !strings.Contains(results[0].Reason, "no digest declared") {
		t.Fatalf("reason=%q", results[0].Reason)
	}
	if got := capsuleEvidenceByStatus(results, capsuleEvidenceInvalid); len(got) != 0 {
		t.Fatalf("legacy capsule must stay readable, invalid=%#v", got)
	}
}

func TestVerifyCapsuleEvidenceSkipsURLOnlyReferences(t *testing.T) {
	dir := t.TempDir()
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{{
		Name: "github-artifact",
		URL:  "https://github.example/artifacts/1.zip",
		Size: 42,
	}}, "true", "")
	if results := verifyCapsuleEvidence(manifest, dir); len(results) != 0 {
		t.Fatalf("url-only references must be skipped, got %#v", results)
	}
}

func TestVerifyCapsuleEvidenceIsReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	dir := t.TempDir()
	content := "panic: fixture\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	evidencePath := filepath.Join(dir, "logs", "failed.log")
	infoBefore, err := os.Stat(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
	manifest := evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", "")
	writeEvidenceTestCapsule(t, dir, manifest)

	_ = verifyCapsuleEvidence(manifest, dir)

	infoAfter, err := os.Stat(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if infoAfter.Mode() != infoBefore.Mode() || infoAfter.ModTime() != infoBefore.ModTime() || infoAfter.Size() != infoBefore.Size() {
		t.Fatalf("evidence file changed during verification: before=%#v after=%#v", infoBefore, infoAfter)
	}
}

func TestCapsuleInspectListsVerifiedEvidence(t *testing.T) {
	dir := t.TempDir()
	content := "panic: fixture\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", content)
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout, stderr bytes.Buffer
	if err := (App{Stdout: &stdout, Stderr: &stderr}).capsuleInspect(context.Background(), []string{manifestPath}); err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"evidence group=logs", `"failed-actions-log"`, "path=logs/failed.log", "status=verified"} {
		if !strings.Contains(out, want) {
			t.Fatalf("inspect output %q missing %q", out, want)
		}
	}
}

func TestCapsuleInspectListsInvalidEvidenceAndFails(t *testing.T) {
	dir := t.TempDir()
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", "tampered-log!")
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", "original-log!")
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout bytes.Buffer
	err := (App{Stdout: &stdout, Stderr: &stdout}).capsuleInspect(context.Background(), []string{manifestPath})
	var exitErr ExitError
	if !AsExitError(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("expected exit code 1, got %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"status=invalid", "failed-actions-log", "logs/failed.log", "digest mismatch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("inspect output %q missing %q", out, want)
		}
	}
	if !strings.Contains(err.Error(), "evidence verification failed") {
		t.Fatalf("inspect error %q missing verification failure", err.Error())
	}
}

func TestCapsuleInspectMarksLegacyEvidenceUnverified(t *testing.T) {
	dir := t.TempDir()
	content := "legacy log\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	ref := capsuleArtifactRef{Name: "failed-actions-log", Path: "logs/failed.log", Size: int64(len(content))}
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout bytes.Buffer
	if err := (App{Stdout: &stdout, Stderr: &stdout}).capsuleInspect(context.Background(), []string{manifestPath}); err != nil {
		t.Fatalf("legacy inspect failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "status=unverified") || !strings.Contains(stdout.String(), "no digest declared") {
		t.Fatalf("inspect output=%q", stdout.String())
	}
}

func TestCapsuleInspectNoVerifySkipsEvidenceChecks(t *testing.T) {
	dir := t.TempDir()
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", "tampered-log!")
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", "original-log!")
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout bytes.Buffer
	if err := (App{Stdout: &stdout, Stderr: &stdout}).capsuleInspect(context.Background(), []string{manifestPath, "--no-verify"}); err != nil {
		t.Fatalf("--no-verify should skip verification: %v", err)
	}
	if strings.Contains(stdout.String(), "\nevidence group=") {
		t.Fatalf("--no-verify must not print evidence lines: %q", stdout.String())
	}
}

func TestCapsuleInspectJSONIncludesEvidenceResults(t *testing.T) {
	dir := t.TempDir()
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", "tampered-log!")
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", "original-log!")
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout bytes.Buffer
	err := (App{Stdout: &stdout, Stderr: &stdout}).capsuleInspect(context.Background(), []string{manifestPath, "--json"})
	var exitErr ExitError
	if !AsExitError(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("expected exit code 1, got %v", err)
	}
	var out struct {
		CapsuleID string                  `json:"capsule_id"`
		Evidence  []capsuleEvidenceResult `json:"evidence"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode json: %v\n%s", err, stdout.String())
	}
	if out.CapsuleID != "sha256:evidence-test" || len(out.Evidence) != 1 {
		t.Fatalf("json output=%#v", out)
	}
	if out.Evidence[0].Status != capsuleEvidenceInvalid || !strings.Contains(out.Evidence[0].Reason, "digest mismatch") {
		t.Fatalf("evidence=%#v", out.Evidence[0])
	}
}

func TestCapsuleReplayBlocksTamperedEvidenceBeforeLease(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("CRABBOX_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("CRABBOX_PROVIDER", "capsule-evidence-test-nonexistent")
	dir := t.TempDir()
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", "tampered-log!")
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", "original-log!")
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout, stderr bytes.Buffer
	err := (App{Stdout: &stdout, Stderr: &stderr}).capsuleReplay(context.Background(), []string{manifestPath})
	var exitErr ExitError
	if !AsExitError(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("expected verification failure exit 1, got %v", err)
	}
	for _, want := range []string{"refusing replay", "failed-actions-log", "logs/failed.log", "digest mismatch"} {
		if !strings.Contains(err.Error(), want) && !strings.Contains(stderr.String(), want) {
			t.Fatalf("replay error %q missing %q", err.Error(), want)
		}
	}
	reread, readErr := readCapsuleManifest(manifestPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(reread.Replays) != 0 {
		t.Fatalf("blocked replay must not append a replay record: %#v", reread.Replays)
	}
}

func TestCapsuleReplayWarnsForLegacyUnverifiedEvidence(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("CRABBOX_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("CRABBOX_PROVIDER", "capsule-evidence-test-nonexistent")
	dir := t.TempDir()
	content := "legacy log\n"
	writeCapsuleEvidenceFile(t, dir, "logs/failed.log", content)
	ref := capsuleArtifactRef{Name: "failed-actions-log", Path: "logs/failed.log", Size: int64(len(content))}
	manifestPath := writeEvidenceTestCapsule(t, dir, evidenceTestCapsule(dir, []capsuleArtifactRef{ref}, "true", ""))

	var stdout, stderr bytes.Buffer
	err := (App{Stdout: &stdout, Stderr: &stderr}).capsuleReplay(context.Background(), []string{manifestPath})
	if err != nil && strings.Contains(err.Error(), "evidence verification failed") {
		t.Fatalf("legacy evidence must not block replay: %v", err)
	}
	warning := stderr.String()
	for _, want := range []string{"warning:", "failed-actions-log", "logs/failed.log", "unverified"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("legacy warning %q missing %q", warning, want)
		}
	}
}

func setupCapsuleReplayRunHarness(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake ssh fixture")
	}
	clearConfigEnv(t)
	t.Setenv("CI", "true")
	workDir := t.TempDir()
	isolateRunTestUserDirs(t, workDir)
	t.Chdir(workDir)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ssh := `#!/bin/sh
cmd=""
for arg do cmd="$arg"; done
case "$cmd" in
  *CRABBOX_RUN_*)
    printf 'workload\n' >> "$CRABBOX_TEST_WORKLOAD_LOG"
    sh -c "$cmd"
    exit $? ;;
  mkdir\ -p*|cd\ *|\(cd\ *|bash\ -lc*|/bin/bash\ -lc*|/usr/bin/env\ *) exec sh -c "$cmd" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(workDir, "ssh"), []byte(ssh), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", workDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CRABBOX_CONFIG", filepath.Join(workDir, "config.yaml"))
	t.Setenv("CRABBOX_PROVIDER", "run-env-profile-test")
	t.Setenv("CRABBOX_FAKE_SSH_PORT", port)
	t.Setenv("CRABBOX_WORK_ROOT", filepath.Join(workDir, "remote"))
	workloadLog := filepath.Join(workDir, "workloads.log")
	t.Setenv("CRABBOX_TEST_WORKLOAD_LOG", workloadLog)
	runEnvProfileTestReleaseHook = func() error { return nil }
	t.Cleanup(func() { runEnvProfileTestReleaseHook = nil })
	return workloadLog
}

func TestCapsuleReplayRunsAfterSuccessfulVerification(t *testing.T) {
	workloadLog := setupCapsuleReplayRunHarness(t)
	capsuleDir := t.TempDir()
	evidence := "Go\tTest\tpanic: original failure\n"
	writeCapsuleEvidenceFile(t, capsuleDir, "logs/failed.log", evidence)
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", evidence)
	manifest := evidenceTestCapsule(capsuleDir, []capsuleArtifactRef{ref}, "printf 'panic: capsule replay fixture\n'; exit 23", "panic: capsule replay fixture")
	manifestPath := writeEvidenceTestCapsule(t, capsuleDir, manifest)

	var stdout, stderr bytes.Buffer
	err := (App{Stdout: &stdout, Stderr: &stderr}).capsuleReplay(context.Background(), []string{manifestPath, "--no-sync"})
	if err != nil {
		t.Fatalf("verified replay should run and reproduce the failure: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "outcome="+capsuleOutcomeFailReproduced) {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(workloadLog); err != nil {
		t.Fatalf("replay workload never ran: %v", err)
	}
	reread, err := readCapsuleManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reread.Replays) != 1 || reread.Replays[0].Outcome != capsuleOutcomeFailReproduced || reread.Replays[0].ExitCode != 23 {
		t.Fatalf("replay history=%#v", reread.Replays)
	}
}

func TestCapsuleReplayDoesNotStartRunnerWhenVerificationFails(t *testing.T) {
	workloadLog := setupCapsuleReplayRunHarness(t)
	capsuleDir := t.TempDir()
	writeCapsuleEvidenceFile(t, capsuleDir, "logs/failed.log", "tampered-log!")
	ref := capsuleEvidenceRefFor("failed-actions-log", "logs/failed.log", "original-log!")
	manifestPath := writeEvidenceTestCapsule(t, capsuleDir, evidenceTestCapsule(capsuleDir, []capsuleArtifactRef{ref}, "true", "panic"))

	var stdout, stderr bytes.Buffer
	err := (App{Stdout: &stdout, Stderr: &stderr}).capsuleReplay(context.Background(), []string{manifestPath, "--no-sync"})
	var exitErr ExitError
	if !AsExitError(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("expected verification failure exit 1, got %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(err.Error(), "refusing replay") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(workloadLog); !os.IsNotExist(err) {
		t.Fatalf("replay started despite failed verification: workload log exists: %v", err)
	}
	reread, err := readCapsuleManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reread.Replays) != 0 {
		t.Fatalf("blocked replay must not record history: %#v", reread.Replays)
	}
}
