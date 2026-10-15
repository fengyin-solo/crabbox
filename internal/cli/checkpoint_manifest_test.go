package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type checkpointFixtureEntry struct {
	path     string
	kind     string
	mode     int64
	content  []byte
	linkname string
}

func buildCheckpointFixtureArchive(t *testing.T, entries []checkpointFixtureEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	root := &tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: time.Unix(1_700_000_000, 0)}
	if err := tw.WriteHeader(root); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		header := &tar.Header{Name: "./" + entry.path, Mode: entry.mode, ModTime: time.Unix(1_700_000_000, 0)}
		switch entry.kind {
		case checkpointManifestEntryFile:
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(entry.content))
		case checkpointManifestEntryDir:
			header.Typeflag = tar.TypeDir
		case checkpointManifestEntrySymlink:
			header.Typeflag = tar.TypeSymlink
			header.Linkname = entry.linkname
		default:
			t.Fatalf("unsupported fixture kind %s", entry.kind)
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.kind == checkpointManifestEntryFile {
			if _, err := tw.Write(entry.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeCheckpointFixtureArchive(t *testing.T, archivePath string, entries []checkpointFixtureEntry) []byte {
	t.Helper()
	data := buildCheckpointFixtureArchive(t, entries)
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func checkpointTestEntries() []checkpointFixtureEntry {
	return []checkpointFixtureEntry{
		{path: "bin", kind: checkpointManifestEntryDir, mode: 0o755},
		{path: "bin/run.sh", kind: checkpointManifestEntryFile, mode: 0o755, content: []byte("#!/bin/sh\necho ok\n")},
		{path: "etc", kind: checkpointManifestEntryDir, mode: 0o750},
		{path: "etc/config.yaml", kind: checkpointManifestEntryFile, mode: 0o640, content: []byte("name: my-app\n")},
		{path: "README.md", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("# checkpoint\n")},
		{path: "logs", kind: checkpointManifestEntrySymlink, mode: 0o777, linkname: "/tmp/logs"},
		{path: "etc/rel", kind: checkpointManifestEntrySymlink, mode: 0o777, linkname: "../README.md"},
	}
}

func adoptTestManifest(t *testing.T, archivePath, leaseID, workdir string) *checkpointArchiveManifest {
	t.Helper()
	report, err := adoptCheckpointArchiveManifest(archivePath, checkpointManifestPathFor(archivePath),
		checkpointArchive, leaseID, workdir, "2026-10-15T08:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("adopted manifest did not verify: %#v", report.Damages)
	}
	manifest, err := loadCheckpointArchiveManifest(checkpointManifestPathFor(archivePath))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func damageCodes(report *checkpointArchiveVerification) []string {
	codes := make([]string, 0, len(report.Damages))
	for _, damage := range report.Damages {
		codes = append(codes, damage.Code)
	}
	sort.Strings(codes)
	return codes
}

func damageForPath(report *checkpointArchiveVerification, path, code string) bool {
	for _, damage := range report.Damages {
		if damage.Path == path && damage.Code == code {
			return true
		}
	}
	return false
}

func TestCheckpointManifestCreateRecordsMetadataAndEntries(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	writeCheckpointFixtureArchive(t, archivePath, checkpointTestEntries())
	manifest := adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace/my-app")

	if manifest.SchemaVersion != checkpointManifestSchemaV1 {
		t.Fatalf("schema=%d", manifest.SchemaVersion)
	}
	if manifest.CreatedAt != "2026-10-15T08:00:00Z" || manifest.SourceLeaseID != "cbx_0123456789ab" || manifest.Workdir != "/workspace/my-app" {
		t.Fatalf("metadata=%#v", manifest)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Archive.Size != info.Size() || len(manifest.Archive.SHA256) != 64 {
		t.Fatalf("archive digest=%#v size=%d", manifest.Archive, info.Size())
	}
	byPath := map[string]checkpointManifestEntry{}
	for _, entry := range manifest.Entries {
		byPath[entry.Path] = entry
	}
	run := byPath["bin/run.sh"]
	if run.Type != checkpointManifestEntryFile || run.Mode != 0o755 || run.Size != int64(len("#!/bin/sh\necho ok\n")) || len(run.SHA256) != 64 {
		t.Fatalf("run.sh entry=%#v", run)
	}
	logs := byPath["logs"]
	if logs.Type != checkpointManifestEntrySymlink || logs.Linkname != "/tmp/logs" {
		t.Fatalf("logs entry=%#v", logs)
	}
	rel := byPath["etc/rel"]
	if rel.Type != checkpointManifestEntrySymlink || rel.Linkname != "../README.md" {
		t.Fatalf("rel entry=%#v", rel)
	}
	if byPath["bin"].Type != checkpointManifestEntryDir || byPath["etc/config.yaml"].Mode != 0o640 {
		t.Fatalf("dir/mode entries=%#v %#v", byPath["bin"], byPath["etc/config.yaml"])
	}
	if _, ok := byPath[""]; ok {
		t.Fatal("manifest recorded the archive root entry")
	}

	// The on-disk manifest is the JSON published next to the archive.
	data, err := os.ReadFile(checkpointManifestPathFor(archivePath))
	if err != nil {
		t.Fatal(err)
	}
	var decoded checkpointArchiveManifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Archive.SHA256 != manifest.Archive.SHA256 {
		t.Fatal("persisted manifest digest mismatch")
	}
}

func TestCheckpointManifestVerifyTruncatedArchive(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	data := writeCheckpointFixtureArchive(t, archivePath, checkpointTestEntries())
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	if err := os.Truncate(archivePath, int64(len(data)/2)); err != nil {
		t.Fatal(err)
	}
	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if report.Legacy || report.Manifest != true || report.Verified {
		t.Fatalf("report=%#v", report)
	}
	if !report.damage(checkpointDamageArchiveUnreadable) || !report.damage(checkpointDamageArchiveDigest) {
		t.Fatalf("expected truncation and digest damage, got %v", damageCodes(report))
	}
	if !report.damage(checkpointDamageMissingEntry) {
		t.Fatalf("expected missing entries after truncation: %v", damageCodes(report))
	}
	if report.Repair != "refetch_entries" {
		t.Fatalf("repair=%s", report.Repair)
	}
	for _, damage := range report.Damages {
		if damage.Path != "" && !damage.Repairable {
			t.Fatalf("entry damage must be repairable: %#v", damage)
		}
	}
}

func TestCheckpointManifestVerifyReplacedFile(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	replaced := append([]checkpointFixtureEntry(nil), entries...)
	replaced[4] = checkpointFixtureEntry{path: "README.md", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("# replaced by hand\n")}
	writeCheckpointFixtureArchive(t, archivePath, replaced)

	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if report.Verified {
		t.Fatal("replaced file verified")
	}
	if !damageForPath(report, "README.md", checkpointDamageDigestMismatch) {
		t.Fatalf("missing digest damage: %v", damageCodes(report))
	}
	if !report.damage(checkpointDamageArchiveDigest) {
		t.Fatalf("archive digest must fail: %v", damageCodes(report))
	}
	if damageForPath(report, "bin/run.sh", checkpointDamageDigestMismatch) {
		t.Fatal("unrelated file reported damaged")
	}
}

func TestCheckpointManifestVerifyPermissionChange(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	changed := append([]checkpointFixtureEntry(nil), entries...)
	changed[3] = checkpointFixtureEntry{path: "etc/config.yaml", kind: checkpointManifestEntryFile, mode: 0o600, content: []byte("name: my-app\n")}
	writeCheckpointFixtureArchive(t, archivePath, changed)

	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if !damageForPath(report, "etc/config.yaml", checkpointDamageModeMismatch) {
		t.Fatalf("expected mode damage: %v", damageCodes(report))
	}
}

func TestCheckpointManifestVerifySymlinkRetarget(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	changed := append([]checkpointFixtureEntry(nil), entries...)
	changed[5] = checkpointFixtureEntry{path: "logs", kind: checkpointManifestEntrySymlink, mode: 0o777, linkname: "/var/tmp/logs"}
	writeCheckpointFixtureArchive(t, archivePath, changed)

	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if !damageForPath(report, "logs", checkpointDamageLinkMismatch) {
		t.Fatalf("expected link damage: %v", damageCodes(report))
	}
}

func TestCheckpointManifestVerifyExtraEntry(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	writeCheckpointFixtureArchive(t, archivePath, checkpointTestEntries())
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	withExtra := append(checkpointTestEntries(),
		checkpointFixtureEntry{path: "surprise.txt", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("late")})
	writeCheckpointFixtureArchive(t, archivePath, withExtra)

	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if !damageForPath(report, "surprise.txt", checkpointDamageExtraEntry) {
		t.Fatalf("expected extra entry damage: %v", damageCodes(report))
	}
}

func TestCheckpointManifestLegacyMarkedUnverified(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	writeCheckpointFixtureArchive(t, archivePath, checkpointTestEntries())

	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if !report.Legacy || report.Verified || report.Repair != "rebuild_manifest" {
		t.Fatalf("legacy report=%#v", report)
	}

	// An unreadable legacy archive cannot be reconstructed without a manifest.
	if err := os.WriteFile(archivePath, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	report = verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if !report.Legacy || report.Repair != "recreate" || !report.damage(checkpointDamageArchiveUnreadable) {
		t.Fatalf("unreadable legacy report=%#v", report)
	}
}

func TestCheckpointManifestCorruptManifestReportedAndAdoptable(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	writeCheckpointFixtureArchive(t, archivePath, checkpointTestEntries())
	manifestPath := checkpointManifestPathFor(archivePath)
	if err := os.WriteFile(manifestPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := verifyLocalCheckpointArchive(archivePath, manifestPath)
	if report.Legacy || report.Manifest || report.Verified {
		t.Fatalf("report=%#v", report)
	}
	if !report.damage(checkpointDamageManifestCorrupt) || report.Repair != "rebuild_manifest" {
		t.Fatalf("damages=%v repair=%s", damageCodes(report), report.Repair)
	}
	adopted, err := adoptCheckpointArchiveManifest(archivePath, manifestPath, checkpointArchive,
		"cbx_0123456789ab", "/workspace", "2026-10-15T08:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !adopted.Verified {
		t.Fatalf("adoption did not verify: %#v", adopted.Damages)
	}
}

func newFixtureEntryTransfer(t *testing.T, fixtures []checkpointFixtureEntry) (checkpointEntryTransfer, *[]string, *sync.Mutex) {
	t.Helper()
	source := map[string]checkpointFixtureEntry{}
	for _, entry := range fixtures {
		source[entry.path] = entry
	}
	var mu sync.Mutex
	requested := []string{}
	transfer := func(_ context.Context, entry checkpointManifestEntry, destination string) error {
		mu.Lock()
		requested = append(requested, entry.Path)
		mu.Unlock()
		fixture, ok := source[entry.Path]
		if !ok {
			return fmt.Errorf("test source has no entry %s", entry.Path)
		}
		data := buildCheckpointFixtureArchive(t, []checkpointFixtureEntry{fixture})
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			return err
		}
		return nil
	}
	return transfer, &requested, &mu
}

func repairAndVerify(t *testing.T, archivePath string, fixtures []checkpointFixtureEntry, transfer checkpointEntryTransfer) *checkpointArchiveVerification {
	t.Helper()
	manifest, err := loadCheckpointArchiveManifest(checkpointManifestPathFor(archivePath))
	if err != nil {
		t.Fatal(err)
	}
	report, err := repairCheckpointArchive(context.Background(), archivePath, checkpointManifestPathFor(archivePath), manifest, transfer)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if !report.Verified {
		t.Fatalf("post-repair report=%#v", report.Damages)
	}
	return report
}

func TestCheckpointManifestIncrementalRepairTransfersOnlyDamagedEntry(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	replaced := append([]checkpointFixtureEntry(nil), entries...)
	replaced[4] = checkpointFixtureEntry{path: "README.md", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("# replaced by hand\n")}
	writeCheckpointFixtureArchive(t, archivePath, replaced)

	transfer, requested, mu := newFixtureEntryTransfer(t, entries)
	report := repairAndVerify(t, archivePath, entries, transfer)

	mu.Lock()
	got := append([]string(nil), (*requested)...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "README.md" {
		t.Fatalf("requested=%v, want only README.md", got)
	}
	if report.EntryCount != len(entries) {
		t.Fatalf("entries=%d want %d", report.EntryCount, len(entries))
	}
	// A second repair is a no-op and performs no transfer.
	before := len(got)
	report = repairAndVerify(t, archivePath, entries, transfer)
	if len(got) != before || !report.Verified {
		t.Fatalf("idempotent repair transferred again: %v", got)
	}
}

func TestCheckpointManifestRepairResumesSpooledEntries(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	corrupt := append([]checkpointFixtureEntry(nil), entries...)
	corrupt[1] = checkpointFixtureEntry{path: "bin/run.sh", kind: checkpointManifestEntryFile, mode: 0o755, content: []byte("broken")}
	corrupt[4] = checkpointFixtureEntry{path: "README.md", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("also broken")}
	writeCheckpointFixtureArchive(t, archivePath, corrupt)

	// Simulate a previous interrupted repair: a valid spool exists for
	// README.md while the bin/run.sh spool is garbage and must be refetched.
	spoolDir := archivePath + ".repair"
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	readme := entries[4]
	if err := os.WriteFile(filepath.Join(spoolDir, checkpointSpoolName("README.md")),
		buildCheckpointFixtureArchive(t, []checkpointFixtureEntry{readme}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, checkpointSpoolName("bin/run.sh")), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	transfer, requested, mu := newFixtureEntryTransfer(t, entries)
	repairAndVerify(t, archivePath, entries, transfer)

	mu.Lock()
	got := append([]string(nil), (*requested)...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "bin/run.sh" {
		t.Fatalf("requested=%v, want only the invalid-spool entry bin/run.sh", got)
	}
	if _, err := os.Stat(spoolDir); !os.IsNotExist(err) {
		t.Fatalf("spool directory survived repair: %v", err)
	}
}

func TestCheckpointManifestRepairAfterTruncationRefetchesMissingEntries(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	data := writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")
	if err := os.Truncate(archivePath, int64(len(data)/2)); err != nil {
		t.Fatal(err)
	}

	transfer, requested, mu := newFixtureEntryTransfer(t, entries)
	repairAndVerify(t, archivePath, entries, transfer)

	mu.Lock()
	got := append([]string(nil), (*requested)...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("truncated archive repair refetched nothing")
	}
	// Intact prefix entries must not be transferred again.
	seen := map[string]bool{}
	for _, p := range got {
		if seen[p] {
			t.Fatalf("entry %s transferred twice", p)
		}
		seen[p] = true
	}
}

func TestCheckpointManifestRepairDropsExtraEntryWithoutTransfer(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	writeCheckpointFixtureArchive(t, archivePath, entries)
	adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")
	withExtra := append(entries, checkpointFixtureEntry{path: "surprise.txt", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("late")})
	writeCheckpointFixtureArchive(t, archivePath, withExtra)

	transfer := func(_ context.Context, _ checkpointManifestEntry, _ string) error {
		t.Fatal("repair of an extra entry must not transfer anything")
		return nil
	}
	report := repairAndVerify(t, archivePath, entries, transfer)
	if report.EntryCount != len(entries) {
		t.Fatalf("entries=%d want %d", report.EntryCount, len(entries))
	}
}

func TestCheckpointManifestRepairRecompactsWhenOnlyArchiveDigestDiffers(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, checkpointArchive)
	entries := checkpointTestEntries()
	data := writeCheckpointFixtureArchive(t, archivePath, entries)
	manifest := adoptTestManifest(t, archivePath, "cbx_0123456789ab", "/workspace")

	// Rewrap the identical tar stream with different gzip framing: only the
	// compressed-archive digest can differ.
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tarBytes, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	var rewrapped bytes.Buffer
	writer, err := gzip.NewWriterLevel(&rewrapped, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rewrapped.Bytes(), data) {
		t.Fatal("test setup failed to change gzip framing")
	}
	if err := os.WriteFile(archivePath, rewrapped.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	report := verifyLocalCheckpointArchive(archivePath, checkpointManifestPathFor(archivePath))
	if !report.damage(checkpointDamageArchiveDigest) || len(checkpointRefetchPaths(manifest, report)) != 0 {
		t.Fatalf("expected archive-only digest damage: %v", damageCodes(report))
	}
	transfer := func(_ context.Context, _ checkpointManifestEntry, _ string) error {
		t.Fatal("archive-level damage must repair locally without transfers")
		return nil
	}
	repairAndVerify(t, archivePath, entries, transfer)
}

func TestCheckpointManifestRefetchSpoolRejectsWrongContent(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool.tgz")
	writeCheckpointFixtureArchive(t, spool, []checkpointFixtureEntry{
		{path: "README.md", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("different")},
	})
	digest := fmt.Sprintf("%x", sha256SumForTest([]byte("# checkpoint\n")))
	manifestEntry := checkpointManifestEntry{
		Path: "README.md", Type: checkpointManifestEntryFile, Mode: 0o644,
		Size: int64(len("# checkpoint\n")), SHA256: digest,
	}
	if validCheckpointEntrySpool(spool, manifestEntry) {
		t.Fatal("spool with mismatched content was accepted")
	}

	writeCheckpointFixtureArchive(t, spool, []checkpointFixtureEntry{
		{path: "README.md", kind: checkpointManifestEntryFile, mode: 0o644, content: []byte("# checkpoint\n")},
	})
	if !validCheckpointEntrySpool(spool, manifestEntry) {
		t.Fatal("matching spool was rejected")
	}
}

func sha256SumForTest(content []byte) []byte {
	digest := sha256.Sum256(content)
	return digest[:]
}

func TestCheckpointManifestEntryNameCrossPlatform(t *testing.T) {
	for _, tc := range []struct {
		name    string
		goos    string
		input   string
		wantRel string
		wantOK  bool
	}{
		{name: "nested unix", goos: "linux", input: "etc/config.yaml", wantRel: "etc/config.yaml", wantOK: true},
		{name: "dot slash prefix", goos: "linux", input: "./etc/config.yaml", wantRel: "etc/config.yaml", wantOK: true},
		{name: "archive root", goos: "linux", input: "./", wantRel: "", wantOK: true},
		{name: "spaces and unicode", goos: "linux", input: "data/üniçode f.txt", wantRel: "data/üniçode f.txt", wantOK: true},
		{name: "traversal", goos: "linux", input: "../secret", wantOK: false},
		{name: "nested traversal", goos: "linux", input: "a/../../secret", wantOK: false},
		{name: "absolute", goos: "linux", input: "/etc/passwd", wantOK: false},
		{name: "empty component", goos: "linux", input: "a//b", wantOK: false},
		{name: "parent only", goos: "linux", input: "..", wantOK: false},
		{name: "windows backslash", goos: "windows", input: `a\b`, wantOK: false},
		{name: "windows reserved", goos: "windows", input: "AUX.txt", wantOK: false},
		{name: "windows com port", goos: "windows", input: "COM9/log", wantOK: false},
		{name: "windows drive colon", goos: "windows", input: "a:b", wantOK: false},
		{name: "windows trailing dot", goos: "windows", input: "x.", wantOK: false},
		{name: "windows trailing space", goos: "windows", input: "x ", wantOK: false},
		{name: "windows nested", goos: "windows", input: "etc/config.yaml", wantRel: "etc/config.yaml", wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel, root, err := normalizeCheckpointEntryNameForGOOS(tc.goos, tc.input)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("normalize(%q) error=%v", tc.input, err)
				}
				want := tc.wantRel
				if tc.input == "./" && !root {
					t.Fatalf("normalize(%q) root=false", tc.input)
				}
				if rel != want {
					t.Fatalf("normalize(%q)=%q want %q", tc.input, rel, want)
				}
			} else if err == nil {
				t.Fatalf("normalize(%q)=%q, want error", tc.input, rel)
			}
		})
	}
}

func TestCheckpointManifestValidatesUnsafePersistedEntries(t *testing.T) {
	manifest := &checkpointArchiveManifest{
		SchemaVersion: checkpointManifestSchemaV1,
		CreatedAt:     "2026-10-15T08:00:00Z",
		Archive: checkpointManifestArchiveDigest{
			Name: checkpointArchive, Size: 1, SHA256: strings.Repeat("a", 64),
		},
		Entries: []checkpointManifestEntry{
			{Path: "../escape", Type: checkpointManifestEntryFile, Size: 0, SHA256: strings.Repeat("b", 64)},
		},
	}
	if err := manifest.validate(); err == nil {
		t.Fatal("manifest with traversal entry validated")
	}
	manifest.Entries[0].Path = "ok"
	manifest.Entries[0].SHA256 = "short"
	if err := manifest.validate(); err == nil {
		t.Fatal("manifest with bad digest validated")
	}
	manifest.Entries[0].SHA256 = strings.Repeat("b", 64)
	manifest.SchemaVersion = 99
	if err := manifest.validate(); err == nil {
		t.Fatal("future schema version must be rejected")
	}
}
