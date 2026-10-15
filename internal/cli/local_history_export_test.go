package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func setExportTestHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	prev, had := os.LookupEnv("XDG_STATE_HOME")
	if err := os.Setenv("XDG_STATE_HOME", root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("XDG_STATE_HOME", prev)
		} else {
			_ = os.Unsetenv("XDG_STATE_HOME")
		}
	})
	return root
}

func exportTerminalRecord(t *testing.T, n int, logText string, summary *TestResultSummary, modify func(*localHistoryRecord)) localHistoryRecord {
	t.Helper()
	record := localHistoryTestRecord(n)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record.StartedAt = now
	record.UpdatedAt = now
	if modify != nil {
		modify(&record)
	}
	writer, err := beginLocalHistory(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordingState = "terminal"
	record.Phase = "finalizing"
	record.EndedAt = now
	code := 0
	record.ExitCode = &code
	if summary != nil {
		record.ResultsState = "collected"
		record.RunStatus = RunStatusSucceeded
	}
	if err := writer.Commit(record, runLogSnapshot{Log: logText}, summary); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return record
}

func exportTestApp(input io.Reader) (App, *bytes.Buffer, *bytes.Buffer) {
	var out, diag bytes.Buffer
	if input == nil {
		input = bytes.NewReader(nil)
	}
	return App{Stdout: &out, Stderr: &diag, Stdin: input}, &out, &diag
}

func runHistoryExport(t *testing.T, a App, args ...string) (string, string, error) {
	t.Helper()
	err := a.history(context.Background(), append([]string{"export"}, args...))
	return a.Stdout.(*bytes.Buffer).String(), a.Stderr.(*bytes.Buffer).String(), err
}

func runHistoryImport(t *testing.T, a App, args ...string) (string, string, error) {
	t.Helper()
	err := a.history(context.Background(), append([]string{"import"}, args...))
	return a.Stdout.(*bytes.Buffer).String(), a.Stderr.(*bytes.Buffer).String(), err
}

// readExportArchive returns the manifest and a name -> bytes member map.
func readExportArchive(t *testing.T, archive []byte) (historyExportManifest, map[string][]byte) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	manifest := historyExportManifest{}
	members := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == historyExportManifestName {
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
		}
		members[header.Name] = data
	}
	return manifest, members
}

func TestLocalHistoryExportImportCrossMachineRoundtrip(t *testing.T) {
	setExportTestHome(t)
	first := exportTerminalRecord(t, 1, "first output\n", &TestResultSummary{Format: "junit", Tests: 4, Failures: 1, Failed: []TestFailure{{Name: "fails"}}}, nil)
	second := exportTerminalRecord(t, 2, "plain log\n", nil, func(r *localHistoryRecord) {
		r.Source = "both"
		r.CoordinatorState = "recorded"
		r.CoordinatorRunID = r.ID
		r.CoordinatorReference = "sha256:" + strings.Repeat("a", 64)
	})
	a, _, _ := exportTestApp(nil)
	archivePath := filepath.Join(t.TempDir(), "history.tar.gz")
	if _, diag, err := runHistoryExport(t, a, "--output", archivePath); err != nil {
		t.Fatalf("export: %v %s", err, diag)
	}
	if info, err := os.Stat(archivePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode=%v err=%v, want 0600", info.Mode(), err)
	}
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, members := readExportArchive(t, raw)
	if manifest.SchemaVersion != historyExportSchemaVersion {
		t.Fatalf("schema=%d", manifest.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.ExportedAt); err != nil {
		t.Fatalf("exportedAt: %v", err)
	}
	if len(manifest.Records) != 2 {
		t.Fatalf("records=%d", len(manifest.Records))
	}
	for _, record := range manifest.Records {
		if record.RecordingState != "terminal" {
			t.Fatalf("non-terminal manifest record %s", record.ID)
		}
		for _, file := range record.Files {
			data, ok := members[file.Path]
			if !ok {
				t.Fatalf("missing member %s", file.Path)
			}
			if localHistoryDigest(data) != file.SHA256 {
				t.Fatalf("manifest digest wrong for %s", file.Path)
			}
			if file.Mode != 0o600 {
				t.Fatalf("mode for %s = %o", file.Path, file.Mode)
			}
		}
	}

	// Migrate to a fresh machine state directory before importing.
	setExportTestHome(t)
	b, out, _ := exportTestApp(bytes.NewReader(raw))
	if text, _, err := runHistoryImport(t, b, "-"); err != nil || !strings.Contains(text, "imported 2") {
		t.Fatalf("stdin import: %v %q", err, text)
	}
	for _, id := range []string{first.ID, second.ID} {
		record, log, results, err := readLocalHistory(id)
		if err != nil {
			t.Fatalf("read %s after import: %v", id, err)
		}
		if record.ID != id {
			t.Fatalf("identity mismatch %s", id)
		}
		if id == first.ID {
			if log != "first output\n" || results == nil || results.Format != "junit" || results.Tests != 4 || len(results.Failed) != 1 {
				t.Fatalf("payload mismatch log=%q results=%+v", log, results)
			}
		} else {
			if log != "plain log\n" || results != nil {
				t.Fatalf("plain record payload log=%q results=%+v", log, results)
			}
			if record.Source != "both" || record.CoordinatorState != "recorded" ||
				record.CoordinatorRunID != id || record.CoordinatorReference != "sha256:"+strings.Repeat("a", 64) {
				t.Fatalf("coordinator provenance lost: %+v", record)
			}
		}
	}
	c, listOut, _ := exportTestApp(nil)
	if _, diag, err := runHistoryList(t, c, "--source", "local", "--json"); err != nil {
		t.Fatalf("history list: %v %s", err, diag)
	}
	var envelope historyReadEnvelope
	if err := json.Unmarshal([]byte(listOut.String()), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Records) != 2 {
		t.Fatalf("listed %d records after import", len(envelope.Records))
	}
	assertImportedHistoryPrivate(t)
	_ = out
}

func runHistoryList(t *testing.T, a App, args ...string) (string, string, error) {
	t.Helper()
	err := a.history(context.Background(), args)
	return a.Stdout.(*bytes.Buffer).String(), a.Stderr.(*bytes.Buffer).String(), err
}

func assertImportedHistoryPrivate(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	state, err := CrabboxStateDir()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(state, "history")
	err = filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0o600)
		if entry.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			return fmt.Errorf("imported %s mode %o, want %o", name, info.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalHistoryExportFilters(t *testing.T) {
	setExportTestHome(t)
	one := exportTerminalRecord(t, 1, "one\n", &TestResultSummary{Format: "junit", Tests: 1}, func(r *localHistoryRecord) {
		r.LeaseID = "cbx_lease-filter-one"
		r.StartedAt = "2026-01-01T00:00:00Z"
	})
	two := exportTerminalRecord(t, 2, "two\n", nil, func(r *localHistoryRecord) {
		r.LeaseID = "cbx_lease-filter-two"
		r.StartedAt = "2026-02-01T00:00:00Z"
	})
	dir := t.TempDir()

	// Explicit single id.
	a, _, _ := exportTestApp(nil)
	path := filepath.Join(dir, "single.tar.gz")
	if _, diag, err := runHistoryExport(t, a, "--output", path, one.ID); err != nil {
		t.Fatalf("single export: %v %s", err, diag)
	}
	manifest, _ := readExportArchive(t, readFile(t, path))
	if len(manifest.Records) != 1 || manifest.Records[0].ID != one.ID {
		t.Fatalf("single manifest=%+v", manifest.Records)
	}

	// Lease filter selects one record even though two terminal records exist.
	b, _, _ := exportTestApp(nil)
	path = filepath.Join(dir, "lease.tar.gz")
	if _, diag, err := runHistoryExport(t, b, "--output", path, "--lease", "cbx_lease-filter-two"); err != nil {
		t.Fatalf("lease export: %v %s", err, diag)
	}
	manifest, _ = readExportArchive(t, readFile(t, path))
	if len(manifest.Records) != 1 || manifest.Records[0].ID != two.ID {
		t.Fatalf("lease manifest=%+v", manifest.Records)
	}

	// State filter matches the succeeded run only.
	c, _, _ := exportTestApp(nil)
	path = filepath.Join(dir, "state.tar.gz")
	if _, diag, err := runHistoryExport(t, c, "--output", path, "--state", "succeeded"); err != nil {
		t.Fatalf("state export: %v %s", err, diag)
	}
	manifest, _ = readExportArchive(t, readFile(t, path))
	if len(manifest.Records) != 1 || manifest.Records[0].ID != one.ID {
		t.Fatalf("state manifest=%+v", manifest.Records)
	}

	// Limit applies in newest-first listing order.
	d, _, _ := exportTestApp(nil)
	path = filepath.Join(dir, "limit.tar.gz")
	if _, diag, err := runHistoryExport(t, d, "--output", path, "--limit", "1"); err != nil {
		t.Fatalf("limit export: %v %s", err, diag)
	}
	manifest, _ = readExportArchive(t, readFile(t, path))
	if len(manifest.Records) != 1 || manifest.Records[0].ID != two.ID {
		t.Fatalf("limit manifest=%+v", manifest.Records)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLocalHistoryExportSkipsActive(t *testing.T) {
	setExportTestHome(t)
	active := localHistoryTestRecord(7)
	writer, err := beginLocalHistory(active)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	a, _, diag := exportTestApp(nil)
	_, _, err = runHistoryExport(t, a)
	if err == nil || !strings.Contains(err.Error(), "no terminal local history records") {
		t.Fatalf("active-only export err=%v", err)
	}
	if !strings.Contains(diag.String(), "skipping non-terminal") {
		t.Fatalf("skip warning=%q", diag.String())
	}

	// Explicitly selecting the active id still refuses instead of exporting it.
	b, _, _ := exportTestApp(nil)
	_, _, err = runHistoryExport(t, b, active.ID)
	if err == nil || !strings.Contains(err.Error(), "no terminal local history records") {
		t.Fatalf("active explicit export err=%v", err)
	}
}

func TestLocalHistoryExportRefusesSecrets(t *testing.T) {
	setExportTestHome(t)
	for i, secret := range []string{
		"Cookie: sessionid=abc123xyz\n",
		"MY_PROVIDER_TOKEN=ghp_deadbeefdeadbeef echo hi\n",
		"https://broker.example/run?ticket=T-9f8e7d6c\n",
	} {
		exportTerminalRecord(t, 10+i, secret, nil, nil)
		a, _, _ := exportTestApp(nil)
		path := filepath.Join(t.TempDir(), "out.tar.gz")
		_, _, err := runHistoryExport(t, a, "--output", path, "--json")
		if err == nil || !strings.Contains(err.Error(), "refusing to export") {
			t.Fatalf("secret %q exported: %v", secret, err)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("archive was created despite refusal: %v", statErr)
		}
	}
}

func TestLocalHistoryImportDuplicateAndForce(t *testing.T) {
	setExportTestHome(t)
	record := exportTerminalRecord(t, 1, "same bytes\n", &TestResultSummary{Format: "junit", Tests: 1}, nil)
	a, _, _ := exportTestApp(nil)
	archive := exportToBuffer(t, a)

	setExportTestHome(t)
	b, _, _ := exportTestApp(bytes.NewReader(archive))
	if _, _, err := runHistoryImport(t, b, "-"); err != nil {
		t.Fatal(err)
	}

	// A second import refuses the duplicate by default.
	c, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err := runHistoryImport(t, c, "-")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate import err=%v", err)
	}

	// Force succeeds only as an unchanged no-op because digests match.
	d, out, _ := exportTestApp(bytes.NewReader(archive))
	text, _, err := runHistoryImport(t, d, "--force", "-")
	if err != nil || !strings.Contains(text, "1 unchanged") {
		t.Fatalf("force identical: %v %q", err, text)
	}
	payload, err := loadLocalHistoryPayload(record.ID)
	if err != nil || string(payload.files["log"]) != "same bytes\n" {
		t.Fatalf("record changed after force: %v", err)
	}
	_ = out

	// A divergent terminal record with the same id cannot be force-replaced.
	setExportTestHome(t)
	divergent := localHistoryTestRecord(1)
	divergent.Phase = "finalizing"
	divergent.ResultsState = "no-results"
	divergent.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	dWriter, err := beginLocalHistory(divergent)
	if err != nil {
		t.Fatal(err)
	}
	divergent.RecordingState = "terminal"
	code := 1
	divergent.ExitCode = &code
	divergent.EndedAt = divergent.StartedAt
	if err := dWriter.Commit(divergent, runLogSnapshot{Log: "different bytes\n"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dWriter.Close(); err != nil {
		t.Fatal(err)
	}
	e, _, _ := exportTestApp(nil)
	divergentArchive := exportToBuffer(t, e)

	// Back into the home that already holds the original record.
	setExportTestHome(t)
	// Recreate the original home content by importing the original archive first.
	f, _, _ := exportTestApp(bytes.NewReader(archive))
	if _, _, err := runHistoryImport(t, f, "-"); err != nil {
		t.Fatal(err)
	}
	g, _, _ := exportTestApp(bytes.NewReader(divergentArchive))
	_, _, err = runHistoryImport(t, g, "--force", "-")
	if err == nil || !strings.Contains(err.Error(), "different payload digests") {
		t.Fatalf("divergent force err=%v", err)
	}
}

func TestLocalHistoryImportForceRejectsActiveExisting(t *testing.T) {
	setExportTestHome(t)
	record := exportTerminalRecord(t, 3, "archived\n", nil, nil)
	a, _, _ := exportTestApp(nil)
	archive := exportToBuffer(t, a)

	setExportTestHome(t)
	active := localHistoryTestRecord(3)
	active.LeaseID = ""
	writer, err := beginLocalHistory(active)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if record.ID != active.ID {
		t.Fatal("test ids must collide")
	}
	b, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, b, "--force", "-")
	if err == nil || !strings.Contains(err.Error(), "cannot force replace") {
		t.Fatalf("active force err=%v", err)
	}
}

func exportToBuffer(t *testing.T, a App) []byte {
	t.Helper()
	var buf bytes.Buffer
	saved := a.Stdout
	a.Stdout = &buf
	if err := a.history(context.Background(), []string{"export"}); err != nil {
		t.Fatal(err)
	}
	a.Stdout = saved
	return buf.Bytes()
}

func TestLocalHistoryImportCorruptArchive(t *testing.T) {
	setExportTestHome(t)
	exportTerminalRecord(t, 1, "data\n", nil, nil)
	a, _, _ := exportTestApp(nil)
	archive := exportToBuffer(t, a)

	corrupt := append([]byte(nil), archive...)
	corrupt[len(corrupt)/2] ^= 0xff
	b, _, _ := exportTestApp(bytes.NewReader(corrupt))
	_, _, err := runHistoryImport(t, b, "-")
	if err == nil || !strings.Contains(err.Error(), "import failed") {
		t.Fatalf("corrupt archive err=%v", err)
	}

	// Truncated archives fail too.
	c, _, _ := exportTestApp(bytes.NewReader(archive[:len(archive)-40]))
	_, _, err = runHistoryImport(t, c, "-")
	if err == nil {
		t.Fatal("truncated archive accepted")
	}
}

type customArchiveMember struct {
	name string
	data []byte
	mode int64
}

func buildCustomArchive(t *testing.T, manifest historyExportManifest, members []customArchiveMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte, mode int64) {
		header := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data)), ModTime: time.Now().UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write(historyExportManifestName, manifestData, 0o600)
	for _, member := range members {
		write(member.name, member.data, member.mode)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func manifestFromPayload(t *testing.T, payload *localHistoryPayload) historyExportManifest {
	t.Helper()
	manifest, err := buildHistoryExportManifest([]*localHistoryPayload{payload}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func membersFromPayload(t *testing.T, payload *localHistoryPayload, overrides map[string][]byte) []customArchiveMember {
	t.Helper()
	members := []customArchiveMember{}
	for _, entry := range historyExportRoles {
		data, ok := payload.files[entry.role]
		if !ok {
			if entry.role == "results" {
				continue
			}
			data = nil
		}
		if override, ok := overrides[entry.role]; ok {
			data = override
		}
		members = append(members, customArchiveMember{name: historyExportRecordPath(payload.record.ID, entry.name), data: data, mode: 0o600})
	}
	return members
}

func TestLocalHistoryImportPathTraversal(t *testing.T) {
	setExportTestHome(t)
	record := exportTerminalRecord(t, 1, "data\n", nil, nil)
	payload, err := loadLocalHistoryPayload(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestFromPayload(t, payload)
	members := membersFromPayload(t, payload, nil)
	members = append(members, customArchiveMember{name: "runs/" + record.ID + "/../../escape", data: []byte("x"), mode: 0o600})
	archive := buildCustomArchive(t, manifest, members)
	a, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, a, "-")
	if err == nil || !strings.Contains(err.Error(), "unsafe archive member path") {
		t.Fatalf("traversal err=%v", err)
	}

	// Absolute paths are rejected the same way.
	members[len(members)-1].name = "/etc/crabbox-evil"
	archive = buildCustomArchive(t, manifest, members)
	b, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, b, "-")
	if err == nil || !strings.Contains(err.Error(), "unsafe archive member path") {
		t.Fatalf("absolute path err=%v", err)
	}
}

func TestLocalHistoryImportDigestAndManifestRejection(t *testing.T) {
	setExportTestHome(t)
	record := exportTerminalRecord(t, 1, "data\n", nil, nil)
	payload, err := loadLocalHistoryPayload(record.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Digest in manifest does not match the payload bytes.
	badManifest := manifestFromPayload(t, payload)
	for i := range badManifest.Records[0].Files {
		if badManifest.Records[0].Files[i].Role == "log" {
			badManifest.Records[0].Files[i].SHA256 = strings.Repeat("0", 64)
		}
	}
	archive := buildCustomArchive(t, badManifest, membersFromPayload(t, payload, nil))
	a, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, a, "-")
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("digest tampering err=%v", err)
	}

	// Public mode declared in the manifest is rejected.
	modeManifest := manifestFromPayload(t, payload)
	for i := range modeManifest.Records[0].Files {
		modeManifest.Records[0].Files[i].Mode = 0o644
	}
	archive = buildCustomArchive(t, modeManifest, membersFromPayload(t, payload, nil))
	b, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, b, "-")
	if err == nil || !strings.Contains(err.Error(), "owner-private") {
		t.Fatalf("manifest mode err=%v", err)
	}

	// Public tar header mode is rejected even when the manifest says 0600.
	members := membersFromPayload(t, payload, nil)
	for i := range members {
		if members[i].name == historyExportRecordPath(record.ID, "record.json") {
			members[i].mode = 0o644
		}
	}
	archive = buildCustomArchive(t, manifestFromPayload(t, payload), members)
	c, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, c, "-")
	if err == nil || !strings.Contains(err.Error(), "owner-private") {
		t.Fatalf("tar header mode err=%v", err)
	}

	// A required member missing from the archive is rejected.
	incomplete := membersFromPayload(t, payload, nil)
	filtered := incomplete[:0]
	for _, member := range incomplete {
		if member.name != historyExportRecordPath(record.ID, "log.txt") {
			filtered = append(filtered, member)
		}
	}
	archive = buildCustomArchive(t, manifestFromPayload(t, payload), filtered)
	d, _, _ := exportTestApp(bytes.NewReader(archive))
	_, _, err = runHistoryImport(t, d, "-")
	if err == nil || !strings.Contains(err.Error(), "archive missing") {
		t.Fatalf("missing member err=%v", err)
	}
}

func TestLocalHistoryImportRefusesSecrets(t *testing.T) {
	setExportTestHome(t)
	record := exportTerminalRecord(t, 1, "data\n", nil, nil)
	payload, err := loadLocalHistoryPayload(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	taintedLog := []byte("Cookie: sessionid=stolen-token-value\n")
	taintedRecord := payload.record
	taintedRecord.LogSHA256 = localHistoryDigest(taintedLog)
	taintedRecord.LogBytes = len(taintedLog)
	_, canonical, err := localHistoryRecordBytes(taintedRecord)
	if err != nil {
		t.Fatal(err)
	}
	taintedPayload := &localHistoryPayload{record: taintedRecord, files: map[string][]byte{
		"record": canonical,
		"log":    taintedLog,
	}}
	var buf bytes.Buffer
	if err := writeLocalHistoryArchivePayloads(&buf, []*localHistoryPayload{taintedPayload}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	a, _, _ := exportTestApp(bytes.NewReader(buf.Bytes()))
	_, _, err = runHistoryImport(t, a, "-")
	if err == nil || !strings.Contains(err.Error(), "ticket or cookie marker") {
		t.Fatalf("secret import err=%v", err)
	}
}

func TestLocalHistoryArchiveSecretScanner(t *testing.T) {
	for _, clean := range []string{
		"MONKEY=1 ordinary output\n",
		"the ticket queue is empty\n",
		`{"status":"ok","id":"run_1"}` + "\n",
		"hockey=sport jockey=ride\n",
		"ANTHROPIC_BASE_URL=https://api.example.com\n",
	} {
		if hit := localHistoryArchiveSecretHit("log", []byte(clean)); hit != "" {
			t.Fatalf("benign text flagged: %q -> %s", clean, hit)
		}
	}
	for _, secret := range []string{
		"MY_SECRET_TOKEN=abcdef123456\n",
		"ANTHROPIC_API_KEY=sk-ant-x\n",
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n",
		"Set-Cookie: sid=abc; HttpOnly\n",
		"ticket: T-1234\n",
		`{"token":"abc"}` + "\n",
		"Authorization: Bearer abcdef\n",
	} {
		if hit := localHistoryArchiveSecretHit("log", []byte(secret)); hit == "" {
			t.Fatalf("secret not flagged: %q", secret)
		}
	}
}

func TestLocalHistoryImportSourceLocalOnly(t *testing.T) {
	a, _, _ := exportTestApp(nil)
	if _, _, err := runHistoryExport(t, a, "--source", "coordinator"); err == nil {
		t.Fatal("coordinator export accepted")
	}
	b, _, _ := exportTestApp(nil)
	if _, _, err := runHistoryImport(t, b, "x.tar.gz", "--source", "all"); err == nil {
		t.Fatal("all import accepted")
	}
	c, _, _ := exportTestApp(nil)
	if _, _, err := runHistoryImport(t, c); err == nil {
		t.Fatal("import without archive path accepted")
	}
}
