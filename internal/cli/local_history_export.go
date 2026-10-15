package cli

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	historyExportSchemaVersion = 1
	historyExportManifestLimit = 4 << 20
	historyExportManifestName  = "manifest.json"
	historyExportStagingName   = ".import"
	historyExportPrivateMode   = 0o600
)

type historyExportManifest struct {
	SchemaVersion int                         `json:"schemaVersion"`
	ExportedAt    string                      `json:"exportedAt"`
	Records       []historyExportRecordHeader `json:"records"`
}

type historyExportRecordHeader struct {
	ID             string                    `json:"id"`
	Source         string                    `json:"source"`
	StartedAt      string                    `json:"startedAt"`
	EndedAt        string                    `json:"endedAt,omitempty"`
	RecordingState string                    `json:"recordingState"`
	Files          []historyExportFileHeader `json:"files"`
}

type historyExportFileHeader struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

type historyArchiveSkip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type historyExportReport struct {
	Source      string               `json:"source"`
	Destination string               `json:"destination"`
	Exported    []string             `json:"exported"`
	Skipped     []historyArchiveSkip `json:"skipped,omitempty"`
}

type historyImportReport struct {
	Source    string   `json:"source"`
	Imported  []string `json:"imported"`
	Unchanged []string `json:"unchanged,omitempty"`
}

// historyExportRoles fixes both member order and the on-disk file name per role.
var historyExportRoles = []struct {
	role string
	name string
}{
	{"record", "record.json"},
	{"log", "log.txt"},
	{"results", "results.json"},
	{"lock", "write.lock"},
}

func historyExportRoleName(role string) (string, bool) {
	for _, entry := range historyExportRoles {
		if entry.role == role {
			return entry.name, true
		}
	}
	return "", false
}

func historyExportNameRole(name string) (string, bool) {
	for _, entry := range historyExportRoles {
		if entry.name == name {
			return entry.role, true
		}
	}
	return "", false
}

func historyExportRecordPath(id, name string) string {
	return path.Join("runs", id, name)
}

// A localHistoryPayload carries the exact on-disk bytes of one terminal record.
type localHistoryPayload struct {
	record localHistoryRecord
	files  map[string][]byte
}

func loadLocalHistoryPayload(id string) (*localHistoryPayload, error) {
	if !localHistoryID(id) {
		return nil, fmt.Errorf("invalid local history run ID")
	}
	root, err := localHistoryRoot(false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	held, err := localHistoryLock(root, true, true)
	if err != nil {
		return nil, err
	}
	defer localHistoryUnlock(held)
	runs, err := localHistoryChild(root, "runs")
	if err != nil {
		return nil, err
	}
	defer runs.Close()
	return readLocalHistoryPayloadLocked(runs, id)
}

func readLocalHistoryPayloadLocked(runs *os.Root, id string) (*localHistoryPayload, error) {
	dir, err := localHistoryChild(runs, id)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	lock, lockErr := localHistoryLock(dir, false, false)
	if lockErr != nil && !errors.Is(lockErr, errLocalHistoryBusy) && !errors.Is(lockErr, os.ErrNotExist) {
		return nil, lockErr
	}
	defer localHistoryUnlock(lock)
	recordData, err := localHistoryReadBytes(dir, "record.json", localHistoryMetadataLimit)
	if err != nil {
		return nil, err
	}
	var record localHistoryRecord
	if err := json.Unmarshal(recordData, &record); err != nil {
		return nil, fmt.Errorf("local history metadata invalid: %w", err)
	}
	bounded, canonical, err := localHistoryRecordBytes(record)
	if err != nil {
		return nil, fmt.Errorf("local history metadata invalid: %w", err)
	}
	if !bytes.Equal(recordData, canonical) {
		return nil, fmt.Errorf("local history metadata is not canonical")
	}
	if bounded.RecordingState != "terminal" {
		return nil, fmt.Errorf("local history record %s is %s, not terminal", id, bounded.RecordingState)
	}
	logData, err := localHistoryReadBytes(dir, "log.txt", maxRunLogBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(logData) || localHistoryDigest(logData) != bounded.LogSHA256 || len(logData) != bounded.LogBytes {
		return nil, fmt.Errorf("local history log integrity mismatch")
	}
	files := map[string][]byte{"record": recordData, "log": logData}
	if bounded.ResultsSHA256 != "" {
		resultsData, err := localHistoryReadBytes(dir, "results.json", localHistoryResultsLimit)
		if err != nil {
			return nil, err
		}
		if localHistoryDigest(resultsData) != bounded.ResultsSHA256 {
			return nil, fmt.Errorf("local history results integrity mismatch")
		}
		files["results"] = resultsData
	}
	if info, err := dir.Lstat("write.lock"); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() || info.Size() != 0 {
		return nil, fmt.Errorf("invalid local history lock")
	}
	return &localHistoryPayload{record: bounded, files: files}, nil
}

var (
	// Tickets and cookies are never part of portable run evidence.
	historyExportCookieTicketPattern = regexp.MustCompile(`(?i)(?:^|[?&\s"'{;,:])(?:set-cookie|cookie|ticket)\s*[:=]\s*[^\s"',;}]+`)
	// Environment assignments for credential-bearing names, including inline
	// `FOO_TOKEN=value` command text captured in the log. A bare "KEY" substring
	// would false-positive ordinary words such as MONKEY; require a key boundary.
	historyExportEnvSecretPattern = regexp.MustCompile(`(?m)(?:^|[&\s"'])` +
		`[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|COOKIE|TICKET|KEY_|_KEY)[A-Z0-9_]*=\s*\S`)
)

// localHistoryArchiveSecretHit names the first credential marker found, if any.
func localHistoryArchiveSecretHit(role string, data []byte) string {
	if historyExportCookieTicketPattern.Match(data) {
		return role + " contains a ticket or cookie marker"
	}
	if historyExportEnvSecretPattern.Match(data) {
		return role + " contains an environment secret assignment"
	}
	if RedactDiagnosticSecrets(string(data)) != string(data) {
		return role + " contains an authorization header, token, or private key"
	}
	return ""
}

func buildHistoryExportManifest(payloads []*localHistoryPayload, exportedAt time.Time) (historyExportManifest, error) {
	emptyDigest := localHistoryDigest(nil)
	manifest := historyExportManifest{
		SchemaVersion: historyExportSchemaVersion,
		ExportedAt:    exportedAt.UTC().Format(time.RFC3339Nano),
		Records:       make([]historyExportRecordHeader, 0, len(payloads)),
	}
	for _, payload := range payloads {
		record := payload.record
		files := make([]historyExportFileHeader, 0, 4)
		for _, entry := range historyExportRoles {
			data, ok := payload.files[entry.role]
			if !ok {
				if entry.role == "results" || entry.role == "lock" {
					continue
				}
				return manifest, fmt.Errorf("local history export missing %s for %s", entry.role, record.ID)
			}
			files = append(files, historyExportFileHeader{
				Role:   entry.role,
				Path:   historyExportRecordPath(record.ID, entry.name),
				Size:   int64(len(data)),
				Mode:   historyExportPrivateMode,
				SHA256: localHistoryDigest(data),
			})
		}
		files = append(files, historyExportFileHeader{
			Role: "lock", Path: historyExportRecordPath(record.ID, "write.lock"),
			Size: 0, Mode: historyExportPrivateMode, SHA256: emptyDigest,
		})
		manifest.Records = append(manifest.Records, historyExportRecordHeader{
			ID: record.ID, Source: record.Source, StartedAt: record.StartedAt,
			EndedAt: record.EndedAt, RecordingState: record.RecordingState, Files: files,
		})
	}
	return manifest, nil
}

func writeHistoryTarMember(tw *tar.Writer, name string, data []byte, modTime time.Time) error {
	header := &tar.Header{
		Name:       name,
		Typeflag:   tar.TypeReg,
		Mode:       historyExportPrivateMode,
		Size:       int64(len(data)),
		ModTime:    modTime,
		Format:     tar.FormatUSTAR,
		Uname:      "",
		Gname:      "",
		Devmajor:   0,
		Devminor:   0,
		AccessTime: time.Time{},
		ChangeTime: time.Time{},
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeLocalHistoryArchivePayloads(w io.Writer, payloads []*localHistoryPayload, exportedAt time.Time) error {
	manifest, err := buildHistoryExportManifest(payloads, exportedAt)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeHistoryTarMember(tw, historyExportManifestName, manifestData, exportedAt); err != nil {
		return err
	}
	for _, payload := range payloads {
		modTime := exportedAt
		for _, entry := range historyExportRoles {
			data, ok := payload.files[entry.role]
			if !ok {
				// Results are optional; the empty lock is synthesized below.
				if entry.role == "results" || entry.role == "lock" {
					continue
				}
				return fmt.Errorf("local history export missing %s for %s", entry.role, payload.record.ID)
			}
			if err := writeHistoryTarMember(tw, historyExportRecordPath(payload.record.ID, entry.name), data, modTime); err != nil {
				return err
			}
		}
		if err := writeHistoryTarMember(tw, historyExportRecordPath(payload.record.ID, "write.lock"), nil, modTime); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// historyArchiveMemberClassify validates an archive member name. Relative paths
// are the only accepted shape: manifest.json or runs/<valid-id>/<known-file>.
func historyArchiveMemberClassify(name string) (id, role string, err error) {
	if name == historyExportManifestName {
		return "", "manifest", nil
	}
	clean := path.Clean(filepath.ToSlash(name))
	if clean == "." || clean != filepath.ToSlash(name) || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", "", fmt.Errorf("unsafe archive member path %q", name)
	}
	parts := strings.Split(clean, "/")
	if len(parts) != 3 || parts[0] != "runs" || !localHistoryID(parts[1]) {
		return "", "", fmt.Errorf("unexpected archive member %q", name)
	}
	role, ok := historyExportNameRole(parts[2])
	if !ok {
		return "", "", fmt.Errorf("unexpected archive member %q", name)
	}
	return parts[1], role, nil
}

func historyDigestValid(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateHistoryExportManifest(manifest historyExportManifest) error {
	if manifest.SchemaVersion != historyExportSchemaVersion {
		return fmt.Errorf("unsupported history export schema version %d", manifest.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.ExportedAt); err != nil {
		return fmt.Errorf("invalid export time: %w", err)
	}
	if len(manifest.Records) == 0 {
		return fmt.Errorf("history export manifest contains no records")
	}
	seen := map[string]bool{}
	emptyDigest := localHistoryDigest(nil)
	for _, record := range manifest.Records {
		if !localHistoryID(record.ID) {
			return fmt.Errorf("invalid record id in manifest")
		}
		if seen[record.ID] {
			return fmt.Errorf("duplicate record %s in manifest", record.ID)
		}
		seen[record.ID] = true
		if record.Source != "local" && record.Source != "both" {
			return fmt.Errorf("invalid source for %s", record.ID)
		}
		if record.RecordingState != "terminal" {
			return fmt.Errorf("record %s is not terminal", record.ID)
		}
		if _, err := time.Parse(time.RFC3339Nano, record.StartedAt); err != nil {
			return fmt.Errorf("invalid started time for %s: %w", record.ID, err)
		}
		if record.EndedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, record.EndedAt); err != nil {
				return fmt.Errorf("invalid ended time for %s: %w", record.ID, err)
			}
		}
		roles := map[string]*historyExportFileHeader{}
		for i := range record.Files {
			file := &record.Files[i]
			name, ok := historyExportRoleName(file.Role)
			if !ok {
				return fmt.Errorf("invalid file role %q for %s", file.Role, record.ID)
			}
			if _, exists := roles[file.Role]; exists {
				return fmt.Errorf("duplicate %s file for %s", file.Role, record.ID)
			}
			roles[file.Role] = file
			if file.Path != historyExportRecordPath(record.ID, name) {
				return fmt.Errorf("archive path mismatch for %s %s", record.ID, file.Role)
			}
			if file.Mode != historyExportPrivateMode {
				return fmt.Errorf("archive file %s must stay owner-private (mode 0600)", file.Path)
			}
			if file.Size < 0 || !historyDigestValid(file.SHA256) {
				return fmt.Errorf("invalid size or digest for %s", file.Path)
			}
			maximum := int64(0)
			switch file.Role {
			case "record":
				maximum = localHistoryMetadataLimit
			case "log":
				maximum = maxRunLogBytes
			case "results":
				maximum = localHistoryResultsLimit
			case "lock":
				maximum = 0
				if file.Size != 0 || file.SHA256 != emptyDigest {
					return fmt.Errorf("history lock %s must be empty", file.Path)
				}
			}
			if file.Size > maximum {
				return fmt.Errorf("archive file %s exceeds bound", file.Path)
			}
		}
		for _, required := range []string{"record", "log", "lock"} {
			if roles[required] == nil {
				return fmt.Errorf("manifest for %s missing %s file", record.ID, required)
			}
		}
	}
	return nil
}

type historyArchiveExpectedFile struct {
	id       string
	role     string
	header   historyExportFileHeader
	received bool
}

// importLocalHistoryArchive verifies the manifest, member paths, modes, and
// digests, then commits every record with a single rename per record directory.
// Existing record ids are refused unless force is set, the current record is
// terminal, and every payload digest already matches the archive.
func importLocalHistoryArchive(r io.Reader, force bool) (*historyImportReport, error) {
	root, err := localHistoryRoot(true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	held, err := localHistoryLock(root, true, true)
	if err != nil {
		return nil, err
	}
	defer localHistoryUnlock(held)
	runs, err := localHistoryChild(root, "runs")
	if err != nil {
		return nil, err
	}
	defer runs.Close()

	expected, manifest, err := stageHistoryArchive(runs, r)
	if err != nil {
		_ = runs.RemoveAll(historyExportStagingName)
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = runs.RemoveAll(historyExportStagingName)
		}
	}()

	if err := verifyHistoryArchiveStaging(runs, expected, manifest); err != nil {
		return nil, err
	}

	toImport := make([]string, 0, len(manifest.Records))
	unchanged := []string{}
	for _, record := range manifest.Records {
		if _, err := runs.Lstat(record.ID); errors.Is(err, os.ErrNotExist) {
			toImport = append(toImport, record.ID)
			continue
		} else if err != nil {
			return nil, err
		}
		existing, err := readLocalHistoryPayloadLocked(runs, record.ID)
		if err != nil {
			if !force {
				return nil, fmt.Errorf("local history record %s already exists (use --force to replace identical terminal records)", record.ID)
			}
			return nil, fmt.Errorf("cannot force replace %s: %v", record.ID, err)
		}
		if !force {
			return nil, fmt.Errorf("local history record %s already exists (use --force to replace identical terminal records)", record.ID)
		}
		match, err := historyPayloadMatchesManifest(existing, record)
		if err != nil {
			return nil, fmt.Errorf("cannot force replace %s: %v", record.ID, err)
		}
		if !match {
			return nil, fmt.Errorf("cannot force replace %s: existing terminal record has different payload digests", record.ID)
		}
		unchanged = append(unchanged, record.ID)
	}

	// All conflict checks passed before any final name appears in runs/.
	for _, id := range toImport {
		if err := runs.Rename(filepath.Join(historyExportStagingName, id), id); err != nil {
			return nil, fmt.Errorf("commit imported history %s: %w", id, err)
		}
	}
	if err := localHistorySync(runs); err != nil {
		return nil, err
	}
	if err := runs.RemoveAll(historyExportStagingName); err != nil {
		return nil, err
	}
	committed = true
	if err := localHistorySync(runs); err != nil {
		return nil, err
	}
	sort.Strings(toImport)
	sort.Strings(unchanged)
	return &historyImportReport{Source: "local", Imported: toImport, Unchanged: unchanged}, nil
}

func historyArchiveDecompress(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	prefix, err := br.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if bytes.Equal(prefix, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return gz, nil
	}
	return br, nil
}

func stageHistoryArchive(runs *os.Root, r io.Reader) (map[string]*historyArchiveExpectedFile, historyExportManifest, error) {
	expected := map[string]*historyArchiveExpectedFile{}
	var manifest historyExportManifest
	stream, err := historyArchiveDecompress(r)
	if err != nil {
		return expected, manifest, err
	}
	tr := tar.NewReader(stream)
	header, err := tr.Next()
	if err != nil {
		return expected, manifest, fmt.Errorf("history archive is empty or unreadable: %w", err)
	}
	if header.Typeflag != tar.TypeReg || header.Name != historyExportManifestName {
		return expected, manifest, fmt.Errorf("history archive must begin with %s", historyExportManifestName)
	}
	if header.Mode != historyExportPrivateMode {
		return expected, manifest, fmt.Errorf("archive manifest must stay owner-private (mode 0600)")
	}
	manifestData, err := io.ReadAll(io.LimitReader(tr, historyExportManifestLimit+1))
	if err != nil {
		return expected, manifest, err
	}
	if int64(len(manifestData)) > historyExportManifestLimit {
		return expected, manifest, fmt.Errorf("history export manifest exceeds bound")
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return expected, manifest, fmt.Errorf("invalid history export manifest: %w", err)
	}
	if err := validateHistoryExportManifest(manifest); err != nil {
		return expected, manifest, err
	}
	for i := range manifest.Records {
		record := &manifest.Records[i]
		for j := range record.Files {
			file := &record.Files[j]
			expected[file.Path] = &historyArchiveExpectedFile{id: record.ID, role: file.Role, header: *file}
		}
	}

	// A crashed earlier attempt must never be trusted: rebuild staging privately.
	if err := runs.RemoveAll(historyExportStagingName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return expected, manifest, err
	}
	if _, err := localHistoryCreateDirectory(runs, historyExportStagingName); err != nil {
		return expected, manifest, err
	}
	staging, err := localHistoryChild(runs, historyExportStagingName)
	if err != nil {
		return expected, manifest, err
	}
	defer staging.Close()
	stageDirs := map[string]*os.Root{}
	closeDirs := func() {
		for _, dir := range stageDirs {
			dir.Close()
		}
	}

	memberCount := 0
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			closeDirs()
			return expected, manifest, fmt.Errorf("unreadable history archive member: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			closeDirs()
			return expected, manifest, fmt.Errorf("archive member %q must be a regular file", header.Name)
		}
		if header.Mode != historyExportPrivateMode {
			closeDirs()
			return expected, manifest, fmt.Errorf("archive member %q must stay owner-private (mode 0600)", header.Name)
		}
		id, role, err := historyArchiveMemberClassify(header.Name)
		if err != nil {
			closeDirs()
			return expected, manifest, err
		}
		if role == "manifest" {
			closeDirs()
			return expected, manifest, fmt.Errorf("history archive contains a second manifest")
		}
		entry, ok := expected[header.Name]
		if !ok || entry.received {
			closeDirs()
			return expected, manifest, fmt.Errorf("unexpected or duplicated archive member %q", header.Name)
		}
		if header.Size != entry.header.Size {
			closeDirs()
			return expected, manifest, fmt.Errorf("archive member %q size header mismatch", header.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, entry.header.Size+1))
		if err != nil {
			closeDirs()
			return expected, manifest, err
		}
		if int64(len(data)) != entry.header.Size {
			closeDirs()
			return expected, manifest, fmt.Errorf("archive member %q truncated", header.Name)
		}
		if localHistoryDigest(data) != entry.header.SHA256 {
			closeDirs()
			return expected, manifest, fmt.Errorf("digest mismatch for %s", header.Name)
		}
		if role == "lock" {
			// Locks are machine-local state; materialize a fresh empty private
			// lock instead of trusting bytes from another machine.
			dir, err := historyStageDir(staging, stageDirs, id)
			if err != nil {
				closeDirs()
				return expected, manifest, err
			}
			lock, err := localHistoryLock(dir, true, false)
			if err != nil {
				closeDirs()
				return expected, manifest, err
			}
			if err := localHistoryUnlock(lock); err != nil {
				closeDirs()
				return expected, manifest, err
			}
		} else {
			dir, err := historyStageDir(staging, stageDirs, id)
			if err != nil {
				closeDirs()
				return expected, manifest, err
			}
			name, _ := historyExportRoleName(role)
			if err := localHistoryWrite(dir, name, data); err != nil {
				closeDirs()
				return expected, manifest, err
			}
		}
		entry.received = true
		memberCount++
	}
	closeDirs()
	for path, entry := range expected {
		if !entry.received {
			return expected, manifest, fmt.Errorf("archive missing %s", path)
		}
	}
	if memberCount == 0 {
		return expected, manifest, fmt.Errorf("history archive contains no payload members")
	}
	return expected, manifest, nil
}

func historyStageDir(staging *os.Root, dirs map[string]*os.Root, id string) (*os.Root, error) {
	if dir, ok := dirs[id]; ok {
		return dir, nil
	}
	if _, err := localHistoryCreateDirectory(staging, id); err != nil {
		return nil, err
	}
	dir, err := localHistoryChild(staging, id)
	if err != nil {
		return nil, err
	}
	dirs[id] = dir
	return dir, nil
}

func verifyHistoryArchiveStaging(runs *os.Root, expected map[string]*historyArchiveExpectedFile, manifest historyExportManifest) error {
	staging, err := localHistoryChild(runs, historyExportStagingName)
	if err != nil {
		return err
	}
	defer staging.Close()
	for _, record := range manifest.Records {
		dir, err := localHistoryChild(staging, record.ID)
		if err != nil {
			return err
		}
		recordData, err := localHistoryReadBytes(dir, "record.json", localHistoryMetadataLimit)
		if err != nil {
			dir.Close()
			return err
		}
		var parsed localHistoryRecord
		if err := json.Unmarshal(recordData, &parsed); err != nil {
			dir.Close()
			return fmt.Errorf("invalid record json for %s: %w", record.ID, err)
		}
		bounded, canonical, err := localHistoryRecordBytes(parsed)
		if err != nil {
			dir.Close()
			return fmt.Errorf("invalid record json for %s: %w", record.ID, err)
		}
		if !bytes.Equal(recordData, canonical) {
			dir.Close()
			return fmt.Errorf("non-canonical record json for %s", record.ID)
		}
		if bounded.ID != record.ID || bounded.Source != record.Source || bounded.StartedAt != record.StartedAt ||
			bounded.EndedAt != record.EndedAt || bounded.RecordingState != record.RecordingState {
			dir.Close()
			return fmt.Errorf("manifest metadata mismatch for %s", record.ID)
		}
		logData, err := localHistoryReadBytes(dir, "log.txt", maxRunLogBytes)
		if err != nil {
			dir.Close()
			return err
		}
		if !utf8.Valid(logData) || localHistoryDigest(logData) != bounded.LogSHA256 || len(logData) != bounded.LogBytes {
			dir.Close()
			return fmt.Errorf("log integrity mismatch for %s", record.ID)
		}
		manifestRoles := map[string]bool{}
		for _, file := range record.Files {
			manifestRoles[file.Role] = true
		}
		var resultsData []byte
		if bounded.ResultsSHA256 != "" {
			if !manifestRoles["results"] {
				dir.Close()
				return fmt.Errorf("manifest for %s missing results file", record.ID)
			}
			resultsData, err = localHistoryReadBytes(dir, "results.json", localHistoryResultsLimit)
			if err != nil {
				dir.Close()
				return err
			}
			if localHistoryDigest(resultsData) != bounded.ResultsSHA256 {
				dir.Close()
				return fmt.Errorf("results integrity mismatch for %s", record.ID)
			}
		} else if _, statErr := dir.Lstat("results.json"); !errors.Is(statErr, os.ErrNotExist) {
			dir.Close()
			return fmt.Errorf("unexpected results payload for %s", record.ID)
		}
		for role, data := range map[string][]byte{"record": recordData, "log": logData, "results": resultsData} {
			if len(data) == 0 {
				continue
			}
			if hit := localHistoryArchiveSecretHit(role, data); hit != "" {
				dir.Close()
				return fmt.Errorf("record %s rejected: %s", record.ID, hit)
			}
		}
		info, err := dir.Lstat("write.lock")
		if err != nil {
			dir.Close()
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			dir.Close()
			return fmt.Errorf("invalid staged lock for %s", record.ID)
		}
		dir.Close()
	}
	return nil
}

func historyPayloadMatchesManifest(payload *localHistoryPayload, record historyExportRecordHeader) (bool, error) {
	headers := map[string]historyExportFileHeader{}
	for _, file := range record.Files {
		headers[file.Role] = file
	}
	for _, role := range []string{"record", "log", "results"} {
		data, present := payload.files[role]
		header, listed := headers[role]
		if !present && !listed {
			continue
		}
		if !present || !listed {
			return false, nil
		}
		if localHistoryDigest(data) != header.SHA256 || int64(len(data)) != header.Size {
			return false, nil
		}
	}
	return payload.record.ID == record.ID, nil
}

func sortHistoryPayloads(payloads []*localHistoryPayload) {
	sort.Slice(payloads, func(i, j int) bool { return payloads[i].record.ID < payloads[j].record.ID })
}

func (a App) historyExport(args []string) error {
	fs := newFlagSet("history export", a.Stderr)
	source := fs.String("source", "local", "record source (local only)")
	output := fs.String("output", "", "archive file path (default: standard output)")
	leaseID := fs.String("lease", "", "filter by lease id")
	state := fs.String("state", "", "filter by state")
	limit := fs.Int("limit", 0, "maximum records to export (0: all matched)")
	jsonOut := fs.Bool("json", false, "print JSON summary")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *source != "local" {
		return Exit(2, "history export supports only --source local")
	}
	if *limit < 0 {
		return Exit(2, "limit must be >= 0")
	}
	if *jsonOut && *output == "" {
		return Exit(2, "--json summary requires --output so it cannot corrupt the archive stream")
	}
	requested := map[string]bool{}
	for _, id := range fs.Args() {
		if !localHistoryID(id) {
			return Exit(2, "invalid local history run id %q", id)
		}
		requested[id] = true
	}
	records, err := listLocalHistory(localHistoryFilter{LeaseID: *leaseID, State: *state, Limit: *limit})
	if err != nil {
		return err
	}
	matched := map[string]bool{}
	for _, record := range records {
		matched[record.ID] = true
	}
	for id := range requested {
		if !matched[id] {
			return Exit(1, "no local history record matched %s", terminalSafeResultField(id))
		}
	}
	report := historyExportReport{Source: "local", Exported: []string{}, Skipped: []historyArchiveSkip{}}
	destination := *output
	if destination == "" {
		destination = "-"
	}
	report.Destination = destination
	payloads := []*localHistoryPayload{}
	for _, record := range records {
		if len(requested) > 0 && !requested[record.ID] {
			continue
		}
		if record.RecordingState != "terminal" {
			report.Skipped = append(report.Skipped, historyArchiveSkip{ID: record.ID, Reason: "recordingState=" + record.RecordingState})
			fmt.Fprintf(a.Stderr, "skipping non-terminal local history %s (%s)\n", terminalSafeResultField(record.ID), record.RecordingState)
			continue
		}
		payload, err := loadLocalHistoryPayload(record.ID)
		if err != nil {
			return Exit(1, "cannot export %s: %v", terminalSafeResultField(record.ID), err)
		}
		for _, role := range []string{"record", "log", "results"} {
			if data, ok := payload.files[role]; ok {
				if hit := localHistoryArchiveSecretHit(role, data); hit != "" {
					return Exit(1, "refusing to export %s: %s", terminalSafeResultField(record.ID), hit)
				}
			}
		}
		payloads = append(payloads, payload)
	}
	if len(payloads) == 0 {
		return Exit(1, "no terminal local history records selected for export")
	}
	sortHistoryPayloads(payloads)

	var sink io.Writer = a.Stdout
	var file *os.File
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return Exit(1, "open export archive: %v", err)
		}
		sink = file
	}
	if err := writeLocalHistoryArchivePayloads(sink, payloads, time.Now().UTC()); err != nil {
		if file != nil {
			file.Close()
		}
		return Exit(1, "write export archive: %v", err)
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return err
		}
	}
	for _, payload := range payloads {
		report.Exported = append(report.Exported, payload.record.ID)
	}
	if *jsonOut {
		return json.NewEncoder(a.Stdout).Encode(report)
	}
	target := "standard output"
	if *output != "" {
		target = *output
	}
	fmt.Fprintf(a.Stdout, "exported %d local history record(s) to %s\n", len(report.Exported), target)
	return nil
}

func (a App) historyImport(args []string) error {
	fs := newFlagSet("history import", a.Stderr)
	source := fs.String("source", "local", "record source (local only)")
	force := fs.Bool("force", false, "overwrite an existing record only when it is terminal and payload digests match")
	jsonOut := fs.Bool("json", false, "print JSON summary")
	archivePath, rest := popLeadingRunID(args)
	if err := parseFlags(fs, rest); err != nil {
		return err
	}
	if *source != "local" {
		return Exit(2, "history import supports only --source local")
	}
	positionals := fs.Args()
	if archivePath != "" {
		positionals = append([]string{archivePath}, positionals...)
	}
	if len(positionals) != 1 {
		return Exit(2, "usage: crabbox history import <archive-file|-> [--force] [--source local]")
	}
	path := positionals[0]
	var in io.ReadCloser
	if path == "-" {
		in = io.NopCloser(a.input())
	} else {
		file, err := os.Open(path)
		if err != nil {
			return Exit(1, "open import archive: %v", err)
		}
		in = file
	}
	defer in.Close()
	report, err := importLocalHistoryArchive(in, *force)
	if err != nil {
		return Exit(1, "import failed: %v", err)
	}
	if *jsonOut {
		return json.NewEncoder(a.Stdout).Encode(report)
	}
	fmt.Fprintf(a.Stdout, "imported %d local history record(s)", len(report.Imported))
	if len(report.Unchanged) > 0 {
		fmt.Fprintf(a.Stdout, "; %d unchanged", len(report.Unchanged))
	}
	fmt.Fprintln(a.Stdout)
	return nil
}
