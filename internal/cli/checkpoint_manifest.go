package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// printCheckpointArchiveReport renders the streaming verification result for
// `crabbox checkpoint inspect --verify`.
func printCheckpointArchiveReport(out io.Writer, report *checkpointArchiveVerification) {
	switch {
	case report.Verified:
		fmt.Fprintf(out, "archive_manifest=present archive_verified=true entries=%d sha256=%s\n",
			report.EntryCount, report.ArchiveSHA256)
	case report.Legacy:
		fmt.Fprintf(out, "archive_manifest=legacy archive_verified=false entries=%d\n", report.EntryCount)
	default:
		fmt.Fprintf(out, "archive_manifest=present archive_verified=false entries=%d expected_entries=%d repair=%s sha256=%s\n",
			report.EntryCount, report.ExpectedCount, blank(report.Repair, "-"), blank(report.ArchiveSHA256, "-"))
	}
	for _, damage := range report.Damages {
		target := damage.Path
		if target == "" {
			target = "-"
		}
		fmt.Fprintf(out, "archive_damage path=%s code=%s repairable=%t\n", target, damage.Code, damage.Repairable)
	}
}

const (
	checkpointManifestFile      = "workspace.manifest.json"
	checkpointManifestSchemaV1  = 1
	checkpointManifestEntryFile = "file"
	// Directories and symbolic links are optional manifest entries; GNU tar
	// checkpoints always record them so verify can detect their replacement.
	checkpointManifestEntryDir      = "dir"
	checkpointManifestEntrySymlink  = "symlink"
	checkpointManifestEntryHardlink = "hardlink"
	checkpointManifestEntrySpecial  = "special"

	// Damage codes reported by streaming archive verification.
	checkpointDamageArchiveMissing    = "archive_missing"
	checkpointDamageArchiveNotFile    = "archive_not_file"
	checkpointDamageArchiveUnreadable = "archive_unreadable"
	checkpointDamageArchiveSize       = "archive_size_mismatch"
	checkpointDamageArchiveDigest     = "archive_digest_mismatch"
	checkpointDamageManifestCorrupt   = "manifest_corrupt"
	checkpointDamageMissingEntry      = "missing_entry"
	checkpointDamageExtraEntry        = "extra_entry"
	checkpointDamageTypeMismatch      = "type_mismatch"
	checkpointDamageSizeMismatch      = "size_mismatch"
	checkpointDamageModeMismatch      = "mode_mismatch"
	checkpointDamageDigestMismatch    = "digest_mismatch"
	checkpointDamageLinkMismatch      = "link_mismatch"
)

type checkpointArchiveManifest struct {
	SchemaVersion int                             `json:"schemaVersion"`
	CreatedAt     string                          `json:"createdAt"`
	SourceLeaseID string                          `json:"sourceLeaseId,omitempty"`
	Workdir       string                          `json:"workdir,omitempty"`
	Archive       checkpointManifestArchiveDigest `json:"archive"`
	Entries       []checkpointManifestEntry       `json:"entries"`
}

type checkpointManifestArchiveDigest struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type checkpointManifestEntry struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Size     int64  `json:"size,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	Linkname string `json:"linkname,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type checkpointArchiveDamage struct {
	Path       string `json:"path,omitempty"`
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	Repairable bool   `json:"repairable"`
}

type checkpointArchiveVerification struct {
	// Manifest reports whether a valid manifest accompanies the archive.
	Manifest bool `json:"manifest"`
	// Legacy archives predate manifests. They remain readable but their
	// contents cannot be verified against a captured digest.
	Legacy        bool   `json:"legacy"`
	Verified      bool   `json:"verified"`
	ArchiveSize   int64  `json:"archiveSize,omitempty"`
	ArchiveSHA256 string `json:"archiveSha256,omitempty"`
	ExpectedSize  int64  `json:"expectedSize,omitempty"`
	EntryCount    int    `json:"entryCount,omitempty"`
	ExpectedCount int    `json:"expectedCount,omitempty"`
	// Repair describes the cheapest recovery strategy:
	// "rebuild_manifest" (local, no transfer), "refetch_entries"
	// (transfer only damaged entries), or "recreate" (full re-archive).
	Repair  string                    `json:"repair,omitempty"`
	Damages []checkpointArchiveDamage `json:"damages,omitempty"`
}

func (v *checkpointArchiveVerification) damage(code string) bool {
	for _, damage := range v.Damages {
		if damage.Code == code {
			return true
		}
	}
	return false
}

func (v *checkpointArchiveVerification) add(code, entryPath, message string, repairable bool) {
	v.Damages = append(v.Damages, checkpointArchiveDamage{
		Path:       entryPath,
		Code:       code,
		Message:    message,
		Repairable: repairable,
	})
}

func checkpointManifestPathFor(archivePath string) string {
	return filepath.Join(filepath.Dir(archivePath), checkpointManifestFile)
}

// normalizeCheckpointEntryName converts a tar entry name to the slash-separated
// relative path stored in the manifest. The archive root ("./" produced by
// `tar -C workdir -czf - .`) maps to the empty root path.
func normalizeCheckpointEntryName(name string) (rel string, root bool, err error) {
	return normalizeCheckpointEntryNameForGOOS(runtime.GOOS, name)
}

func normalizeCheckpointEntryNameForGOOS(goos, name string) (rel string, root bool, err error) {
	if goos == "windows" && strings.Contains(name, `\`) {
		return "", false, fmt.Errorf("archive entry contains a backslash: %q", name)
	}
	slashed := filepath.ToSlash(name)
	if strings.ContainsRune(slashed, 0) || path.IsAbs(slashed) {
		return "", false, fmt.Errorf("unsafe archive entry path: %q", name)
	}
	if slashed == "." || slashed == "./" {
		return "", true, nil
	}
	// GNU tar prefixes every entry with "./"; nothing else may use redundant
	// or escaping path components.
	stripped := strings.TrimPrefix(slashed, "./")
	if stripped == slashed && strings.HasPrefix(slashed, ".") && (strings.HasPrefix(slashed, "../") || slashed == "..") {
		return "", false, fmt.Errorf("unsafe archive entry path: %q", name)
	}
	clean := path.Clean(stripped)
	if clean != stripped || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, fmt.Errorf("unsafe archive entry path: %q", name)
	}
	if goos == "windows" && !validWindowsCheckpointManifestPath(clean) {
		return "", false, fmt.Errorf("unsafe Windows archive entry path: %q", name)
	}
	return clean, false, nil
}

func validWindowsCheckpointManifestPath(rel string) bool {
	for _, component := range strings.Split(rel, "/") {
		if strings.Contains(component, ":") || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return false
		}
		base := component
		if index := strings.IndexByte(base, '.'); index >= 0 {
			base = base[:index]
		}
		base = strings.ToUpper(base)
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return false
		}
	}
	return true
}

// validateCheckpointManifestLinkname performs structural checks on a recorded
// symlink target. Relative targets are allowed to escape the workdir because
// GNU tar preserves them as links; the manifest never resolves them.
func validateCheckpointManifestLinkname(goos, name string) error {
	trimmed := filepath.ToSlash(name)
	if strings.ContainsRune(trimmed, 0) {
		return fmt.Errorf("unsafe archive link target: %q", name)
	}
	if goos == "windows" && strings.Contains(trimmed, `\`) {
		return fmt.Errorf("archive link target contains a backslash: %q", name)
	}
	return nil
}

type digestCountReader struct {
	reader io.Reader
	hash   hash.Hash
	size   int64
}

func (d *digestCountReader) Read(p []byte) (int, error) {
	n, err := d.reader.Read(p)
	if n > 0 {
		d.hash.Write(p[:n])
		d.size += int64(n)
	}
	return n, err
}

// scanCheckpointArchive replays a gzip-compressed tar stream once, computing
// the compressed-archive digest and per-file content digests. Entries scanned
// before a truncation error are returned alongside the error so callers can
// salvage the intact prefix.
func scanCheckpointArchive(reader io.Reader) (archiveDigest string, size int64, entries []checkpointManifestEntry, err error) {
	counter := &digestCountReader{reader: reader, hash: sha256.New()}
	gz, err := gzip.NewReader(counter)
	if err != nil {
		return "", 0, nil, fmt.Errorf("read checkpoint archive gzip stream: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		header, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			err = fmt.Errorf("read checkpoint archive tar stream: %w", nextErr)
			break
		}
		entry, entryErr := checkpointEntryFromTarHeader(header)
		if entryErr != nil {
			err = entryErr
			break
		}
		if entry.Path == "" {
			// The archive root ("./") carries no manifest payload.
			continue
		}
		if entry.Type == checkpointManifestEntryFile {
			digest := sha256.New()
			copied, copyErr := io.Copy(digest, tr)
			if copyErr != nil {
				err = fmt.Errorf("read checkpoint archive entry %s: %w", entry.Path, copyErr)
				break
			}
			if copied != header.Size {
				err = fmt.Errorf("checkpoint archive entry %s is truncated: read %d of %d bytes", entry.Path, copied, header.Size)
				break
			}
			entry.SHA256 = hex.EncodeToString(digest.Sum(nil))
		}
		entries = append(entries, entry)
	}
	closeErr := gz.Close()
	if err == nil && closeErr != nil {
		err = fmt.Errorf("verify checkpoint archive gzip trailer: %w", closeErr)
	}
	return hex.EncodeToString(counter.hash.Sum(nil)[:]), counter.size, entries, err
}

func checkpointEntryFromTarHeader(header *tar.Header) (checkpointManifestEntry, error) {
	rel, root, err := normalizeCheckpointEntryName(header.Name)
	if err != nil {
		return checkpointManifestEntry{}, err
	}
	if root {
		return checkpointManifestEntry{Path: ""}, nil
	}
	entry := checkpointManifestEntry{Path: rel, Mode: uint32(header.Mode)}
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		entry.Type = checkpointManifestEntryFile
		if header.Size < 0 {
			return checkpointManifestEntry{}, fmt.Errorf("checkpoint archive entry %s has negative size", rel)
		}
		entry.Size = header.Size
	case tar.TypeDir:
		entry.Type = checkpointManifestEntryDir
	case tar.TypeSymlink:
		entry.Type = checkpointManifestEntrySymlink
		entry.Linkname = filepath.ToSlash(header.Linkname)
		if err := validateCheckpointManifestLinkname(runtime.GOOS, entry.Linkname); err != nil {
			return checkpointManifestEntry{}, fmt.Errorf("checkpoint archive entry %s: %w", rel, err)
		}
	case tar.TypeLink:
		entry.Type = checkpointManifestEntryHardlink
		linkname, _, linkErr := normalizeCheckpointEntryName(header.Linkname)
		if linkErr != nil {
			return checkpointManifestEntry{}, fmt.Errorf("checkpoint archive hardlink %s: %w", rel, linkErr)
		}
		entry.Linkname = linkname
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		entry.Type = checkpointManifestEntrySpecial
	default:
		return checkpointManifestEntry{}, fmt.Errorf("checkpoint archive contains unsupported entry %q of type %d", rel, header.Typeflag)
	}
	return entry, nil
}

func newCheckpointArchiveManifest(archiveName string, size int64, archiveDigest, leaseID, workdir, createdAt string, entries []checkpointManifestEntry) *checkpointArchiveManifest {
	copied := make([]checkpointManifestEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Path == "" {
			continue
		}
		copied = append(copied, entry)
	}
	return &checkpointArchiveManifest{
		SchemaVersion: checkpointManifestSchemaV1,
		CreatedAt:     createdAt,
		SourceLeaseID: leaseID,
		Workdir:       workdir,
		Archive: checkpointManifestArchiveDigest{
			Name:   archiveName,
			Size:   size,
			SHA256: archiveDigest,
		},
		Entries: copied,
	}
}

func (m *checkpointArchiveManifest) validate() error {
	if m.SchemaVersion != checkpointManifestSchemaV1 {
		return fmt.Errorf("unsupported checkpoint manifest schema version %d", m.SchemaVersion)
	}
	if m.CreatedAt == "" {
		return errors.New("checkpoint manifest is missing createdAt")
	}
	if m.Archive.Name != checkpointArchive {
		return fmt.Errorf("checkpoint manifest references %q, want %q", m.Archive.Name, checkpointArchive)
	}
	if m.Archive.Size < 0 {
		return errors.New("checkpoint manifest has negative archive size")
	}
	if decoded, err := hex.DecodeString(m.Archive.SHA256); err != nil || len(decoded) != sha256.Size {
		return errors.New("checkpoint manifest archive sha256 is invalid")
	}
	seen := make(map[string]bool, len(m.Entries))
	for _, entry := range m.Entries {
		if entry.Path == "" {
			return errors.New("checkpoint manifest contains a root entry")
		}
		if seen[entry.Path] {
			return fmt.Errorf("checkpoint manifest lists %q more than once", entry.Path)
		}
		seen[entry.Path] = true
		if _, _, err := normalizeCheckpointEntryName(entry.Path); err != nil {
			return fmt.Errorf("checkpoint manifest entry %s: %w", entry.Path, err)
		}
		switch entry.Type {
		case checkpointManifestEntryFile:
			if entry.Size < 0 {
				return fmt.Errorf("checkpoint manifest entry %s has negative size", entry.Path)
			}
			if decoded, err := hex.DecodeString(entry.SHA256); err != nil || len(decoded) != sha256.Size {
				return fmt.Errorf("checkpoint manifest entry %s has an invalid sha256", entry.Path)
			}
		case checkpointManifestEntryDir, checkpointManifestEntrySpecial:
		case checkpointManifestEntrySymlink:
			if entry.Linkname == "" {
				return fmt.Errorf("checkpoint manifest symlink %s has no target", entry.Path)
			}
		case checkpointManifestEntryHardlink:
			if entry.Linkname == "" {
				return fmt.Errorf("checkpoint manifest hardlink %s has no target", entry.Path)
			}
		default:
			return fmt.Errorf("checkpoint manifest entry %s has unknown type %q", entry.Path, entry.Type)
		}
	}
	return nil
}

// writeCheckpointManifestAtomic publishes the manifest next to the archive
// after fsync so readers only ever observe a complete manifest.
func writeCheckpointManifestAtomic(manifestPath string, manifest *checkpointArchiveManifest) (err error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checkpoint manifest: %w", err)
	}
	data = append(data, '\n')
	tmpPath := manifestPath + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create checkpoint manifest: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write checkpoint manifest: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync checkpoint manifest: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close checkpoint manifest: %w", err)
	}
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		return fmt.Errorf("publish checkpoint manifest: %w", err)
	}
	keep = true
	return syncControllerDirectory(filepath.Dir(manifestPath))
}

// publishCheckpointArchiveWithManifest renames the fully synced archive into
// place before publishing its manifest: a visible manifest therefore always
// implies the archive is present.
func publishCheckpointArchiveWithManifest(archiveTmp, archivePath string, manifest *checkpointArchiveManifest, manifestPath string) error {
	info, err := os.Stat(archiveTmp)
	if err != nil {
		return fmt.Errorf("stat finished checkpoint archive: %w", err)
	}
	if info.Size() == 0 {
		return errors.New("checkpoint archive is empty")
	}
	if err := os.Rename(archiveTmp, archivePath); err != nil {
		return fmt.Errorf("publish checkpoint archive: %w", err)
	}
	if err := syncControllerDirectory(filepath.Dir(archivePath)); err != nil {
		return err
	}
	if err := writeCheckpointManifestAtomic(manifestPath, manifest); err != nil {
		return err
	}
	return syncControllerDirectory(filepath.Dir(archivePath))
}

func loadCheckpointArchiveManifest(manifestPath string) (*checkpointArchiveManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest checkpointArchiveManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse checkpoint manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// verifyLocalCheckpointArchive streams the archive once and replays it against
// the manifest. All damage is reported; a partial scan still yields salvage
// information for incremental repair.
func verifyLocalCheckpointArchive(archivePath, manifestPath string) *checkpointArchiveVerification {
	report := &checkpointArchiveVerification{}
	info, err := os.Stat(archivePath)
	if err != nil {
		if os.IsNotExist(err) {
			report.add(checkpointDamageArchiveMissing, "", "archive file does not exist", false)
			report.Repair = "recreate"
			return report
		}
		report.add(checkpointDamageArchiveUnreadable, "", err.Error(), false)
		report.Repair = "recreate"
		return report
	}
	if info.IsDir() {
		report.add(checkpointDamageArchiveNotFile, "", "archive path is a directory", false)
		report.Repair = "delete_or_recreate"
		return report
	}

	manifest, manifestErr := loadCheckpointArchiveManifest(manifestPath)
	if manifestErr != nil {
		if os.IsNotExist(manifestErr) {
			report.Legacy = true
		} else {
			report.add(checkpointDamageManifestCorrupt, "", manifestErr.Error(), true)
		}
	} else {
		report.Manifest = true
		report.ExpectedSize = manifest.Archive.Size
		report.ExpectedCount = len(manifest.Entries)
		if info.Size() != manifest.Archive.Size {
			report.add(checkpointDamageArchiveSize, "",
				fmt.Sprintf("archive is %d bytes; manifest records %d", info.Size(), manifest.Archive.Size), true)
		}
	}

	digest, size, actual, scanErr := scanCheckpointArchiveFile(archivePath)
	report.ArchiveSize = size
	report.ArchiveSHA256 = digest
	report.EntryCount = len(actual)
	if scanErr != nil {
		report.add(checkpointDamageArchiveUnreadable, "", scanErr.Error(), report.Manifest)
	}

	if report.Legacy {
		// Legacy checkpoints keep their current read behavior; verify only
		// flags that their contents were never certified.
		if scanErr != nil {
			report.Repair = "recreate"
		} else {
			report.Repair = "rebuild_manifest"
		}
		return report
	}
	if !report.Manifest {
		if scanErr != nil {
			report.Repair = "recreate"
		} else {
			report.Repair = "rebuild_manifest"
		}
		return report
	}

	if digest != manifest.Archive.SHA256 {
		report.add(checkpointDamageArchiveDigest, "",
			fmt.Sprintf("archive sha256 %s does not match manifest %s", digest, manifest.Archive.SHA256), true)
	}

	actualByPath := make(map[string]checkpointManifestEntry, len(actual))
	for _, entry := range actual {
		if entry.Path == "" {
			continue
		}
		actualByPath[entry.Path] = entry
	}
	expectedByPath := make(map[string]checkpointManifestEntry, len(manifest.Entries))
	for _, expected := range manifest.Entries {
		expectedByPath[expected.Path] = expected
		got, ok := actualByPath[expected.Path]
		if !ok {
			report.add(checkpointDamageMissingEntry, expected.Path, "entry is absent from the archive", true)
			continue
		}
		compareCheckpointManifestEntry(expected, got, report)
	}
	for path := range actualByPath {
		if _, ok := expectedByPath[path]; !ok {
			report.add(checkpointDamageExtraEntry, path, "entry is present in the archive but absent from the manifest", true)
		}
	}
	sortCheckpointDamages(report.Damages)

	if len(report.Damages) == 0 {
		report.Verified = true
		report.Repair = ""
	} else {
		report.Repair = "refetch_entries"
	}
	return report
}

func compareCheckpointManifestEntry(expected, got checkpointManifestEntry, report *checkpointArchiveVerification) {
	if expected.Type != got.Type {
		report.add(checkpointDamageTypeMismatch, expected.Path,
			fmt.Sprintf("entry is %s; manifest records %s", got.Type, expected.Type), true)
		return
	}
	switch expected.Type {
	case checkpointManifestEntryFile:
		if got.Size != expected.Size {
			report.add(checkpointDamageSizeMismatch, expected.Path,
				fmt.Sprintf("file is %d bytes; manifest records %d", got.Size, expected.Size), true)
		}
		if got.SHA256 != expected.SHA256 {
			report.add(checkpointDamageDigestMismatch, expected.Path,
				fmt.Sprintf("file sha256 %s does not match manifest %s", got.SHA256, expected.SHA256), true)
		}
		if got.Mode&0o7777 != expected.Mode&0o7777 {
			report.add(checkpointDamageModeMismatch, expected.Path,
				fmt.Sprintf("file mode %04o does not match manifest %04o", got.Mode&0o7777, expected.Mode&0o7777), true)
		}
	case checkpointManifestEntryDir, checkpointManifestEntrySpecial:
		if got.Mode&0o7777 != expected.Mode&0o7777 {
			report.add(checkpointDamageModeMismatch, expected.Path,
				fmt.Sprintf("%s mode %04o does not match manifest %04o", expected.Type, got.Mode&0o7777, expected.Mode&0o7777), true)
		}
	case checkpointManifestEntrySymlink, checkpointManifestEntryHardlink:
		if got.Linkname != expected.Linkname {
			report.add(checkpointDamageLinkMismatch, expected.Path,
				fmt.Sprintf("link target %q does not match manifest %q", got.Linkname, expected.Linkname), true)
		}
	}
}

func sortCheckpointDamages(damages []checkpointArchiveDamage) {
	sort.SliceStable(damages, func(i, j int) bool {
		if damages[i].Path == damages[j].Path {
			return damages[i].Code < damages[j].Code
		}
		return damages[i].Path < damages[j].Path
	})
}

func scanCheckpointArchiveFile(path string) (digest string, size int64, entries []checkpointManifestEntry, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, nil, fmt.Errorf("open checkpoint archive: %w", err)
	}
	defer file.Close()
	return scanCheckpointArchive(file)
}

// checkpointRefetchPaths returns manifest entry paths whose on-disk content
// must be transferred again. Archive-level damage alone compacts locally
// without any transfer; extra entries are dropped locally.
func checkpointRefetchPaths(manifest *checkpointArchiveManifest, report *checkpointArchiveVerification) []string {
	damaged := make(map[string]bool)
	for _, damage := range report.Damages {
		if damage.Path == "" || damage.Code == checkpointDamageExtraEntry {
			continue
		}
		damaged[damage.Path] = true
	}
	paths := make([]string, 0, len(damaged))
	for _, entry := range manifest.Entries {
		if damaged[entry.Path] {
			paths = append(paths, entry.Path)
		}
	}
	return paths
}

// checkpointEntryTransfer materializes a single-entry gzip tar stream for one
// manifest entry at destination. Production streams it from the source lease
// with `tar --no-recursion`; tests provide local fixtures.
type checkpointEntryTransfer func(ctx context.Context, entry checkpointManifestEntry, destination string) error

// repairCheckpointArchive rebuilds the archive from every intact prefix entry
// plus freshly transferred replacements for only the damaged entries. A
// per-entry spool directory makes interrupted repairs resumable.
func repairCheckpointArchive(ctx context.Context, archivePath, manifestPath string, manifest *checkpointArchiveManifest, transfer checkpointEntryTransfer) (*checkpointArchiveVerification, error) {
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	report := verifyLocalCheckpointArchive(archivePath, manifestPath)
	if report.Verified {
		return report, nil
	}
	refetch := make(map[string]bool)
	for _, p := range checkpointRefetchPaths(manifest, report) {
		refetch[p] = true
	}

	spoolDir := archivePath + ".repair"
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("create checkpoint repair spool directory: %w", err)
	}
	entries := make(map[string]checkpointManifestEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		entries[entry.Path] = entry
	}
	spoolFor := func(entry checkpointManifestEntry) (string, error) {
		spoolPath := filepath.Join(spoolDir, checkpointSpoolName(entry.Path))
		if validCheckpointEntrySpool(spoolPath, entry) {
			return spoolPath, nil
		}
		if err := transfer(ctx, entry, spoolPath); err != nil {
			return "", err
		}
		if !validCheckpointEntrySpool(spoolPath, entry) {
			_ = os.Remove(spoolPath)
			return "", fmt.Errorf("refetched checkpoint entry %s failed verification", entry.Path)
		}
		return spoolPath, nil
	}

	rebuiltPath := archivePath + ".rebuild.tmp"
	output, err := os.OpenFile(rebuiltPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create rebuilt checkpoint archive: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(rebuiltPath)
		}
	}()
	gz := gzip.NewWriter(output)
	tw := tar.NewWriter(gz)

	copied := make(map[string]bool)
	salvageErr := copySalvageableCheckpointEntries(ctx, archivePath, tw, entries, refetch, copied)
	if salvageErr != nil {
		_ = tw.Close()
		_ = gz.Close()
		_ = output.Close()
		return nil, salvageErr
	}

	// Append replaced entries in manifest order so directory entries precede
	// their replacement children when possible.
	for _, entry := range manifest.Entries {
		if !refetch[entry.Path] {
			continue
		}
		spoolPath, err := spoolFor(entry)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = output.Close()
			return nil, err
		}
		if err := copyCheckpointSpoolEntry(tw, spoolPath, entry); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = output.Close()
			return nil, err
		}
		copied[entry.Path] = true
	}
	for _, entry := range manifest.Entries {
		if !copied[entry.Path] {
			_ = tw.Close()
			_ = gz.Close()
			_ = output.Close()
			return nil, fmt.Errorf("checkpoint repair could not reconstruct entry %s", entry.Path)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = output.Close()
		return nil, fmt.Errorf("finish rebuilt checkpoint archive tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = output.Close()
		return nil, fmt.Errorf("finish rebuilt checkpoint archive gzip: %w", err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return nil, fmt.Errorf("sync rebuilt checkpoint archive: %w", err)
	}
	if err := output.Close(); err != nil {
		return nil, fmt.Errorf("close rebuilt checkpoint archive: %w", err)
	}

	digest, size, rebuiltEntries, err := scanCheckpointArchiveFile(rebuiltPath)
	if err != nil {
		return nil, fmt.Errorf("verify rebuilt checkpoint archive: %w", err)
	}
	if err := assertCheckpointEntriesMatch(manifest, rebuiltEntries); err != nil {
		return nil, err
	}
	repairedManifest := newCheckpointArchiveManifest(checkpointArchive, size, digest,
		manifest.SourceLeaseID, manifest.Workdir, manifest.CreatedAt, rebuiltEntries)
	if err := publishCheckpointArchiveWithManifest(rebuiltPath, archivePath, repairedManifest, manifestPath); err != nil {
		return nil, err
	}
	keep = true
	if err := os.RemoveAll(spoolDir); err != nil {
		return nil, fmt.Errorf("remove checkpoint repair spool directory: %w", err)
	}
	return verifyLocalCheckpointArchive(archivePath, manifestPath), nil
}

func checkpointSpoolName(rel string) string {
	digest := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(digest[:16]) + ".tgz"
}

// copySalvageableCheckpointEntries streams the damaged archive prefix into the
// rebuilt writer, copying tar headers verbatim. Damaged and unexpected entries
// are skipped; only manifest-known entries survive.
func copySalvageableCheckpointEntries(ctx context.Context, archivePath string, tw *tar.Writer, expected map[string]checkpointManifestEntry, refetch map[string]bool, copied map[string]bool) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open checkpoint archive for repair: %w", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		// Nothing salvageable; every manifest entry is already in refetch or
		// would be reported missing by the pre-repair verification.
		return nil
	}
	tr := tar.NewReader(gz)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, nextErr := tr.Next()
		if nextErr == io.EOF {
			return nil
		}
		if nextErr != nil {
			// Reaching the damaged region ends salvage; verification already
			// scheduled every later entry for refetch.
			return nil
		}
		rel, root, nameErr := normalizeCheckpointEntryName(header.Name)
		if nameErr != nil {
			return nameErr
		}
		if root {
			if err := tw.WriteHeader(header); err != nil {
				return fmt.Errorf("copy checkpoint archive root header: %w", err)
			}
			continue
		}
		_, expectedEntry := expected[rel]
		if !expectedEntry || refetch[rel] {
			if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
				if _, err := io.Copy(io.Discard, tr); err != nil {
					return nil
				}
			}
			continue
		}
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("copy checkpoint archive header %s: %w", rel, err)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if _, err := io.Copy(tw, tr); err != nil {
				return fmt.Errorf("copy checkpoint archive entry %s: %w", rel, err)
			}
		}
		copied[rel] = true
	}
}

func copyCheckpointSpoolEntry(tw *tar.Writer, spoolPath string, entry checkpointManifestEntry) error {
	file, err := os.Open(spoolPath)
	if err != nil {
		return fmt.Errorf("open refetched checkpoint entry %s: %w", entry.Path, err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("read refetched checkpoint entry %s: %w", entry.Path, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		header, nextErr := tr.Next()
		if nextErr == io.EOF {
			if !found {
				return fmt.Errorf("refetched checkpoint entry %s is absent from its transfer", entry.Path)
			}
			return nil
		}
		if nextErr != nil {
			return fmt.Errorf("read refetched checkpoint entry %s: %w", entry.Path, nextErr)
		}
		rel, root, nameErr := normalizeCheckpointEntryName(header.Name)
		if nameErr != nil || root || rel != entry.Path {
			continue
		}
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write refetched checkpoint entry %s: %w", entry.Path, err)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if _, err := io.Copy(tw, tr); err != nil {
				return fmt.Errorf("copy refetched checkpoint entry %s: %w", entry.Path, err)
			}
		}
		found = true
	}
}

func validCheckpointEntrySpool(spoolPath string, expected checkpointManifestEntry) bool {
	_, _, entries, err := scanCheckpointArchiveFile(spoolPath)
	if err != nil {
		return false
	}
	var found bool
	for _, entry := range entries {
		if entry.Path == "" {
			continue
		}
		if entry.Path != expected.Path {
			return false
		}
		found = true
		report := &checkpointArchiveVerification{}
		compareCheckpointManifestEntry(expected, entry, report)
		if len(report.Damages) != 0 {
			return false
		}
	}
	return found
}

func assertCheckpointEntriesMatch(manifest *checkpointArchiveManifest, actual []checkpointManifestEntry) error {
	report := &checkpointArchiveVerification{}
	actualByPath := make(map[string]checkpointManifestEntry, len(actual))
	for _, entry := range actual {
		if entry.Path == "" {
			continue
		}
		actualByPath[entry.Path] = entry
	}
	expectedByPath := make(map[string]checkpointManifestEntry, len(manifest.Entries))
	for _, expected := range manifest.Entries {
		expectedByPath[expected.Path] = expected
		got, ok := actualByPath[expected.Path]
		if !ok {
			return fmt.Errorf("repaired checkpoint archive is missing %s", expected.Path)
		}
		compareCheckpointManifestEntry(expected, got, report)
	}
	for path := range actualByPath {
		if _, ok := expectedByPath[path]; !ok {
			return fmt.Errorf("repaired checkpoint archive contains unexpected entry %s", path)
		}
	}
	if len(report.Damages) != 0 {
		return fmt.Errorf("repaired checkpoint entry %s: %s", report.Damages[0].Path, report.Damages[0].Code)
	}
	return nil
}

// adoptCheckpointArchiveManifest builds and publishes a manifest for an
// existing manifest-less archive. The digest certifies the archive as it is
// now; it cannot be compared against the original capture.
func adoptCheckpointArchiveManifest(archivePath, manifestPath, archiveName, leaseID, workdir, createdAt string) (*checkpointArchiveVerification, error) {
	digest, size, entries, err := scanCheckpointArchiveFile(archivePath)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint archive for manifest adoption: %w", err)
	}
	manifest := newCheckpointArchiveManifest(archiveName, size, digest, leaseID, workdir, createdAt, entries)
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	if err := writeCheckpointManifestAtomic(manifestPath, manifest); err != nil {
		return nil, err
	}
	return verifyLocalCheckpointArchive(archivePath, manifestPath), nil
}
