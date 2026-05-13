// Package bundle handles unpacking an iOS IPA archive and indexing
// its contents (main app binary, frameworks, plists, resources).
package bundle

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	plist "github.com/blacktop/go-plist"
)

// Bundle is one parsed IPA, mounted on a temp directory.
// Callers must invoke Close to remove the temp directory.
type Bundle struct {
	IPAPath string
	TmpRoot string // root of the extracted ZIP (parent of Payload/)
	AppDir  string // <TmpRoot>/Payload/<App>.app

	Info    map[string]any // decoded Info.plist
	ExeName string         // CFBundleExecutable
	ExePath string         // <AppDir>/<ExeName>

	BundleID   string // CFBundleIdentifier
	BundleName string // CFBundleName (display name)
	Version    string // CFBundleShortVersionString
	Build      string // CFBundleVersion

	// Frameworks holds bundle-relative paths to every non-main Mach-O found
	// anywhere inside the bundle (frameworks, plugin executables, nested
	// frameworks inside plugins, watchOS companion binaries, loose dylibs,
	// XPC services, etc.). The main executable is not included here.
	// The name is historical; "binaries" would be more accurate.
	Frameworks []string

	// Files indexes every regular file in the bundle by bundle-relative path.
	Files map[string]FileMeta

	// MainEncrypted is true when the main app binary has FairPlay encryption.
	// Encrypted frameworks are flagged per-entry in Files[rel].Encrypted.
	MainEncrypted bool
}

// Load extracts ipa into a fresh temp directory, parses Info.plist,
// classifies every file, and detects FairPlay encryption.
// Callers MUST defer b.Close() to remove the temp directory.
func Load(ipa string) (*Bundle, error) {
	if _, err := os.Stat(ipa); err != nil {
		return nil, fmt.Errorf("ipa not found: %w", err)
	}

	tmp, err := os.MkdirTemp("", "ipadiff-*")
	if err != nil {
		return nil, fmt.Errorf("mkdtemp: %w", err)
	}

	b := &Bundle{
		IPAPath: ipa,
		TmpRoot: tmp,
		Files:   make(map[string]FileMeta),
	}

	log.WithField("ipa", filepath.Base(ipa)).Info("unzipping")
	t := time.Now()
	if err := extractZip(ipa, tmp); err != nil {
		b.Close()
		return nil, err
	}
	log.WithField("took", time.Since(t).Truncate(time.Millisecond)).Debug("unzip done")

	appDir, err := findAppDir(tmp)
	if err != nil {
		b.Close()
		return nil, err
	}
	b.AppDir = appDir

	if err := b.parseInfoPlist(); err != nil {
		b.Close()
		return nil, fmt.Errorf("parse Info.plist: %w", err)
	}

	log.WithField("app", filepath.Base(appDir)).Info("indexing files")
	t = time.Now()
	if err := b.indexFiles(); err != nil {
		b.Close()
		return nil, fmt.Errorf("index files: %w", err)
	}
	log.WithFields(log.Fields{
		"files":      len(b.Files),
		"frameworks": len(b.Frameworks),
		"took":       time.Since(t).Truncate(time.Millisecond),
	}).Info("indexed")

	return b, nil
}

// Close removes the temporary extraction directory. Safe to call multiple
// times. Always safe even if Load failed mid-way.
func (b *Bundle) Close() error {
	if b == nil || b.TmpRoot == "" {
		return nil
	}
	err := os.RemoveAll(b.TmpRoot)
	b.TmpRoot = ""
	return err
}

func (b *Bundle) parseInfoPlist() error {
	infoPath := filepath.Join(b.AppDir, "Info.plist")
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return err
	}
	var info map[string]any
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("plist unmarshal: %w", err)
	}
	b.Info = info
	if v, ok := info["CFBundleExecutable"].(string); ok {
		b.ExeName = v
	}
	if v, ok := info["CFBundleIdentifier"].(string); ok {
		b.BundleID = v
	}
	if v, ok := info["CFBundleName"].(string); ok {
		b.BundleName = v
	}
	if b.BundleName == "" {
		if v, ok := info["CFBundleDisplayName"].(string); ok {
			b.BundleName = v
		}
	}
	if v, ok := info["CFBundleShortVersionString"].(string); ok {
		b.Version = v
	}
	if v, ok := info["CFBundleVersion"].(string); ok {
		b.Build = v
	}

	if b.ExeName == "" {
		// Fallback: largest Mach-O directly under AppDir.
		largest, err := b.largestMachoInRoot()
		if err != nil {
			return fmt.Errorf("CFBundleExecutable missing and no Mach-O fallback found: %w", err)
		}
		b.ExeName = largest
	}
	b.ExePath = filepath.Join(b.AppDir, b.ExeName)
	return nil
}

func (b *Bundle) largestMachoInRoot() (string, error) {
	entries, err := os.ReadDir(b.AppDir)
	if err != nil {
		return "", err
	}
	var bestName string
	var bestSize int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(b.AppDir, e.Name())
		head, err := readHead(full, 4)
		if err != nil || !machoMagic(head) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Size() > bestSize {
			bestSize = fi.Size()
			bestName = e.Name()
		}
	}
	if bestName == "" {
		return "", fmt.Errorf("no Mach-O at bundle root")
	}
	return bestName, nil
}

func (b *Bundle) indexFiles() error {
	return filepath.WalkDir(b.AppDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip _CodeSignature/ entirely — it's pure signing metadata
		// (CodeResources, CodeDirectory, CodeRequirements) that doesn't
		// describe the app itself and just adds noise.
		if d.IsDir() {
			if d.Name() == "_CodeSignature" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(b.AppDir, p)
		if relErr != nil {
			return nil
		}
		fi, fiErr := d.Info()
		if fiErr != nil {
			return nil
		}

		head, _ := readHead(p, 512)
		kind := Classify(rel, head)

		meta := FileMeta{
			RelPath: rel,
			Kind:    kind,
			Size:    fi.Size(),
		}

		if kind == KindMacho {
			// Probe encryption. Every non-main Mach-O — wherever it lives in
			// the bundle (Frameworks/, PlugIns/, Watch/, XPCServices/,
			// loose dylibs at root, nested .framework/.appex Mach-Os) — is
			// added to b.Frameworks so the Mach-O diff section sees it.
			if rel == b.ExeName {
				if enc, _ := isFairPlayEncrypted(p); enc {
					b.MainEncrypted = true
					meta.Encrypted = true
				}
			} else {
				b.Frameworks = append(b.Frameworks, rel)
				if enc, _ := isFairPlayEncrypted(p); enc {
					meta.Encrypted = true
				}
			}
		}

		b.Files[rel] = meta
		return nil
	})
}

// readHead returns up to n bytes from the start of path.
func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return buf[:got], nil
	}
	if err != nil {
		return nil, err
	}
	return buf[:got], nil
}

// isFairPlayEncrypted opens the Mach-O at path and returns true if any
// LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 load command has CryptID != 0.
func isFairPlayEncrypted(path string) (bool, error) {
	m, err := macho.Open(path)
	if err != nil {
		// Fat binaries fall through this open; try OpenFat.
		fat, fatErr := macho.OpenFat(path)
		if fatErr != nil {
			return false, err
		}
		defer fat.Close()
		for _, a := range fat.Arches {
			if encryptedLoad(a.File) {
				return true, nil
			}
		}
		return false, nil
	}
	defer m.Close()
	return encryptedLoad(m), nil
}

func encryptedLoad(m *macho.File) bool {
	for _, l := range m.Loads {
		switch e := l.(type) {
		case *macho.EncryptionInfo:
			if e.CryptID != 0 {
				return true
			}
		case *macho.EncryptionInfo64:
			if e.CryptID != 0 {
				return true
			}
		}
	}
	return false
}
