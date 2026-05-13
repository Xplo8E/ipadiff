package bundle

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// extractZip unpacks src (an .ipa, which is just a ZIP archive) into dest.
// It rejects entries that would escape dest via "../" (zip-slip).
// Symlinks are written as regular files (their literal target string),
// matching how SearchZip in ipsw handles untrusted archives.
func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open ipa: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		target, err := vutils.SanitizeArchivePath(dest, f.Name)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir parent of %s: %w", target, err)
		}

		if err := extractFile(f, target); err != nil {
			return fmt.Errorf("extract %s: %w", f.Name, err)
		}
	}
	return nil
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}

// findAppDir locates the single Payload/<App>.app/ directory inside the
// extracted IPA root. Returns an error if zero or multiple .app dirs exist.
func findAppDir(extractedRoot string) (string, error) {
	payload := filepath.Join(extractedRoot, "Payload")
	entries, err := os.ReadDir(payload)
	if err != nil {
		return "", fmt.Errorf("missing Payload/ directory: %w", err)
	}
	var candidates []string
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
			candidates = append(candidates, filepath.Join(payload, e.Name()))
		}
	}
	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("no *.app directory found under Payload/")
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("expected exactly one *.app under Payload/, found %d", len(candidates))
	}
}
