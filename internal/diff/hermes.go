package diff

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

func (d *Diff) diffHermes() error {
	oldMap := hermesFiles(d.Old)
	newMap := hermesFiles(d.New)

	hd := &HermesDiff{Updated: make(map[string]*HermesBundleDiff)}
	oldKeys := keysOfBool(oldMap)
	newKeys := keysOfBool(newMap)

	hd.New = vutils.Difference(newKeys, oldKeys)
	hd.Removed = vutils.Difference(oldKeys, newKeys)
	sort.Strings(hd.New)
	sort.Strings(hd.Removed)

	common := intersect(oldKeys, newKeys)
	sort.Strings(common)
	for _, rel := range common {
		same, err := sameFileBytes(filepath.Join(d.Old.AppDir, rel), filepath.Join(d.New.AppDir, rel))
		if err != nil {
			d.addWarning("hermes", rel, err.Error())
			continue
		}
		if same {
			continue
		}
		item := &HermesBundleDiff{Path: rel}
		if err := item.snapshotInputs(d.Old.AppDir, d.New.AppDir); err != nil {
			d.addWarning("hermes", rel, "snapshot failed: "+err.Error())
			item.Warning = "snapshot failed: " + err.Error()
		}
		hd.Updated[rel] = item
	}

	d.Hermes = hd
	return nil
}

func (h *HermesBundleDiff) snapshotInputs(oldRoot, newRoot string) error {
	tmp, err := os.MkdirTemp("", "ipadiff-hermes-*")
	if err != nil {
		return err
	}
	oldPath := filepath.Join(tmp, "old"+filepath.Ext(h.Path))
	newPath := filepath.Join(tmp, "new"+filepath.Ext(h.Path))
	if err := copyFile(filepath.Join(oldRoot, h.Path), oldPath); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("copy old: %w", err)
	}
	if err := copyFile(filepath.Join(newRoot, h.Path), newPath); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("copy new: %w", err)
	}
	h.oldInput = oldPath
	h.newInput = newPath
	return nil
}

func (h *HermesBundleDiff) cleanupInputs() {
	if h.oldInput != "" {
		_ = os.RemoveAll(filepath.Dir(h.oldInput))
	}
	if h.newInput != "" && filepath.Dir(h.newInput) != filepath.Dir(h.oldInput) {
		_ = os.RemoveAll(filepath.Dir(h.newInput))
	}
	h.oldInput = ""
	h.newInput = ""
}

func (d *Diff) cleanupHermesInputs() {
	if d == nil || d.Hermes == nil {
		return
	}
	for _, item := range d.Hermes.Updated {
		item.cleanupInputs()
	}
}

func hermesFiles(b *bundle.Bundle) map[string]bool {
	out := make(map[string]bool)
	for rel, meta := range b.Files {
		if meta.Kind == bundle.KindHermes {
			out[rel] = true
		}
	}
	return out
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sameFileBytes(oldPath, newPath string) (bool, error) {
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		return false, err
	}
	newBytes, err := os.ReadFile(newPath)
	if err != nil {
		return false, err
	}
	return bytes.Equal(oldBytes, newBytes), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
