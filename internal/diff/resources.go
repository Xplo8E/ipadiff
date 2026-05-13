package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// diffResources covers everything that's NOT a Mach-O, a plist, or media:
// text files get a unified diff; "other binary" files get a size-only
// delta line. Media files are deliberately ignored at this section
// (file-tree diff still records their additions/removals).
func (d *Diff) diffResources() error {
	if d.cfg.SkipResources {
		return nil
	}
	rd := &ResourcesDiff{
		Updated:  make(map[string]string),
		SizeOnly: make(map[string]string),
	}

	oldFiles := nonMediaResourceKeys(d.Old)
	newFiles := nonMediaResourceKeys(d.New)
	oldSet := toSet(oldFiles)
	newSet := toSet(newFiles)

	for rel := range newSet {
		if _, ok := oldSet[rel]; !ok {
			rd.New = append(rd.New, rel)
		}
	}
	for rel := range oldSet {
		if _, ok := newSet[rel]; !ok {
			rd.Removed = append(rd.Removed, rel)
		}
	}
	sort.Strings(rd.New)
	sort.Strings(rd.Removed)

	for rel := range newSet {
		if _, ok := oldSet[rel]; !ok {
			continue
		}
		oldMeta := d.Old.Files[rel]
		newMeta := d.New.Files[rel]
		switch oldMeta.Kind {
		case bundle.KindText:
			diff := compareText(d.Old.AppDir, d.New.AppDir, rel)
			if diff != "" {
				rd.Updated[rel] = diff
			}
		case bundle.KindBinary, bundle.KindUnknown:
			if oldMeta.Size != newMeta.Size {
				rd.SizeOnly[rel] = fmt.Sprintf("%d -> %d bytes", oldMeta.Size, newMeta.Size)
			}
		}
	}

	d.Resources = rd
	return nil
}

// nonMediaResourceKeys returns every bundle-relative path that is NOT a
// Mach-O and NOT media (we still cover plists separately, but include
// them here too so file-tree-style new/removed catches plist renames).
func nonMediaResourceKeys(b *bundle.Bundle) []string {
	var out []string
	for rel, meta := range b.Files {
		switch meta.Kind {
		case bundle.KindMacho, bundle.KindMedia, bundle.KindPlist:
			continue
		}
		out = append(out, rel)
	}
	return out
}

func toSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, k := range s {
		m[k] = struct{}{}
	}
	return m
}

func compareText(oldRoot, newRoot, rel string) string {
	a, err := os.ReadFile(filepath.Join(oldRoot, rel))
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(newRoot, rel))
	if err != nil {
		return ""
	}
	if string(a) == string(b) {
		return ""
	}
	out, err := vutils.GitDiff(string(a)+"\n", string(b)+"\n", &vutils.GitDiffConfig{Tool: "git"})
	if err != nil || out == "" {
		return ""
	}
	return fmt.Sprintf("```diff\n%s\n```", out)
}
