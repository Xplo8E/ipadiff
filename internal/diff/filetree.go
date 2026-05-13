package diff

import (
	"sort"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// diffFileTree records bundle-wide new/removed paths across ALL kinds
// (including media that we deliberately don't content-diff elsewhere).
// This is the single source of truth for "is this file new in the build".
func (d *Diff) diffFileTree() error {
	oldKeys := allKeys(d.Old)
	newKeys := allKeys(d.New)

	ft := &FileTreeDiff{
		New:     vutils.Difference(newKeys, oldKeys),
		Removed: vutils.Difference(oldKeys, newKeys),
	}
	sort.Strings(ft.New)
	sort.Strings(ft.Removed)

	d.FileTree = ft
	return nil
}

func allKeys(b *bundle.Bundle) []string {
	out := make([]string, 0, len(b.Files))
	for k := range b.Files {
		out = append(out, k)
	}
	return out
}
