package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	"github.com/Xplo8E/ipadiff/internal/parsers"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

func (d *Diff) diffPlists() error {
	oldMap := collectPlists(d.Old)
	newMap := collectPlists(d.New)

	pd := &PlistDiff{Updated: make(map[string]string)}

	oldKeys := keysOf(oldMap)
	newKeys := keysOf(newMap)

	pd.New = vutils.Difference(newKeys, oldKeys)
	pd.Removed = vutils.Difference(oldKeys, newKeys)
	sort.Strings(pd.New)
	sort.Strings(pd.Removed)

	common := intersect(oldKeys, newKeys)
	sort.Strings(common)
	for _, rel := range common {
		a := oldMap[rel]
		b := newMap[rel]
		if a == b {
			continue
		}
		out, err := vutils.GitDiff(a+"\n", b+"\n", &vutils.GitDiffConfig{Tool: "git"})
		if err != nil || out == "" {
			continue
		}
		pd.Updated[rel] = fmt.Sprintf("```diff\n%s\n```", out)
	}

	d.Plists = pd
	return nil
}

// collectPlists reads every KindPlist file in the bundle and returns
// canonicalized-XML strings keyed by bundle-relative path. Files that
// fail to parse are silently dropped (some "compiled" plists in nested
// .storyboardc directories aren't actually plists).
func collectPlists(b *bundle.Bundle) map[string]string {
	out := make(map[string]string)
	for rel, meta := range b.Files {
		if meta.Kind != bundle.KindPlist {
			continue
		}
		full := filepath.Join(b.AppDir, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		canon, err := parsers.CanonicalizePlist(data)
		if err != nil {
			continue
		}
		out[rel] = string(canon)
	}
	return out
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	var out []string
	for _, x := range b {
		if _, ok := set[x]; ok {
			out = append(out, x)
		}
	}
	return out
}
