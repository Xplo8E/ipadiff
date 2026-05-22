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
	oldMap := d.collectPlists("old", d.Old)
	newMap := d.collectPlists("new", d.New)

	pd := &PlistDiff{Updated: make(map[string]string)}

	oldKeys := keysOf(oldMap)
	newKeys := keysOf(newMap)

	pd.New = vutils.Difference(newKeys, oldKeys)
	pd.Removed = vutils.Difference(oldKeys, newKeys)
	sort.Strings(pd.New)
	sort.Strings(pd.Removed)

	common := intersect(oldKeys, newKeys)
	sort.Strings(common)
	results := runStringWorkers(common, d.cfg.Workers, func(rel string) plistDiffResult {
		a := oldMap[rel]
		b := newMap[rel]
		if a == b {
			return plistDiffResult{rel: rel}
		}
		out, err := vutils.GitDiff(a+"\n", b+"\n", &vutils.GitDiffConfig{Tool: "git"})
		if err != nil || out == "" {
			if err != nil {
				return plistDiffResult{rel: rel, warning: "diff failed: " + err.Error()}
			}
			return plistDiffResult{rel: rel}
		}
		return plistDiffResult{rel: rel, diff: fmt.Sprintf("```diff\n%s\n```", out)}
	})
	for _, result := range results {
		if result.warning != "" {
			d.addWarning("plists", result.rel, result.warning)
		}
		if result.diff != "" {
			pd.Updated[result.rel] = result.diff
		}
	}

	d.Plists = pd
	return nil
}

// collectPlists reads every KindPlist file in the bundle and returns
// canonicalized-XML strings keyed by bundle-relative path. Files that
// fail to parse are silently dropped (some "compiled" plists in nested
// .storyboardc directories aren't actually plists).
type plistCollectResult struct {
	rel     string
	value   string
	warning string
}

type plistDiffResult struct {
	rel     string
	diff    string
	warning string
}

func (d *Diff) collectPlists(side string, b *bundle.Bundle) map[string]string {
	out := make(map[string]string)
	var keys []string
	for rel, meta := range b.Files {
		if meta.Kind != bundle.KindPlist {
			continue
		}
		keys = append(keys, rel)
	}
	sort.Strings(keys)
	results := runStringWorkers(keys, d.cfg.Workers, func(rel string) plistCollectResult {
		full := filepath.Join(b.AppDir, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			return plistCollectResult{rel: rel, warning: "read failed: " + err.Error()}
		}
		canon, err := parsers.CanonicalizePlist(data)
		if err != nil {
			return plistCollectResult{rel: rel, warning: "parse failed: " + err.Error()}
		}
		return plistCollectResult{rel: rel, value: string(canon)}
	})
	for _, result := range results {
		if result.warning != "" {
			d.addWarning("plists", result.rel, side+": "+result.warning)
			continue
		}
		out[result.rel] = result.value
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
