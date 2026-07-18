package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apex/log"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	"github.com/Xplo8E/ipadiff/internal/parsers"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

func (d *Diff) diffPlists() error {
	oldMap, oldDropped := d.collectPlists("old", d.Old)
	newMap, newDropped := d.collectPlists("new", d.New)
	if keys := oldDropped.keys + newDropped.keys; keys > 0 {
		log.WithFields(log.Fields{
			"keys":   keys,
			"plists": oldDropped.plists + newDropped.plists,
		}).Info("suppressed build-metadata keys in plist diff (--keep-build-keys to show)")
	}

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
// canonicalized-XML strings keyed by bundle-relative path. A file that fails
// to parse is dropped from the map and recorded as a per-file warning (see the
// side+": "+result.warning path below). Compiled NIBArchive .nib/.storyboardc
// files no longer reach here — Classify routes them to KindBinary — so a parse
// warning now means a file that genuinely looks like a plist but isn't valid.
type plistCollectResult struct {
	rel     string
	value   string
	warning string
	dropped int // build-metadata keys removed from this plist
}

type plistDiffResult struct {
	rel     string
	diff    string
	warning string
}

// dropStat tallies build-metadata keys suppressed during plist collection.
type dropStat struct{ keys, plists int }

func (d *Diff) collectPlists(side string, b *bundle.Bundle) (map[string]string, dropStat) {
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
		canon, dropped, err := parsers.CanonicalizePlistDropBuild(data)
		if d.cfg.KeepBuildKeys {
			canon, err = parsers.CanonicalizePlist(data)
			dropped = 0
		}
		if err != nil {
			return plistCollectResult{rel: rel, warning: "parse failed: " + err.Error()}
		}
		return plistCollectResult{rel: rel, value: string(canon), dropped: dropped}
	})
	var stat dropStat
	for _, result := range results {
		if result.warning != "" {
			d.addWarning("plists", result.rel, side+": "+result.warning)
			continue
		}
		if result.dropped > 0 {
			stat.keys += result.dropped
			stat.plists++
		}
		out[result.rel] = result.value
	}
	return out, stat
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
