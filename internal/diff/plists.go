package diff

import (
	"bytes"
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
	oldMap, oldDropped, oldRaw := d.collectPlists("old", d.Old)
	newMap, newDropped, newRaw := d.collectPlists("new", d.New)
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

	// Files that fell back to raw text on exactly one side changed how they
	// canonicalize (encoding/format change) — that is worth a warning. Files
	// that fell back on both sides are compared as raw text below and stay
	// silent when identical, so identical unparseable files no longer produce
	// a warnings wall.
	rawSet := make(map[string]struct{}, len(oldRaw)+len(newRaw))
	for _, rel := range oldRaw {
		rawSet[rel] = struct{}{}
	}
	for _, rel := range newRaw {
		if _, ok := rawSet[rel]; !ok {
			rawSet[rel] = struct{}{}
		} else {
			delete(rawSet, rel) // both sides: silent, counted instead
		}
	}
	for rel := range rawSet {
		if _, ok := intersectLookup(common, rel); ok {
			d.addWarning("plists", rel, "canonicalization failed on one side; compared as raw text")
		}
	}

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

	// Count the common paths compared as raw text so the README can surface
	// the fallback as one line instead of a per-file warnings wall.
	for _, rel := range common {
		_, oldRawHit := intersectLookup(oldRaw, rel)
		_, newRawHit := intersectLookup(newRaw, rel)
		if oldRawHit || newRawHit {
			pd.Raw = append(pd.Raw, rel)
		}
	}
	sort.Strings(pd.Raw)

	d.Plists = pd
	return nil
}

// intersectLookup reports whether rel is present in the sorted slice.
func intersectLookup(sorted []string, rel string) (int, bool) {
	idx := sort.SearchStrings(sorted, rel)
	if idx < len(sorted) && sorted[idx] == rel {
		return idx, true
	}
	return idx, false
}

// collectPlists reads every KindPlist file in the bundle and returns
// canonicalized-XML strings keyed by bundle-relative path, plus the rels that
// fell back to raw text because canonicalization failed. Text-like files that
// fail to parse (OpenStep-format .strings and friends) are compared as raw
// bytes: identical files stay silent, changed files still show a diff —
// instead of being dropped with a per-file warning. Files that are not
// text-like (binary data misclassified as plist) are dropped with a warning
// as before. Compiled NIBArchive .nib/.storyboardc files do not reach here —
// Classify routes them to KindBinary.
type plistCollectResult struct {
	rel      string
	value    string
	fallback bool
	warning  string
	dropped  int // build-metadata keys removed from this plist
}

type plistDiffResult struct {
	rel     string
	diff    string
	warning string
}

// dropStat tallies build-metadata keys suppressed during plist collection.
type dropStat struct{ keys, plists int }

func (d *Diff) collectPlists(side string, b *bundle.Bundle) (map[string]string, dropStat, []string) {
	out := make(map[string]string)
	var raw []string
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
			// Fall back to raw bytes for text-like data so the comparison
			// still happens; binary look-alikes keep the old drop+warn path.
			if isTextLike(data) {
				return plistCollectResult{rel: rel, value: string(data), fallback: true}
			}
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
		if result.fallback {
			raw = append(raw, result.rel)
		}
		if result.dropped > 0 {
			stat.keys += result.dropped
			stat.plists++
		}
		out[result.rel] = result.value
	}
	return out, stat, raw
}

// isTextLike reports whether data looks like a text file: no NUL bytes in
// the leading 4 KiB. OpenStep .strings files are text; binary plists and
// other binary data contain NULs early.
func isTextLike(data []byte) bool {
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	return !bytes.ContainsRune(head, 0)
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
