package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// diffResources covers everything that's NOT a Mach-O, Hermes bytecode, a plist, or media:
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

	var common []string
	for rel := range newSet {
		if _, ok := oldSet[rel]; ok {
			common = append(common, rel)
		}
	}
	sort.Strings(common)
	results := runStringWorkers(common, d.cfg.Workers, func(rel string) resourceDiffResult {
		oldMeta := d.Old.Files[rel]
		newMeta := d.New.Files[rel]
		result := resourceDiffResult{rel: rel}
		switch oldMeta.Kind {
		case bundle.KindText:
			diff, err := compareText(d.Old.AppDir, d.New.AppDir, rel)
			if err != nil {
				result.warning = err.Error()
				return result
			}
			result.textDiff = diff
		case bundle.KindBinary, bundle.KindUnknown:
			if oldMeta.Size != newMeta.Size {
				result.sizeOnly = fmt.Sprintf("%d -> %d bytes", oldMeta.Size, newMeta.Size)
			}
		}
		return result
	})
	for _, result := range results {
		if result.warning != "" {
			d.addWarning("resources", result.rel, result.warning)
		}
		if result.textDiff != "" {
			rd.Updated[result.rel] = result.textDiff
		}
		if result.sizeOnly != "" {
			rd.SizeOnly[result.rel] = result.sizeOnly
		}
	}

	d.Resources = rd
	return nil
}

// nonMediaResourceKeys returns every bundle-relative path that is NOT a
// Mach-O, Hermes bytecode, plist, or media.
func nonMediaResourceKeys(b *bundle.Bundle) []string {
	var out []string
	for rel, meta := range b.Files {
		switch meta.Kind {
		case bundle.KindMacho, bundle.KindHermes, bundle.KindMedia, bundle.KindPlist:
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

type resourceDiffResult struct {
	rel      string
	textDiff string
	sizeOnly string
	warning  string
}

func compareText(oldRoot, newRoot, rel string) (string, error) {
	a, err := os.ReadFile(filepath.Join(oldRoot, rel))
	if err != nil {
		return "", fmt.Errorf("read old text failed: %w", err)
	}
	b, err := os.ReadFile(filepath.Join(newRoot, rel))
	if err != nil {
		return "", fmt.Errorf("read new text failed: %w", err)
	}
	if string(a) == string(b) {
		return "", nil
	}
	if strings.EqualFold(filepath.Ext(rel), ".json") {
		canonA, canonB, ok := canonicalizeJSONPair(a, b)
		if ok {
			if bytes.Equal(canonA, canonB) {
				return "", nil
			}
			a, b = canonA, canonB
		}
	}
	out, err := vutils.GitDiff(string(a)+"\n", string(b)+"\n", &vutils.GitDiffConfig{Tool: "git"})
	if err != nil || out == "" {
		if err != nil {
			return "", fmt.Errorf("text diff failed: %w", err)
		}
		return "", nil
	}
	return fmt.Sprintf("```diff\n%s\n```", out), nil
}

func canonicalizeJSONPair(a, b []byte) ([]byte, []byte, bool) {
	canonA, err := canonicalizeJSON(a)
	if err != nil {
		return nil, nil, false
	}
	canonB, err := canonicalizeJSON(b)
	if err != nil {
		return nil, nil, false
	}
	return canonA, canonB, true
}

func canonicalizeJSON(data []byte) ([]byte, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON values")
	}
	out, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
