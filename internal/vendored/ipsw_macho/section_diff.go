// section_diff.go is vendored from
// github.com/blacktop/ipsw/internal/commands/macho/section_diff.go at commit
// 27f1f0a5b30338fb6406e52e2c0d62f98f9ab16e (unmodified). Original copyright
// belongs to blacktop; see internal/vendored/LICENSE.ipsw.
package vmacho

import (
	"fmt"
	"slices"
	"strings"
)

// addedRemoved returns the keys present only in next ("added") and only in prev
// ("removed"), each sorted.
func addedRemoved(prev, next map[string]struct{}) (added, removed []string) {
	for k := range next {
		if _, ok := prev[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range prev {
		if _, ok := next[k]; !ok {
			removed = append(removed, k)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

// memberDelta renders added ("+ ") and removed ("- ") member lines at column 0
// (so the surrounding ```diff fence colors them), returning "" when there is
// no change.
func memberDelta(added, removed []string) string {
	if len(added) == 0 && len(removed) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range added {
		fmt.Fprintf(&b, "+   %s\n", a)
	}
	for _, r := range removed {
		fmt.Fprintf(&b, "-   %s\n", r)
	}
	return b.String()
}

// diffSection renders one named group (e.g. Classes, Protocols, Swift Types) as a diff
// hunk: an "@@ … @@" header, then added ("+ ") and removed ("- ") entities, then
// changed entities (a context line followed by their member deltas). members
// extracts an entity's comparable member keys; addedLine renders the descriptive
// text shown for a newly added entity.
func diffSection[T any](title string, prev, next map[string]*T, members func(*T) map[string]struct{}, addedLine func(*T) string) string {
	type change struct{ name, body string }
	var added, removed []string
	var changed []change

	for name, ne := range next {
		pe, ok := prev[name]
		if !ok {
			added = append(added, name)
			continue
		}
		if body := memberDelta(addedRemoved(members(pe), members(ne))); body != "" {
			changed = append(changed, change{name, body})
		}
	}
	for name := range prev {
		if _, ok := next[name]; !ok {
			removed = append(removed, name)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	slices.SortFunc(changed, func(a, b change) int { return strings.Compare(a.name, b.name) })

	var b strings.Builder
	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Fprintf(&b, "@@ %s: no changes @@\n", title)
		return b.String()
	}
	fmt.Fprintf(&b, "@@ %s: +%d added, -%d removed, ~%d changed @@\n", title, len(added), len(removed), len(changed))
	for _, name := range added {
		fmt.Fprintf(&b, "+ %s\n", addedLine(next[name]))
	}
	for _, name := range removed {
		fmt.Fprintf(&b, "- %s\n", name)
	}
	for _, c := range changed {
		fmt.Fprintf(&b, " %s\n%s", c.name, c.body)
	}
	return b.String()
}

// sectionUnchanged reports whether out is diffSection's all-quiet output
// ("@@ Title: no changes @@\n" and nothing else). Checked by shape rather
// than substring, so a changed entity whose members merely mention "no
// changes" cannot suppress a real diff.
func sectionUnchanged(out string) bool {
	return strings.HasPrefix(out, "@@ ") &&
		strings.HasSuffix(out, ": no changes @@\n") &&
		strings.Count(out, "\n") == 1
}

// joinDiffSections drops the empty and all-quiet group outputs and joins the
// rest, returning "" when every group is unchanged. ipadiff addition.
func joinDiffSections(sections []string) string {
	var kept []string
	for _, s := range sections {
		if s != "" && !sectionUnchanged(s) {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, "\n")
}
