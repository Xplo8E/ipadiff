package diff

import "sort"

// Warning records non-fatal degradation during a diff run. Section parsers
// still continue, but callers and the README can see what was skipped.
type Warning struct {
	Section string `json:"section,omitempty"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message,omitempty"`
}

func (d *Diff) addWarning(section, path, message string) {
	if d == nil || message == "" {
		return
	}
	d.Warnings = append(d.Warnings, Warning{
		Section: section,
		Path:    path,
		Message: message,
	})
}

func (d *Diff) sortWarnings() {
	sort.SliceStable(d.Warnings, func(i, j int) bool {
		a, b := d.Warnings[i], d.Warnings[j]
		if a.Section != b.Section {
			return a.Section < b.Section
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Message < b.Message
	})
}
