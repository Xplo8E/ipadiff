package diff

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// inlineLimit caps how many "updated" entries we inline into the top-level
// Markdown file before spilling them into per-binary subpages.
const inlineLimit = 25

// charLimit caps the rendered size of any single section in the top-level
// file. Beyond this, the section is also spilled.
const charLimit = 200_000

// Markdown writes a Markdown report for d. When d.cfg.Output is empty the
// full report is streamed to w. Otherwise a directory layout is created:
//
//	<Output>/<TitleToFilename>/<title>.md          (top-level summary)
//	<Output>/<TitleToFilename>/MACHOS/<...>.md     (per-binary spill)
//	<Output>/<TitleToFilename>/PLISTS/<...>.md
//	<Output>/<TitleToFilename>/RESOURCES/<...>.md
func (d *Diff) Markdown(w io.Writer) error {
	if d.cfg.Output == "" {
		return d.writeInline(w)
	}
	return d.writeMultiFile()
}

func (d *Diff) writeInline(w io.Writer) error {
	body := d.renderBody(nil)
	_, err := io.WriteString(w, body)
	return err
}

// OutputDir returns the absolute path of the per-diff folder that
// writeMultiFile will create: <cfg.Output>/<bundleDirName>.
// Useful for callers that want to log the path or chain follow-ups.
func (d *Diff) OutputDir() string {
	return filepath.Join(d.cfg.Output, d.BundleDirName())
}

// BundleDirName builds the conventional per-diff subdirectory name:
// "<bundleID>_<oldVersion>_<newVersion>". Falls back to TitleToFilename
// when the bundle metadata is missing on either side.
func (d *Diff) BundleDirName() string {
	bid := d.Old.BundleID
	if bid == "" {
		bid = d.New.BundleID
	}
	if bid == "" || d.Old.Version == "" || d.New.Version == "" {
		return TitleToFilename(d.Title)
	}
	return TitleToFilename(fmt.Sprintf("%s_%s_%s", bid, d.Old.Version, d.New.Version))
}

// MainFileName is the human-readable name of the top-level report file.
// Prefers CFBundleName ("ChatGPT"), falls back to the last segment of the
// bundle ID, then to "diff".
func (d *Diff) MainFileName() string {
	for _, candidate := range []string{d.Old.BundleName, d.New.BundleName} {
		if candidate != "" {
			return TitleToFilename(candidate)
		}
	}
	bid := d.Old.BundleID
	if bid == "" {
		bid = d.New.BundleID
	}
	if bid != "" {
		parts := strings.Split(bid, ".")
		return TitleToFilename(parts[len(parts)-1])
	}
	return "diff"
}

func (d *Diff) writeMultiFile() error {
	root := d.OutputDir()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}

	spilled := make(map[string]string) // sectionLabel -> spill subdir name
	body := d.renderBody(func(section, key, content string) string {
		subdir, ok := spilled[section]
		if !ok {
			subdir = strings.ToUpper(section)
			spilled[section] = subdir
		}
		dir := filepath.Join(root, subdir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return ""
		}
		fname := safeName(key) + ".md"
		full := filepath.Join(dir, fname)
		page := fmt.Sprintf("## %s\n\n> `%s`\n\n%s\n", filepath.Base(key), key, content)
		_ = os.WriteFile(full, []byte(page), 0o644)
		return filepath.Join(subdir, fname)
	})

	mainFile := d.MainFileName() + ".md"
	if err := os.WriteFile(filepath.Join(root, mainFile), []byte(body), 0o644); err != nil {
		return err
	}

	// README.md is a thin index that points at the main file and any spill
	// subdirectories. Makes the folder navigable in one glance.
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte(d.renderIndex(mainFile, spilled)), 0o644); err != nil {
		return err
	}
	return nil
}

// renderIndex builds the README.md content: title, summary line, and links
// to the main report + each spill subdirectory.
func (d *Diff) renderIndex(mainFile string, spilled map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	b.WriteString("## Contents\n\n")
	fmt.Fprintf(&b, "- [Main report](./%s) — bundle summary, file tree, Obj-C/Swift, entitlements, provisioning\n", mainFile)

	if len(spilled) > 0 {
		// stable ordering
		keys := make([]string, 0, len(spilled))
		for k := range spilled {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, section := range keys {
			subdir := spilled[section]
			files, _ := os.ReadDir(filepath.Join(d.OutputDir(), subdir))
			fmt.Fprintf(&b, "- [%s/](./%s/) — %d updated entr%s\n",
				subdir, subdir, len(files), plural(len(files)))
		}
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// spillFn, when non-nil, is invoked for each "Updated" entry that exceeds
// inlineLimit/charLimit. It writes the entry to its own file and returns
// the relative link to use in the index.
type spillFn func(section, key, content string) string

func (d *Diff) renderBody(spill spillFn) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	d.renderSummary(&b)
	d.renderFileTree(&b)
	d.renderMachos(&b, spill)
	d.renderObjCSwift(&b)
	d.renderPlists(&b, spill)
	d.renderEntitlements(&b)
	d.renderProvisioning(&b)
	d.renderResources(&b, spill)

	return b.String()
}

// ----- per-section renderers ----------------------------------------------

func (d *Diff) renderSummary(b *strings.Builder) {
	b.WriteString("## Bundle Summary\n\n")
	b.WriteString("| | Old | New |\n")
	b.WriteString("| :-- | :-- | :-- |\n")
	fmt.Fprintf(b, "| **Path** | `%s` | `%s` |\n", filepath.Base(d.Old.IPAPath), filepath.Base(d.New.IPAPath))
	fmt.Fprintf(b, "| **Bundle ID** | `%s` | `%s` |\n", d.Old.BundleID, d.New.BundleID)
	fmt.Fprintf(b, "| **Version** | `%s` | `%s` |\n", d.Old.Version, d.New.Version)
	fmt.Fprintf(b, "| **Build** | `%s` | `%s` |\n", d.Old.Build, d.New.Build)
	fmt.Fprintf(b, "| **Executable** | `%s` | `%s` |\n", d.Old.ExeName, d.New.ExeName)
	fmt.Fprintf(b, "| **Frameworks** | %d | %d |\n", len(d.Old.Frameworks), len(d.New.Frameworks))
	fmt.Fprintf(b, "| **Files** | %d | %d |\n", len(d.Old.Files), len(d.New.Files))
	if d.Old.MainEncrypted || d.New.MainEncrypted {
		fmt.Fprintf(b, "| **Encrypted main** | %v | %v |\n", d.Old.MainEncrypted, d.New.MainEncrypted)
	}
	b.WriteString("\n")
}

func (d *Diff) renderFileTree(b *strings.Builder) {
	if d.FileTree == nil {
		return
	}
	if len(d.FileTree.New) == 0 && len(d.FileTree.Removed) == 0 {
		return
	}
	b.WriteString("## File Tree\n\n")
	listBlock(b, "🆕 New", d.FileTree.New)
	listBlock(b, "❌ Removed", d.FileTree.Removed)
}

func (d *Diff) renderMachos(b *strings.Builder, spill spillFn) {
	if d.Machos == nil {
		return
	}
	if len(d.Machos.New) == 0 && len(d.Machos.Removed) == 0 && len(d.Machos.Updated) == 0 {
		return
	}
	b.WriteString("## Mach-Os\n\n")
	listBlock(b, "🆕 New", d.Machos.New)
	listBlock(b, "❌ Removed", d.Machos.Removed)
	updatedBlock(b, "⬆️ Updated", d.Machos.Updated, "machos", spill)
}

func (d *Diff) renderObjCSwift(b *strings.Builder) {
	if strings.TrimSpace(d.ObjC) != "" {
		b.WriteString("## Obj-C\n\n")
		b.WriteString(d.ObjC)
		b.WriteString("\n")
	}
	if strings.TrimSpace(d.Swift) != "" {
		b.WriteString("## Swift\n\n")
		b.WriteString(d.Swift)
		b.WriteString("\n")
	}
}

func (d *Diff) renderPlists(b *strings.Builder, spill spillFn) {
	if d.Plists == nil {
		return
	}
	if len(d.Plists.New) == 0 && len(d.Plists.Removed) == 0 && len(d.Plists.Updated) == 0 {
		return
	}
	b.WriteString("## Plists\n\n")
	listBlock(b, "🆕 New", d.Plists.New)
	listBlock(b, "❌ Removed", d.Plists.Removed)
	updatedBlock(b, "⬆️ Updated", d.Plists.Updated, "plists", spill)
}

func (d *Diff) renderEntitlements(b *strings.Builder) {
	if strings.TrimSpace(d.Ents) == "" {
		return
	}
	b.WriteString("## Entitlements\n\n")
	b.WriteString(d.Ents)
	b.WriteString("\n")
}

func (d *Diff) renderProvisioning(b *strings.Builder) {
	if strings.TrimSpace(d.Provisioning) == "" {
		return
	}
	b.WriteString("## Provisioning Profile\n\n")
	b.WriteString(d.Provisioning)
	b.WriteString("\n\n")
}

func (d *Diff) renderResources(b *strings.Builder, spill spillFn) {
	r := d.Resources
	if r == nil {
		return
	}
	if len(r.New) == 0 && len(r.Removed) == 0 && len(r.Updated) == 0 && len(r.SizeOnly) == 0 {
		return
	}
	b.WriteString("## Resources\n\n")
	listBlock(b, "🆕 New", r.New)
	listBlock(b, "❌ Removed", r.Removed)
	updatedBlock(b, "⬆️ Updated (text)", r.Updated, "resources", spill)

	if len(r.SizeOnly) > 0 {
		b.WriteString("### 📦 Size changes (binary)\n\n")
		keys := mapKeys(r.SizeOnly)
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(b, "- `%s` — %s\n", k, r.SizeOnly[k])
		}
		b.WriteString("\n")
	}
}

// ----- helpers ------------------------------------------------------------

func listBlock(b *strings.Builder, heading string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s (%d)\n\n", heading, len(items))
	wrap := len(items) > 30
	if wrap {
		b.WriteString("<details>\n  <summary><i>View list</i></summary>\n\n")
	}
	for _, it := range items {
		fmt.Fprintf(b, "- `%s`\n", it)
	}
	if wrap {
		b.WriteString("\n</details>\n")
	}
	b.WriteString("\n")
}

// updatedBlock renders an "Updated" section. Each entry is wrapped in its
// own collapsed <details> block so the page is navigable. If spill is
// provided AND the section is large enough, each entry instead gets a
// link out to its own .md file.
func updatedBlock(b *strings.Builder, heading string, updated map[string]string, section string, spill spillFn) {
	if len(updated) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s (%d)\n\n", heading, len(updated))

	keys := mapKeys(updated)
	sort.Strings(keys)

	totalChars := 0
	for _, k := range keys {
		totalChars += len(updated[k])
	}
	shouldSpill := spill != nil && (len(updated) > inlineLimit || totalChars > charLimit)

	for _, k := range keys {
		if shouldSpill {
			link := spill(section, k, updated[k])
			if link != "" {
				fmt.Fprintf(b, "- [%s](%s)\n", k, link)
				continue
			}
		}
		// Per-entry collapsible block. Summary shows the bundle-relative
		// path so a glance through the section reads like a table of contents.
		fmt.Fprintf(b, "<details>\n<summary><code>%s</code></summary>\n\n%s\n\n</details>\n\n", k, updated[k])
	}
	b.WriteString("\n")
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TitleToFilename sanitizes a title into a safe filename. Vendored
// behaviorally from ipsw/internal/diff/diff.go:TitleToFilename — letters,
// digits, `_`, `-`, `,` survive; everything else collapses to a single `_`.
func TitleToFilename(title string) string {
	var out strings.Builder
	lastUnderscore := false
	writeUnderscore := func() {
		if lastUnderscore {
			return
		}
		out.WriteByte('_')
		lastUnderscore = true
	}
	for _, r := range title {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-', r == ',':
			out.WriteRune(r)
			lastUnderscore = false
		case unicode.IsSpace(r), r == '.', r == '(', r == ')', r == '/', r == '\\', r == ':':
			writeUnderscore()
		default:
			writeUnderscore()
		}
	}
	name := strings.Trim(out.String(), "_")
	if name == "" {
		return "diff"
	}
	return name
}

// safeName makes a bundle-relative path safe to use as a single filename.
func safeName(rel string) string {
	r := strings.NewReplacer(string(filepath.Separator), "_", " ", "_")
	return r.Replace(rel)
}
