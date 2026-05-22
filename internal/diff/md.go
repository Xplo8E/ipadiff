package diff

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
)

const (
	spillEntryThreshold = 25
	spillByteThreshold  = 200 * 1024
)

// Markdown writes a Markdown report for d. When d.cfg.Output is empty the
// rendered README is streamed to w. Otherwise the multi-file directory
// layout is written to disk:
//
//	<Output>/<bundleDirName>/README.md             top-level index + stats
//	<Output>/<bundleDirName>/<BundleName>.md       main app binary diff
//	<Output>/<bundleDirName>/FRAMEWORKS/*.md       one per framework binary
//	<Output>/<bundleDirName>/PLUGINS/*.md          one per .appex / Watch / XPC / loose dylib
//	<Output>/<bundleDirName>/PLISTS/*.md           one per updated plist (no index entries)
func (d *Diff) Markdown(w io.Writer) error {
	if d.cfg == nil || d.cfg.Output == "" {
		return d.WriteMarkdown(w)
	}
	return d.WriteFiles(d.cfg.Output)
}

// WriteMarkdown streams a single-file Markdown report to w, regardless of
// Config.Output. Use WriteFiles for the multi-file layout.
func (d *Diff) WriteMarkdown(w io.Writer) error {
	_, err := io.WriteString(w, renderReadme(d, nil))
	return err
}

// WriteFiles writes the multi-file Markdown layout under
// <output>/<bundleDirName>. If output is empty, Config.Output is used, then
// DefaultOutputDir as the final fallback.
func (d *Diff) WriteFiles(output string) error {
	if output == "" && d.cfg != nil {
		output = d.cfg.Output
	}
	if output == "" {
		output = DefaultOutputDir
	}
	return d.writeMultiFile(output)
}

// OutputDir returns the absolute path of the per-diff folder that
// writeMultiFile will create: <cfg.Output>/<bundleDirName>.
func (d *Diff) OutputDir() string {
	output := DefaultOutputDir
	if d.cfg != nil && d.cfg.Output != "" {
		output = d.cfg.Output
	}
	return filepath.Join(output, d.BundleDirName())
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

// MainFileName is the human-readable name of the main app binary report.
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

// ----- binary classification ----------------------------------------------

type binaryKind int

const (
	binMain binaryKind = iota
	binFramework
	binPlugin
)

// classifyBinary decides where a Mach-O's per-binary report lives:
// the main app file, FRAMEWORKS/, or PLUGINS/ (catch-all for everything
// non-Frameworks/: PlugIns/, Watch/, XPCServices/, loose dylibs, nested
// frameworks inside .appex, etc.).
func classifyBinary(rel, mainExe string) binaryKind {
	if rel == mainExe {
		return binMain
	}
	if strings.HasPrefix(rel, "Frameworks"+string(filepath.Separator)) {
		return binFramework
	}
	return binPlugin
}

// niceBinaryFileName collapses canonical layouts to a short filename so
// FRAMEWORKS/PhoneNumberKit.md beats Frameworks_PhoneNumberKit.framework_PhoneNumberKit.md.
// Falls back to safeName for unusual paths.
func niceBinaryFileName(rel string) string {
	dir := filepath.Dir(rel)
	base := filepath.Base(rel)

	// Frameworks/X.framework/X  →  X
	if dir == "Frameworks"+string(filepath.Separator)+base+".framework" {
		return TitleToFilename(base) + ".md"
	}
	// PlugIns/X.appex/X         →  X
	parent := filepath.Base(dir)
	if strings.HasSuffix(parent, ".appex") {
		short := strings.TrimSuffix(parent, ".appex")
		if short == base {
			return TitleToFilename(short) + ".md"
		}
		// Nested binary inside an .appex (e.g. PlugIns/X.appex/Frameworks/Y.framework/Y):
		// prefix with the appex name to disambiguate.
		return TitleToFilename(short+"_"+base) + ".md"
	}
	return safeName(rel) + ".md"
}

// uniqueName ensures we never overwrite a previously-written file in this
// run by appending _1, _2, … on collision. The "used" set is mutated in
// place; pass the same map across an entire writeMultiFile invocation.
func uniqueName(used map[string]bool, candidate string) string {
	if !used[candidate] {
		used[candidate] = true
		return candidate
	}
	stem := strings.TrimSuffix(candidate, ".md")
	for i := 1; ; i++ {
		try := fmt.Sprintf("%s_%d.md", stem, i)
		if !used[try] {
			used[try] = true
			return try
		}
	}
}

// ----- per-binary file body -----------------------------------------------

// renderBinaryFile is the single source of truth for "everything about
// one binary": neutral Mach-O metadata + raw structural diff + ObjC +
// Swift. Used for the main app file and every entry under FRAMEWORKS/
// and PLUGINS/.
func renderBinaryFile(rel string, d *Diff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", rel)
	if d.Old.Files[rel].Encrypted || d.New.Files[rel].Encrypted {
		b.WriteString("> ⚠️ encrypted: structural diff only — symbols / cstrings / Obj-C / Swift skipped\n\n")
	}
	renderMetadataTable(&b, d.oldInfos[rel], d.newInfos[rel])

	if d.Machos != nil {
		if structDiff, ok := d.Machos.Updated[rel]; ok {
			b.WriteString("## Structural Diff\n\n")
			b.WriteString(structDiff)
			b.WriteString("\n")
		}
	}
	if objc := d.ObjC[rel]; objc != "" {
		b.WriteString("## Obj-C\n\n```diff\n")
		b.WriteString(objc)
		b.WriteString("\n```\n\n")
	}
	if swift := d.Swift[rel]; swift != "" {
		b.WriteString("## Swift\n\n```diff\n")
		b.WriteString(swift)
		b.WriteString("\n```\n\n")
	}
	return b.String()
}

func renderMetadataTable(b *strings.Builder, o, n *vmacho.DiffInfo) {
	if o == nil || n == nil {
		return
	}
	b.WriteString("## Mach-O Metadata\n\n")
	b.WriteString("| Field | Old | New |\n")
	b.WriteString("| :-- | :-- | :-- |\n")
	rowEq(b, "UUID", o.UUID, n.UUID)
	rowEq(b, "Source Version", o.Version, n.Version)
	fmt.Fprintf(b, "| **Sections** | %d | %d |\n", len(o.Sections), len(n.Sections))
	fmt.Fprintf(b, "| **Imports** | %d | %d |\n", len(o.Imports), len(n.Imports))
	fmt.Fprintf(b, "| **Symbols** | %d | %d |\n", len(o.Symbols), len(n.Symbols))
	fmt.Fprintf(b, "| **Functions** | %d | %d |\n", o.Functions, n.Functions)
	fmt.Fprintf(b, "| **CStrings** | %d | %d |\n", len(o.CStrings), len(n.CStrings))
	if o.Encrypted || n.Encrypted {
		fmt.Fprintf(b, "| **Encrypted** | %v | %v |\n", o.Encrypted, n.Encrypted)
	}
	b.WriteString("\n")
}

// rowEq emits a markdown row with code-fences around values, and prepends
// a "~" delta marker when old != new to draw the eye.
func rowEq(b *strings.Builder, field, oldV, newV string) {
	marker := "**"
	if oldV != newV {
		marker = "~~**"
	}
	_ = marker // mainly here for future formatting; basic row below
	if oldV == newV {
		fmt.Fprintf(b, "| %s | `%s` | `%s` |\n", field, truncate(oldV, 40), truncate(newV, 40))
	} else {
		fmt.Fprintf(b, "| **%s** | `%s` | `%s` |\n", field, truncate(oldV, 40), truncate(newV, 40))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// allBinaryRelPaths returns every bundle-relative path that has any
// content to render (structural diff, Obj-C diff, or Swift diff). The
// union covers the case where a binary is structurally identical but
// has ObjC/Swift metadata changes (rare but possible).
func (d *Diff) allBinaryRelPaths() []string {
	set := make(map[string]struct{})
	if d.Machos != nil {
		for k := range d.Machos.Updated {
			set[k] = struct{}{}
		}
	}
	for k := range d.ObjC {
		set[k] = struct{}{}
	}
	for k := range d.Swift {
		set[k] = struct{}{}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ----- writeMultiFile -----------------------------------------------------

func (d *Diff) writeMultiFile(output string) error {
	root, err := d.safeOutputRoot(output)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("reset output dir: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}

	mainExe := d.New.ExeName
	if mainExe == "" {
		mainExe = d.Old.ExeName
	}

	used := map[string]bool{}
	links := readmeLinks{binaryFiles: map[string]string{}}

	// Track whether at least one binary in each non-main bucket exists,
	// so renderStats can decide whether to surface the dir-link.
	hasFrameworkDir := false
	hasPluginDir := false

	for _, rel := range d.allBinaryRelPaths() {
		body := renderBinaryFile(rel, d)
		kind := classifyBinary(rel, mainExe)

		switch kind {
		case binMain:
			fname := uniqueName(used, d.MainFileName()+".md")
			if err := os.WriteFile(filepath.Join(root, fname), []byte(body), 0o644); err != nil {
				return err
			}
			links.main = fname
			links.binaryFiles[rel] = fname
		case binFramework:
			if !hasFrameworkDir {
				if err := os.MkdirAll(filepath.Join(root, "FRAMEWORKS"), 0o755); err != nil {
					return err
				}
				hasFrameworkDir = true
			}
			rel2 := "FRAMEWORKS" + string(filepath.Separator) + niceBinaryFileName(rel)
			rel2 = uniqueName(used, rel2)
			if err := os.WriteFile(filepath.Join(root, rel2), []byte(body), 0o644); err != nil {
				return err
			}
			links.binaryFiles[rel] = rel2
		case binPlugin:
			if !hasPluginDir {
				if err := os.MkdirAll(filepath.Join(root, "PLUGINS"), 0o755); err != nil {
					return err
				}
				hasPluginDir = true
			}
			rel2 := "PLUGINS" + string(filepath.Separator) + niceBinaryFileName(rel)
			rel2 = uniqueName(used, rel2)
			if err := os.WriteFile(filepath.Join(root, rel2), []byte(body), 0o644); err != nil {
				return err
			}
			links.binaryFiles[rel] = rel2
		}
	}
	links.hasFrameworks = hasFrameworkDir
	links.hasPlugins = hasPluginDir

	// Per-plist files — README links to the folder only, no per-file index.
	if d.Plists != nil && len(d.Plists.Updated) > 0 {
		pages := buildPlistPages(d.Plists)
		if len(pages) > 0 {
			if err := os.MkdirAll(filepath.Join(root, "PLISTS"), 0o755); err != nil {
				return err
			}
			for _, page := range pages {
				rel2 := uniqueName(used, "PLISTS"+string(filepath.Separator)+safeName(page.displayPath)+".md")
				if err := os.WriteFile(filepath.Join(root, rel2), []byte(page.body), 0o644); err != nil {
					return err
				}
			}
			links.hasPlists = true
		}
	}

	if shouldSpillResources(d.Resources) {
		if err := os.MkdirAll(filepath.Join(root, "RESOURCES"), 0o755); err != nil {
			return err
		}
		pages := buildResourcePages(d.Resources)
		for _, page := range pages {
			rel2 := "RESOURCES" + string(filepath.Separator) + page.fileName
			if err := os.WriteFile(filepath.Join(root, rel2), []byte(page.body), 0o644); err != nil {
				return err
			}
		}
		links.hasResources = true
	}

	if ok, err := d.writeHermesFiles(root); err != nil {
		return err
	} else if ok {
		links.hasHermes = true
	}

	return os.WriteFile(
		filepath.Join(root, "README.md"),
		[]byte(renderReadme(d, &links)),
		0o644,
	)
}

func (d *Diff) safeOutputRoot(output string) (string, error) {
	if strings.TrimSpace(output) == "" {
		return "", errors.New("output directory is empty")
	}
	bundleDir := d.BundleDirName()
	if bundleDir == "" || bundleDir == "." || bundleDir == string(filepath.Separator) {
		return "", fmt.Errorf("unsafe bundle output directory %q", bundleDir)
	}
	root, err := filepath.Abs(filepath.Join(output, bundleDir))
	if err != nil {
		return "", fmt.Errorf("resolve output dir: %w", err)
	}
	root = filepath.Clean(root)
	if filepath.Base(root) != bundleDir {
		return "", fmt.Errorf("unsafe output dir %q: expected final component %q", root, bundleDir)
	}
	if root == string(filepath.Separator) {
		return "", errors.New("refusing to delete filesystem root")
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == root {
		return "", fmt.Errorf("refusing to delete home directory %q", root)
	}
	if cwd, err := os.Getwd(); err == nil && filepath.Clean(cwd) == root {
		return "", fmt.Errorf("refusing to delete repository root %q", root)
	}
	return root, nil
}

// ----- README rendering ---------------------------------------------------

// readmeLinks reports which on-disk artifacts exist so the README can
// link to them. Subdir links are literal names; only the main-binary file
// is dynamic (depends on CFBundleName).
type readmeLinks struct {
	main          string // e.g. "ChatGPT.md"; empty if main binary unchanged
	hasFrameworks bool
	hasPlugins    bool
	hasPlists     bool
	hasResources  bool
	hasHermes     bool
	binaryFiles   map[string]string
}

func renderReadme(d *Diff, links *readmeLinks) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	renderSummary(&b, d)
	renderStats(&b, d, links)
	renderWarnings(&b, d)
	renderFileTree(&b, d)
	renderEntitlements(&b, d)
	renderProvisioning(&b, d)
	if links == nil || !links.hasResources {
		renderResourcesInline(&b, d)
	}
	return b.String()
}

func renderSummary(b *strings.Builder, d *Diff) {
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

// renderStats produces the section-by-section dashboard. Counts come from
// the diff struct; links point at per-binary files (main) or per-section
// dirs (FRAMEWORKS / PLUGINS / PLISTS).
func renderStats(b *strings.Builder, d *Diff, links *readmeLinks) {
	b.WriteString("## Stats\n\n")

	mainExe := d.New.ExeName
	if mainExe == "" {
		mainExe = d.Old.ExeName
	}

	// Main binary status.
	mainChanged := mainHasContent(d, mainExe)
	switch {
	case mainChanged && links != nil && links.main != "":
		fmt.Fprintf(b, "- **Main binary** — updated → [%s](./%s)\n", mainExe, links.main)
	case mainChanged:
		fmt.Fprintf(b, "- **Main binary** (`%s`) — updated\n", mainExe)
	default:
		fmt.Fprintf(b, "- **Main binary** (`%s`) — unchanged\n", mainExe)
	}

	// Mach-Os: roll up across non-main binaries.
	if d.Machos != nil {
		nonMainUpdated := 0
		for k := range d.Machos.Updated {
			if k != mainExe {
				nonMainUpdated++
			}
		}
		var dirs []string
		if links != nil && links.hasFrameworks {
			dirs = append(dirs, "[FRAMEWORKS/](./FRAMEWORKS/)")
		}
		if links != nil && links.hasPlugins {
			dirs = append(dirs, "[PLUGINS/](./PLUGINS/)")
		}
		suffix := ""
		if len(dirs) > 0 {
			suffix = " → " + strings.Join(dirs, ", ")
		}
		fmt.Fprintf(b, "- **Mach-Os** — %d new, %d removed, %d updated%s\n",
			len(d.Machos.New), len(d.Machos.Removed), nonMainUpdated, suffix)
	}

	// Plists.
	if d.Plists != nil {
		suffix := ""
		if links != nil && links.hasPlists {
			suffix = " → [PLISTS/](./PLISTS/)"
		}
		fmt.Fprintf(b, "- **Plists** — %d new, %d removed, %d updated%s\n",
			len(d.Plists.New), len(d.Plists.Removed), plistUpdatedCount(d.Plists), suffix)
	}

	// Entitlements: count "###" headers in the rendered diff (one per
	// changed binary). The vendored DiffDatabases output uses "### " as
	// the per-binary header.
	if strings.TrimSpace(d.Ents) != "" {
		entChanges := countEntChanges(d.Ents)
		if entChanges > 0 {
			fmt.Fprintf(b, "- **Entitlements** — %d changed (inline below)\n", entChanges)
		} else {
			b.WriteString("- **Entitlements** — unchanged\n")
		}
	}

	// Provisioning.
	if strings.TrimSpace(d.Provisioning) != "" {
		b.WriteString("- **Provisioning profile** — changed (inline below)\n")
	}

	// Resources.
	if d.Resources != nil {
		suffix := ""
		if links != nil && links.hasResources {
			suffix = " → [RESOURCES/](./RESOURCES/)"
		}
		fmt.Fprintf(b, "- **Resources** — %d new, %d removed, %d text updated, %d size-only%s\n",
			len(d.Resources.New), len(d.Resources.Removed),
			len(d.Resources.Updated), len(d.Resources.SizeOnly), suffix)
	}

	// Hermes.
	if d.Hermes != nil {
		suffix := ""
		if links != nil && links.hasHermes {
			suffix = " → [HERMES/](./HERMES/)"
		}
		fmt.Fprintf(b, "- **Hermes bundles** — %d new, %d removed, %d updated%s\n",
			len(d.Hermes.New), len(d.Hermes.Removed), len(d.Hermes.Updated), suffix)
	}

	b.WriteString("\n")
}

// mainHasContent reports whether the main app binary has any updated
// structural or metadata content to render.
func mainHasContent(d *Diff, mainExe string) bool {
	if d.Machos != nil {
		if _, ok := d.Machos.Updated[mainExe]; ok {
			return true
		}
	}
	if d.ObjC[mainExe] != "" || d.Swift[mainExe] != "" {
		return true
	}
	return false
}

// countEntChanges approximates the number of changed binaries in an
// entitlements diff by counting "### " headers. The vendored
// DiffDatabases output emits one header per binary that has a diff.
func countEntChanges(ents string) int {
	count := strings.Count(ents, "\n### ")
	if count == 0 && strings.HasPrefix(strings.TrimSpace(ents), "### ") {
		count = 1
	}
	if count == 0 && strings.HasPrefix(strings.TrimSpace(ents), "###") {
		count = 1
	}
	return count
}

func renderWarnings(b *strings.Builder, d *Diff) {
	if len(d.Warnings) == 0 {
		return
	}
	b.WriteString("## Warnings\n\n")
	for _, warning := range d.Warnings {
		label := warning.Section
		if warning.Path != "" {
			label += "/" + warning.Path
		}
		fmt.Fprintf(b, "- `%s` — %s\n", label, warning.Message)
	}
	b.WriteString("\n")
}

func renderFileTree(b *strings.Builder, d *Diff) {
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

func renderEntitlements(b *strings.Builder, d *Diff) {
	if strings.TrimSpace(d.Ents) == "" {
		return
	}
	b.WriteString("## Entitlements\n\n")
	b.WriteString(d.Ents)
	b.WriteString("\n")
}

func renderProvisioning(b *strings.Builder, d *Diff) {
	if strings.TrimSpace(d.Provisioning) == "" {
		return
	}
	b.WriteString("## Provisioning Profile\n\n")
	b.WriteString(d.Provisioning)
	b.WriteString("\n\n")
}

func renderResourcesInline(b *strings.Builder, d *Diff) {
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

	if len(r.Updated) > 0 {
		fmt.Fprintf(b, "### ⬆️ Updated (text) (%d)\n\n", len(r.Updated))
		keys := mapKeys(r.Updated)
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(b, "<details>\n<summary><code>%s</code></summary>\n\n%s\n\n</details>\n\n", k, r.Updated[k])
		}
	}

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

type resourcePage struct {
	displayPath string
	fileName    string
	body        string
}

func shouldSpillResources(r *ResourcesDiff) bool {
	if r == nil {
		return false
	}
	if len(r.Updated) > spillEntryThreshold {
		return true
	}
	var b strings.Builder
	renderResourcesInline(&b, &Diff{Resources: r})
	return b.Len() > spillByteThreshold
}

func buildResourcePages(r *ResourcesDiff) []resourcePage {
	if r == nil {
		return nil
	}
	var pages []resourcePage
	updatedKeys := mapKeys(r.Updated)
	sort.Strings(updatedKeys)
	used := map[string]bool{"README.md": true}
	for _, rel := range updatedKeys {
		fileName := uniqueName(used, safeName(rel)+".md")
		pages = append(pages, resourcePage{
			displayPath: rel,
			fileName:    fileName,
			body:        fmt.Sprintf("# %s\n\n%s\n", rel, r.Updated[rel]),
		})
	}
	pages = append([]resourcePage{{
		fileName: "README.md",
		body:     renderResourceIndex(r, pages),
	}}, pages...)
	return pages
}

func renderResourceIndex(r *ResourcesDiff, pages []resourcePage) string {
	var b strings.Builder
	b.WriteString("# Resources\n\n")
	listBlock(&b, "🆕 New", r.New)
	listBlock(&b, "❌ Removed", r.Removed)

	if len(r.Updated) > 0 {
		fmt.Fprintf(&b, "### ⬆️ Updated (text) (%d)\n\n", len(r.Updated))
		keys := mapKeys(r.Updated)
		sort.Strings(keys)
		pageByRel := make(map[string]string, len(pages))
		for _, page := range pages {
			pageByRel[page.displayPath] = page.fileName
		}
		for _, rel := range keys {
			fmt.Fprintf(&b, "- [`%s`](./%s)\n", rel, pageByRel[rel])
		}
		b.WriteString("\n")
	}

	if len(r.SizeOnly) > 0 {
		b.WriteString("### 📦 Size changes (binary)\n\n")
		keys := mapKeys(r.SizeOnly)
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- `%s` — %s\n", k, r.SizeOnly[k])
		}
		b.WriteString("\n")
	}
	return b.String()
}

type plistPage struct {
	displayPath string
	body        string
}

type localizedPlistGroup struct {
	displayPath string
	diffByRel   map[string]string
	localeByRel map[string]string
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

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func buildPlistPages(pd *PlistDiff) []plistPage {
	if pd == nil || len(pd.Updated) == 0 {
		return nil
	}

	var pages []plistPage
	groups := map[string]*localizedPlistGroup{}
	for rel, diff := range pd.Updated {
		key, locale, displayPath, ok := localizedPlistKey(rel)
		if !ok {
			pages = append(pages, plistPage{
				displayPath: rel,
				body:        fmt.Sprintf("# %s\n\n%s\n", rel, diff),
			})
			continue
		}
		group := groups[key]
		if group == nil {
			group = &localizedPlistGroup{
				displayPath: displayPath,
				diffByRel:   map[string]string{},
				localeByRel: map[string]string{},
			}
			groups[key] = group
		}
		group.diffByRel[rel] = diff
		group.localeByRel[rel] = locale
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		if len(group.diffByRel) == 1 {
			for rel, diff := range group.diffByRel {
				pages = append(pages, plistPage{
					displayPath: rel,
					body:        fmt.Sprintf("# %s\n\n%s\n", rel, diff),
				})
			}
			continue
		}
		pages = append(pages, plistPage{
			displayPath: group.displayPath,
			body:        renderLocalizedPlistPage(group),
		})
	}

	sort.Slice(pages, func(i, j int) bool {
		return pages[i].displayPath < pages[j].displayPath
	})
	return pages
}

func plistUpdatedCount(pd *PlistDiff) int {
	return len(buildPlistPages(pd))
}

func localizedPlistKey(rel string) (key, locale, displayPath string, ok bool) {
	parts := strings.Split(rel, string(filepath.Separator))
	for idx, part := range parts {
		if !strings.HasSuffix(part, ".lproj") || idx == len(parts)-1 {
			continue
		}
		locale = strings.TrimSuffix(part, ".lproj")
		displayParts := append([]string{}, parts[:idx]...)
		displayParts = append(displayParts, "*.lproj")
		displayParts = append(displayParts, parts[idx+1:]...)
		displayPath = filepath.Join(displayParts...)
		return displayPath, locale, displayPath, true
	}
	return "", "", "", false
}

func renderLocalizedPlistPage(group *localizedPlistGroup) string {
	var b strings.Builder
	paths := mapKeys(group.diffByRel)
	sort.Slice(paths, func(i, j int) bool {
		li, lj := group.localeByRel[paths[i]], group.localeByRel[paths[j]]
		if localeSortRank(li) != localeSortRank(lj) {
			return localeSortRank(li) < localeSortRank(lj)
		}
		if li != lj {
			return li < lj
		}
		return paths[i] < paths[j]
	})

	locales := make([]string, 0, len(paths))
	for _, rel := range paths {
		locales = append(locales, group.localeByRel[rel])
	}
	representative := paths[0]

	fmt.Fprintf(&b, "# %s\n\n", group.displayPath)
	b.WriteString("## Localized Family\n\n")
	fmt.Fprintf(&b, "- Representative path: `%s`\n", representative)
	fmt.Fprintf(&b, "- Locales (%d): %s\n\n", len(locales), inlineCodeList(locales))

	b.WriteString("## Paths\n\n")
	for _, rel := range paths {
		fmt.Fprintf(&b, "- `%s`\n", rel)
	}
	b.WriteString("\n## Representative Diff\n\n")
	b.WriteString(group.diffByRel[representative])
	b.WriteString("\n")
	return b.String()
}

func localeSortRank(locale string) int {
	switch locale {
	case "Base":
		return 0
	case "en":
		return 1
	default:
		return 2
	}
}

func inlineCodeList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("`%s`", item))
	}
	return strings.Join(parts, ", ")
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

// safeName turns a bundle-relative path into a single safe filename
// component (collapses `/`, ` ` to `_`).
func safeName(rel string) string {
	r := strings.NewReplacer(string(filepath.Separator), "_", " ", "_")
	return r.Replace(rel)
}

// Compile-time use marker for the vmacho import. The renderer never
// constructs a *vmacho.MachoDiff itself — that's the orchestrator's job —
// but readmeLinks doesn't need a direct reference. We keep the import
// because future renderer changes (per-binary cross-link summaries) will
// inspect *vmacho.MachoDiff directly.
var _ = (*vmacho.MachoDiff)(nil)
