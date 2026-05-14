package diff

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
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
	if d.cfg.Output == "" {
		_, err := io.WriteString(w, renderReadme(d, nil))
		return err
	}
	return d.writeMultiFile()
}

// OutputDir returns the absolute path of the per-diff folder that
// writeMultiFile will create: <cfg.Output>/<bundleDirName>.
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
// one binary": optional intelligence layer (main exe only in v1) +
// structural diff body + ObjC + Swift. Used for the main app file and
// every entry under FRAMEWORKS/ and PLUGINS/.
func renderBinaryFile(rel string, d *Diff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", rel)
	if d.Old.Files[rel].Encrypted || d.New.Files[rel].Encrypted {
		b.WriteString("> ⚠️ encrypted: structural diff only — symbols / cstrings / Obj-C / Swift skipped\n\n")
	}

	// Intelligence layer — main exe only in v1. Frameworks/plugins keep the
	// flat layout below until we retain DiffInfo for every binary.
	if isMainExe(rel, d) && d.mainOld != nil && d.mainNew != nil {
		renderIntel(&b, rel, d)
	}

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

func isMainExe(rel string, d *Diff) bool {
	return rel == d.New.ExeName || rel == d.Old.ExeName
}

// renderIntel writes the security-findings + metadata + linked-libraries +
// string-intelligence + ObjC/Swift-summary sections at the top of a
// per-binary report. All sections are omitted when their underlying data
// is empty (e.g. encrypted binary has no cstring intel).
func renderIntel(b *strings.Builder, rel string, d *Diff) {
	imports := classifyImportsForMain(d)
	strs := classifyStringsForMain(d)
	objcSummary := summarizeObjCDiff(d.ObjC[rel])
	swiftSummary := summarizeSwiftDiff(d.Swift[rel])
	findings := AggregateFindings(imports, strs, objcSummary, swiftSummary)

	renderFindings(b, findings)
	renderMetadataTable(b, d)
	renderLinkedLibs(b, imports)
	renderStringIntel(b, strs)
	renderObjCSummary(b, objcSummary)
	renderSwiftSummary(b, swiftSummary)
}

// classifyImportsForMain returns nil when the main exe DiffInfo isn't
// available on either side (degenerate case — caller should already have
// gated on this, but be defensive).
func classifyImportsForMain(d *Diff) *ImportIntel {
	if d.mainOld == nil || d.mainNew == nil {
		return nil
	}
	added, removed := vmacho.DiffImports(d.mainOld, d.mainNew)
	return ClassifyImportDelta(added, removed)
}

func classifyStringsForMain(d *Diff) *StringIntel {
	if d.mainOld == nil || d.mainNew == nil {
		return nil
	}
	added, removed := vmacho.DiffCStringsTyped(d.mainOld, d.mainNew)
	return ClassifyStringDelta(added, removed)
}

func renderFindings(b *strings.Builder, fs []Finding) {
	if len(fs) == 0 {
		return
	}
	high, med, info := FindingCounts(fs)
	if high+med+info == 0 {
		return
	}
	b.WriteString("## 🚦 Security-Relevant Findings\n\n")
	for _, tier := range []Tier{TierHigh, TierMedium, TierInfo} {
		bucket := filterByTier(fs, tier)
		if len(bucket) == 0 {
			continue
		}
		var label string
		switch tier {
		case TierHigh:
			label = "🔴 High"
		case TierMedium:
			label = "🟡 Medium"
		case TierInfo:
			label = "⚪ Info"
		}
		fmt.Fprintf(b, "### %s (%d)\n\n", label, len(bucket))
		for _, f := range bucket {
			fmt.Fprintf(b, "- %s — _%s_\n", f.Text, f.Reason)
		}
		b.WriteString("\n")
	}
}

func filterByTier(fs []Finding, t Tier) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Tier == t {
			out = append(out, f)
		}
	}
	return out
}

func renderMetadataTable(b *strings.Builder, d *Diff) {
	o, n := d.mainOld, d.mainNew
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

func renderLinkedLibs(b *strings.Builder, imp *ImportIntel) {
	if imp == nil {
		return
	}
	if mapEmpty(imp.Added) && mapEmpty(imp.Removed) {
		return
	}
	b.WriteString("## Linked Libraries\n\n")
	if !mapEmpty(imp.Added) {
		fmt.Fprintf(b, "### 🆕 Added (%d)\n\n", mapLen(imp.Added))
		b.WriteString("| Library | Category |\n| :-- | :-- |\n")
		for _, cat := range fwCategoryOrder {
			for _, lib := range imp.Added[cat] {
				fmt.Fprintf(b, "| `%s` | %s |\n", lib, cat)
			}
		}
		b.WriteString("\n")
	}
	if !mapEmpty(imp.Removed) {
		fmt.Fprintf(b, "### ❌ Removed (%d)\n\n", mapLen(imp.Removed))
		b.WriteString("| Library | Category |\n| :-- | :-- |\n")
		for _, cat := range fwCategoryOrder {
			for _, lib := range imp.Removed[cat] {
				fmt.Fprintf(b, "| `%s` | %s |\n", lib, cat)
			}
		}
		b.WriteString("\n")
	}
}

func renderStringIntel(b *strings.Builder, si *StringIntel) {
	if si == nil {
		return
	}
	if mapEmpty(si.Added) && mapEmpty(si.Removed) {
		return
	}
	b.WriteString("## String Intelligence\n\n")
	renderStringBuckets(b, "🆕 New", si.Added)
	renderStringBuckets(b, "❌ Removed", si.Removed)
}

func renderStringBuckets(b *strings.Builder, label string, buckets map[stringCategory][]string) {
	if mapEmpty(buckets) {
		return
	}
	for _, cat := range stringCategoryOrder {
		items := buckets[cat]
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(b, "### %s %s (%d)\n\n", label, cat, len(items))
		// Long unclassified buckets get a <details> wrapper.
		wrap := cat == catUnclassified && len(items) > 10
		if wrap {
			b.WriteString("<details>\n<summary><i>show</i></summary>\n\n")
		}
		for _, s := range items {
			fmt.Fprintf(b, "- `%s`\n", escapeBacktick(s))
		}
		if wrap {
			b.WriteString("\n</details>\n")
		}
		b.WriteString("\n")
	}
}

// escapeBacktick replaces backticks with a doubled fence so they don't
// break the surrounding inline-code span. Cheap, not full markdown
// escaping — strings with embedded markdown are still rendered roughly.
func escapeBacktick(s string) string {
	return strings.ReplaceAll(s, "`", "ʼ")
}

func renderObjCSummary(b *strings.Builder, s metaSummary) {
	if s.empty() {
		return
	}
	fmt.Fprintf(b, "## Obj-C Summary\n\n_+%d classes / -%d, +%d methods / -%d, +%d protocols / -%d_\n\n",
		s.AddedClasses, s.RemovedClasses,
		s.AddedMethods, s.RemovedMethods,
		s.AddedProtocols, s.RemovedProtocols)
}

func renderSwiftSummary(b *strings.Builder, s metaSummary) {
	if s.empty() {
		return
	}
	fmt.Fprintf(b, "## Swift Summary\n\n_+%d types / -%d, +%d funcs / -%d, +%d protocols / -%d_\n\n",
		s.AddedClasses, s.RemovedClasses,
		s.AddedMethods, s.RemovedMethods,
		s.AddedProtocols, s.RemovedProtocols)
}

func mapEmpty[K comparable, V any](m map[K][]V) bool {
	for _, v := range m {
		if len(v) > 0 {
			return false
		}
	}
	return true
}

func mapLen[K comparable, V any](m map[K][]V) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
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

func (d *Diff) writeMultiFile() error {
	root := d.OutputDir()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}

	mainExe := d.New.ExeName
	if mainExe == "" {
		mainExe = d.Old.ExeName
	}

	used := map[string]bool{}
	links := readmeLinks{}

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
		}
	}
	links.hasFrameworks = hasFrameworkDir
	links.hasPlugins = hasPluginDir

	// Per-plist files — README links to the folder only, no per-file index.
	if d.Plists != nil && len(d.Plists.Updated) > 0 {
		if err := os.MkdirAll(filepath.Join(root, "PLISTS"), 0o755); err != nil {
			return err
		}
		keys := make([]string, 0, len(d.Plists.Updated))
		for k := range d.Plists.Updated {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, rel := range keys {
			rel2 := uniqueName(used, "PLISTS"+string(filepath.Separator)+safeName(rel)+".md")
			page := fmt.Sprintf("# %s\n\n%s\n", rel, d.Plists.Updated[rel])
			if err := os.WriteFile(filepath.Join(root, rel2), []byte(page), 0o644); err != nil {
				return err
			}
		}
		links.hasPlists = true
	}

	return os.WriteFile(
		filepath.Join(root, "README.md"),
		[]byte(renderReadme(d, &links)),
		0o644,
	)
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
}

func renderReadme(d *Diff, links *readmeLinks) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	renderSummary(&b, d)
	renderStats(&b, d, links)
	renderFileTree(&b, d)
	renderEntitlements(&b, d)
	renderProvisioning(&b, d)
	renderResourcesInline(&b, d)
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

	// When the main exe has intel data available, surface a per-tier
	// finding count immediately below the link. Lets the reader see "3
	// high-interest changes" without clicking through to the report.
	if mainChanged && d.mainOld != nil && d.mainNew != nil {
		imp := classifyImportsForMain(d)
		strs := classifyStringsForMain(d)
		objc := summarizeObjCDiff(d.ObjC[mainExe])
		swift := summarizeSwiftDiff(d.Swift[mainExe])
		high, med, info := FindingCounts(AggregateFindings(imp, strs, objc, swift))
		if high > 0 {
			fmt.Fprintf(b, "  - 🔴 %d high-interest finding(s)\n", high)
		}
		if med > 0 {
			fmt.Fprintf(b, "  - 🟡 %d medium-interest finding(s)\n", med)
		}
		if info > 0 && high+med == 0 {
			// Only show info-tier when nothing higher exists, to keep the
			// dashboard tight.
			fmt.Fprintf(b, "  - ⚪ %d info-level finding(s)\n", info)
		}
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
			len(d.Plists.New), len(d.Plists.Removed), len(d.Plists.Updated), suffix)
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
		fmt.Fprintf(b, "- **Resources** — %d new, %d removed, %d text updated, %d size-only\n",
			len(d.Resources.New), len(d.Resources.Removed),
			len(d.Resources.Updated), len(d.Resources.SizeOnly))
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
