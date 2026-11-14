package diff

import (
	"encoding/json"
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
	out, err := renderReadme(d, nil, "")
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, out)
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
	links := readmeLinks{
		binaryFiles:   map[string]string{},
		plistFiles:    map[string]string{},
		resourceFiles: map[string]string{},
	}

	// Track whether at least one binary in each non-main bucket exists,
	// so renderStats can decide whether to surface the dir-link.
	hasFrameworkDir := false
	hasPluginDir := false

	// Render every binary page first, then deduplicate: the same framework
	// binary copied into the main app and every appex otherwise renders the
	// identical comparison once per copy. The first page in order stays full
	// with a "Same diff in" note; the others become stubs pointing at it, so
	// every README link still resolves.
	var pages []binaryPage
	for _, rel := range d.allBinaryRelPaths() {
		body := renderBinaryFile(rel, d)
		kind := classifyBinary(rel, mainExe)
		var fname string
		switch kind {
		case binMain:
			fname = uniqueName(used, d.MainFileName()+".md")
			links.main = fname
		case binFramework:
			if !hasFrameworkDir {
				if err := os.MkdirAll(filepath.Join(root, "FRAMEWORKS"), 0o755); err != nil {
					return err
				}
				hasFrameworkDir = true
			}
			fname = uniqueName(used, "FRAMEWORKS"+string(filepath.Separator)+niceBinaryFileName(rel))
		case binPlugin:
			if !hasPluginDir {
				if err := os.MkdirAll(filepath.Join(root, "PLUGINS"), 0o755); err != nil {
					return err
				}
				hasPluginDir = true
			}
			fname = uniqueName(used, "PLUGINS"+string(filepath.Separator)+niceBinaryFileName(rel))
		}
		links.binaryFiles[rel] = fname
		pages = append(pages, binaryPage{rel: rel, fname: fname, body: body})
	}
	for _, p := range dedupeBinaryPages(pages) {
		if err := os.WriteFile(filepath.Join(root, p.fname), []byte(p.body), 0o644); err != nil {
			return err
		}
	}
	links.hasFrameworks = hasFrameworkDir
	links.hasPlugins = hasPluginDir

	// Per-plist diff pages; the README links each page individually.
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
				links.plistFiles[page.displayPath] = rel2
			}
			links.hasPlists = true
		}
	}

	// Resource diff pages: every updated text resource gets its own page so
	// the README stays a pure index.
	if d.Resources != nil && len(d.Resources.Updated) > 0 {
		if err := os.MkdirAll(filepath.Join(root, "RESOURCES"), 0o755); err != nil {
			return err
		}
		pages := buildResourcePages(d.Resources)
		for _, page := range pages {
			rel2 := "RESOURCES" + string(filepath.Separator) + page.fileName
			if err := os.WriteFile(filepath.Join(root, rel2), []byte(page.body), 0o644); err != nil {
				return err
			}
			if page.displayPath != "" {
				links.resourceFiles[page.displayPath] = rel2
			}
		}
		links.hasResources = true
	}

	// Entitlements side-car: the README links it instead of inlining the diff.
	if entCount := countEntChanges(d.Ents); entCount > 0 {
		body := fmt.Sprintf("# Entitlements\n\n%d changed binaries.\n\n%s\n", entCount, d.Ents)
		if err := os.WriteFile(filepath.Join(root, "Entitlements.md"), []byte(body), 0o644); err != nil {
			return err
		}
	}

	if ok, err := d.writeHermesFiles(root); err != nil {
		return err
	} else if ok {
		links.hasHermes = true
	}

	if d.cfg.Facts {
		if err := d.writeFacts(root); err != nil {
			return fmt.Errorf("write facts: %w", err)
		}
	}

	out, err := renderReadme(d, &links, root)
	if err != nil {
		return err
	}
	return os.WriteFile(
		filepath.Join(root, "README.md"),
		[]byte(out),
		0o644,
	)
}

// writeFacts emits machine-readable per-binary comparison facts for both
// sides, keyed by bundle-relative path. Each binary's facts carry the policy
// that produced them, section content hashes, the load-command digest, and
// the code signature's entitlements + launch constraints, so scripted
// consumers can diff the JSON without re-parsing Mach-Os. The per-function
// start/end arrays are dropped unless cfg.FactsFunctionStarts is set: they
// dominate the file size (hundreds of thousands of entries per binary) while
// the section content hashes and load-command digest already carry the
// change signal.
func (d *Diff) writeFacts(root string) error {
	if len(d.factsOld) == 0 && len(d.factsNew) == 0 {
		return nil
	}
	if !d.cfg.FactsFunctionStarts {
		stripFunctionStarts(d.factsOld)
		stripFunctionStarts(d.factsNew)
	}
	type factsFile struct {
		Schema string                             `json:"schema"`
		Old    map[string]*vmacho.ComparisonFacts `json:"old,omitempty"`
		New    map[string]*vmacho.ComparisonFacts `json:"new,omitempty"`
	}
	data, err := json.MarshalIndent(factsFile{
		Schema: "ipadiff-facts-v1",
		Old:    d.factsOld,
		New:    d.factsNew,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "facts.json"), append(data, '\n'), 0o644)
}

func stripFunctionStarts(facts map[string]*vmacho.ComparisonFacts) {
	for _, f := range facts {
		if f != nil {
			f.FunctionStarts = nil
		}
	}
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
	// plistFiles / resourceFiles map a page's display path to the written
	// file name, so the README can link every diff page individually.
	plistFiles    map[string]string
	resourceFiles map[string]string
}

// ----- uniform list rule ----------------------------------------------------
//
// Every counted list in the README renders under one three-state rule,
// mirroring the latest ipsw diff renderer: fewer than listCollapseThreshold
// entries render as plain bullets, up to listSpillThreshold entries collapse
// into a <details> block, and anything at or above listSpillThreshold spills
// to a side-car doc with a single "View N" link (file mode only — the
// streamed report collapses instead of writing files).

const (
	listCollapseThreshold = 30
	listSpillThreshold    = 1000
)

// listLine is one README bullet: plain text (href "") or a markdown link.
// href is always relative to the report root (page file names already carry
// their section directory), so it is used verbatim.
type listLine struct {
	text string
	href string
}

func (l listLine) markdown() string {
	if l.href == "" {
		return "- `" + l.text + "`\n"
	}
	return fmt.Sprintf("- [%s](%s)\n", l.text, l.href)
}

// renderCountedList renders one counted heading plus its bullets under the
// three-state rule. spillSubDir/spillLabel control the side-car doc for the
// spill case; an empty root (streamed report) skips spilling and collapses.
func renderCountedList(out *strings.Builder, headingPrefix, title string, lines []listLine, root, spillSubDir, spillLabel string) error {
	if len(lines) == 0 {
		return nil
	}
	fmt.Fprintf(out, "%s %s (%d)\n\n", headingPrefix, title, len(lines))
	switch {
	case len(lines) >= listSpillThreshold && root != "" && spillSubDir != "":
		var body strings.Builder
		fmt.Fprintf(&body, "## %s (%d)\n\n", title, len(lines))
		for _, l := range lines {
			body.WriteString(l.markdown())
		}
		relName, err := writeSpillDoc(root, spillSubDir, spillLabel, body.String())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "- [View %d entries](%s)\n\n", len(lines), filepath.Join(spillSubDir, relName))
	case len(lines) >= listCollapseThreshold:
		fmt.Fprintf(out, "<details>\n  <summary><i>View %s</i></summary>\n\n", strings.TrimSpace(title))
		for _, l := range lines {
			out.WriteString(l.markdown())
		}
		out.WriteString("\n</details>\n\n")
	default:
		for _, l := range lines {
			out.WriteString(l.markdown())
		}
		out.WriteString("\n")
	}
	return nil
}

// renderDiffTriple renders the 🆕 NEW / ❌ Removed / ⬆️ Updated triple for one
// binary group or section.
func renderDiffTriple(out *strings.Builder, headingPrefix string, newLines, removedLines, updatedLines []listLine, root, spillSubDir, label string) error {
	if err := renderCountedList(out, headingPrefix, "🆕 NEW", newLines, root, spillSubDir, label+".New"); err != nil {
		return err
	}
	if err := renderCountedList(out, headingPrefix, "❌ Removed", removedLines, root, spillSubDir, label+".Removed"); err != nil {
		return err
	}
	return renderCountedList(out, headingPrefix, "⬆️ Updated", updatedLines, root, spillSubDir, label+".Updated")
}

// writeSpillDoc writes body to <root>/<subDir>/<label>.md (sanitized) and
// returns the base name for the README link.
func writeSpillDoc(root, subDir, label, body string) (string, error) {
	relName := safeName(label) + ".md"
	fname := filepath.Join(root, subDir, relName)
	if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(fname, []byte(body), 0o644); err != nil {
		return "", err
	}
	return relName, nil
}

// nameLines converts sorted rel paths to plain bullets.
func nameLines(paths []string) []listLine {
	lines := make([]listLine, 0, len(paths))
	for _, p := range paths {
		lines = append(lines, listLine{text: p})
	}
	return lines
}

// linkLines converts path->file-name maps to sorted link bullets.
func linkLines(m map[string]string) []listLine {
	keys := mapKeys(m)
	sort.Strings(keys)
	lines := make([]listLine, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, listLine{text: k, href: m[k]})
	}
	return lines
}

// renderReadme composes the index README. In file mode (links non-nil, root
// set) it is a pure index: every diff lives in its own page or side-car doc
// and the README shows counted, emoji-tagged links under the uniform
// three-state list rule. The streamed report (links nil, root empty) inlines
// the diffs it cannot link to.
func renderReadme(d *Diff, links *readmeLinks, root string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	if note := d.statusNote(); note != "" {
		b.WriteString(note + "\n")
	}

	// Inputs
	fmt.Fprintf(&b, "## Inputs\n\n- `%s`\n- `%s`\n\n",
		filepath.Base(d.Old.IPAPath), filepath.Base(d.New.IPAPath))

	renderSummary(&b, d)
	renderChangeSurfaceSection(&b, d, links)
	renderMainBinarySection(&b, d, links)
	if err := renderMachoGroupSections(&b, d, links, root); err != nil {
		return "", err
	}
	if err := renderPlistsSection(&b, d, links, root); err != nil {
		return "", err
	}
	renderEntitlementsSection(&b, d, links)
	renderProvisioning(&b, d)
	if err := renderResourcesSection(&b, d, links, root); err != nil {
		return "", err
	}
	if err := renderHermesSection(&b, d, links, root); err != nil {
		return "", err
	}
	if err := renderFileTreeSection(&b, d, root); err != nil {
		return "", err
	}
	if err := renderWarningsSection(&b, d, root); err != nil {
		return "", err
	}
	b.WriteString("## EOF\n")
	return b.String(), nil
}

// statusNote carries the no-change case so an empty diff never renders as a
// bare title.
func (d *Diff) statusNote() string {
	if d.diffEmpty() {
		return "> No differences found.\n"
	}
	return ""
}

func (d *Diff) diffEmpty() bool {
	machosEmpty := d.Machos == nil ||
		(len(d.Machos.New) == 0 && len(d.Machos.Removed) == 0 && len(d.Machos.Updated) == 0)
	plistsEmpty := d.Plists == nil ||
		(len(d.Plists.New) == 0 && len(d.Plists.Removed) == 0 && len(d.Plists.Updated) == 0 && len(d.Plists.Raw) == 0)
	resEmpty := d.Resources == nil ||
		(len(d.Resources.New) == 0 && len(d.Resources.Removed) == 0 && len(d.Resources.Updated) == 0 && len(d.Resources.SizeOnly) == 0)
	hermesEmpty := d.Hermes == nil ||
		(len(d.Hermes.New) == 0 && len(d.Hermes.Removed) == 0 && len(d.Hermes.Updated) == 0)
	ftEmpty := d.FileTree == nil || (len(d.FileTree.New) == 0 && len(d.FileTree.Removed) == 0)
	metaEmpty := len(d.ObjC) == 0 && len(d.Swift) == 0 &&
		strings.TrimSpace(d.Ents) == "" && strings.TrimSpace(d.Provisioning) == ""
	return machosEmpty && plistsEmpty && resEmpty && hermesEmpty && ftEmpty && metaEmpty
}

// renderChangeSurfaceSection promotes the per-binary delta table to its own
// section: it replaces the old Stats bullets as the at-a-glance view.
func renderChangeSurfaceSection(b *strings.Builder, d *Diff, links *readmeLinks) {
	if table := renderChangeSurface(d, links); table != "" {
		b.WriteString("## Change Surface\n\n")
		b.WriteString(table)
	}
}

func renderMainBinarySection(b *strings.Builder, d *Diff, links *readmeLinks) {
	mainExe := d.New.ExeName
	if mainExe == "" {
		mainExe = d.Old.ExeName
	}
	b.WriteString("## Main Binary\n\n")
	if !mainHasContent(d, mainExe) {
		b.WriteString("- unchanged\n\n")
		return
	}
	href := ""
	if links != nil {
		href = links.main
	}
	if href != "" {
		fmt.Fprintf(b, "#### ⬆️ Updated (1)\n\n- [%s](./%s)\n\n", mainExe, href)
		return
	}
	fmt.Fprintf(b, "#### ⬆️ Updated (1)\n\n- `%s`\n\n", mainExe)
}

// renderMachoGroupSections renders the Frameworks and Plugins groups as
// counted NEW/Removed/Updated triples over the non-main Mach-O diffs.
func renderMachoGroupSections(b *strings.Builder, d *Diff, links *readmeLinks, root string) error {
	mainExe := d.New.ExeName
	if mainExe == "" {
		mainExe = d.Old.ExeName
	}
	if d.Machos == nil {
		return nil
	}
	groups := []struct {
		heading string
		match   func(rel string) bool
		subDir  string
		label   string
	}{
		{"## Frameworks", func(rel string) bool {
			return strings.HasPrefix(rel, "Frameworks"+string(filepath.Separator))
		}, "FRAMEWORKS", "Frameworks"},
		{"## Plugins", func(rel string) bool { return true }, "PLUGINS", "Plugins"},
	}
	for _, g := range groups {
		var newL, rmL, upL []listLine
		for _, rel := range d.Machos.New {
			if rel != mainExe && g.match(rel) {
				newL = append(newL, listLine{text: rel})
			}
		}
		for _, rel := range d.Machos.Removed {
			if rel != mainExe && g.match(rel) {
				rmL = append(rmL, listLine{text: rel})
			}
		}
		for rel := range d.Machos.Updated {
			if rel != mainExe && g.match(rel) {
				href := ""
				if links != nil {
					href = links.binaryFiles[rel]
				}
				upL = append(upL, listLine{text: rel, href: href})
			}
		}
		sortListLines(newL)
		sortListLines(rmL)
		sortListLines(upL)
		if len(newL)+len(rmL)+len(upL) == 0 {
			continue
		}
		b.WriteString(g.heading + "\n\n")
		if err := renderDiffTriple(b, "####", newL, rmL, upL, root, g.subDir, g.label); err != nil {
			return err
		}
	}
	return nil
}

func renderPlistsSection(b *strings.Builder, d *Diff, links *readmeLinks, root string) error {
	pd := d.Plists
	if pd == nil {
		return nil
	}
	if len(pd.New) == 0 && len(pd.Removed) == 0 && len(pd.Updated) == 0 && len(pd.Raw) == 0 {
		return nil
	}
	b.WriteString("## Plists\n\n")
	var upL []listLine
	var inlineKeys []string
	if links != nil && len(links.plistFiles) > 0 {
		upL = linkLines(links.plistFiles)
	} else {
		// Streamed report: no side-car pages exist; count here, inline below.
		inlineKeys = mapKeys(pd.Updated)
		sort.Strings(inlineKeys)
		upL = nameLines(inlineKeys)
	}
	if err := renderDiffTriple(b, "####", nameLines(pd.New), nameLines(pd.Removed), upL, root, "PLISTS", "Plists"); err != nil {
		return err
	}
	if links == nil && len(inlineKeys) > 0 {
		for _, k := range inlineKeys {
			fmt.Fprintf(b, "<details>\n<summary><code>%s</code></summary>\n\n%s\n\n</details>\n\n", k, pd.Updated[k])
		}
	}
	if len(pd.Raw) > 0 {
		fmt.Fprintf(b, "\n> %d plists compared as raw bytes (canonicalization failed; identical files are silent).\n\n", len(pd.Raw))
	}
	return nil
}

func renderEntitlementsSection(b *strings.Builder, d *Diff, links *readmeLinks) {
	if strings.TrimSpace(d.Ents) == "" {
		return
	}
	b.WriteString("## Entitlements\n\n")
	count := countEntChanges(d.Ents)
	if count == 0 {
		b.WriteString("- unchanged\n\n")
		return
	}
	if links != nil {
		// The diff lives in the Entitlements.md side-car (file mode).
		fmt.Fprintf(b, "#### ⬆️ Updated (%d)\n\n- [Entitlements DIFF](./Entitlements.md)\n\n", count)
		return
	}
	fmt.Fprintf(b, "#### ⬆️ Updated (%d)\n\n", count)
	b.WriteString(d.Ents)
	b.WriteString("\n")
}

func renderResourcesSection(b *strings.Builder, d *Diff, links *readmeLinks, root string) error {
	r := d.Resources
	if r == nil {
		return nil
	}
	if len(r.New) == 0 && len(r.Removed) == 0 && len(r.Updated) == 0 && len(r.SizeOnly) == 0 {
		return nil
	}
	b.WriteString("## Resources\n\n")
	var upL []listLine
	var inlineKeys []string
	if links != nil && len(links.resourceFiles) > 0 {
		upL = linkLines(links.resourceFiles)
	} else if links == nil {
		inlineKeys = mapKeys(r.Updated)
		sort.Strings(inlineKeys)
		upL = nameLines(inlineKeys)
	}
	if err := renderDiffTriple(b, "####", nameLines(r.New), nameLines(r.Removed), upL, root, "RESOURCES", "Resources"); err != nil {
		return err
	}
	if links == nil && len(inlineKeys) > 0 {
		for _, k := range inlineKeys {
			fmt.Fprintf(b, "<details>\n<summary><code>%s</code></summary>\n\n%s\n\n</details>\n\n", k, r.Updated[k])
		}
	}
	if len(r.SizeOnly) > 0 {
		keys := mapKeys(r.SizeOnly)
		sort.Strings(keys)
		lines := make([]listLine, 0, len(keys))
		for _, k := range keys {
			lines = append(lines, listLine{text: fmt.Sprintf("%s — %s", k, r.SizeOnly[k])})
		}
		if err := renderCountedList(b, "####", "📦 Size changes (binary)", lines, root, "RESOURCES", "Resources.SizeChanges"); err != nil {
			return err
		}
	}
	return nil
}

func renderHermesSection(b *strings.Builder, d *Diff, links *readmeLinks, root string) error {
	h := d.Hermes
	if h == nil {
		return nil
	}
	if len(h.New) == 0 && len(h.Removed) == 0 && len(h.Updated) == 0 {
		return nil
	}
	b.WriteString("## Hermes\n\n")
	var upL []listLine
	if len(h.Updated) > 0 {
		if links != nil && links.hasHermes {
			upL = []listLine{{text: "bundle diffs", href: filepath.Join("HERMES", "README.md")}}
		} else {
			keys := make([]string, 0, len(h.Updated))
			for k := range h.Updated {
				keys = append(keys, k)
			}
			upL = nameLines(keys)
		}
	}
	return renderDiffTriple(b, "####", nameLines(h.New), nameLines(h.Removed), upL, root, "HERMES", "Hermes")
}

func renderProvisioning(b *strings.Builder, d *Diff) {
	if strings.TrimSpace(d.Provisioning) == "" {
		return
	}
	b.WriteString("## Provisioning Profile\n\n")
	b.WriteString(d.Provisioning)
	b.WriteString("\n\n")
}

func renderFileTreeSection(b *strings.Builder, d *Diff, root string) error {
	if d.FileTree == nil {
		return nil
	}
	if len(d.FileTree.New) == 0 && len(d.FileTree.Removed) == 0 {
		return nil
	}
	b.WriteString("## File Tree\n\n")
	return renderDiffTriple(b, "####", nameLines(d.FileTree.New), nameLines(d.FileTree.Removed), nil, root, "FILE_TREE", "FileTree")
}

func renderWarningsSection(b *strings.Builder, d *Diff, root string) error {
	if len(d.Warnings) == 0 {
		return nil
	}
	lines := make([]listLine, 0, len(d.Warnings))
	for _, w := range d.Warnings {
		label := w.Section
		if w.Path != "" {
			label += "/" + w.Path
		}
		lines = append(lines, listLine{text: fmt.Sprintf("%s — %s", label, w.Message)})
	}
	b.WriteString("## Warnings\n\n")
	return renderCountedList(b, "####", "Skipped / degraded", lines, root, "", "Warnings")
}

func sortListLines(lines []listLine) {
	sort.Slice(lines, func(i, j int) bool { return lines[i].text < lines[j].text })
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

// renderChangeSurface renders one row per binary whose comparison changed,
// sorted by how much moved, so a reader sees WHERE the release changed
// before opening any per-binary page. Counts are the normalized set deltas
// the diff engine compares (build-path/counter noise already collapsed).
func renderChangeSurface(d *Diff, links *readmeLinks) string {
	type row struct {
		rel                string
		symAdd, symDel     int
		csAdd, csDel       int
		funcDelta          int
		objc, swift, macho bool
		newOrRemoved       string
	}

	seen := make(map[string]struct{})
	var rels []string
	collect := func(m map[string]*vmacho.DiffInfo) {
		for rel := range m {
			if _, ok := seen[rel]; !ok {
				seen[rel] = struct{}{}
				rels = append(rels, rel)
			}
		}
	}
	collect(d.oldInfos)
	collect(d.newInfos)
	for rel := range d.ObjC {
		if _, ok := seen[rel]; !ok {
			seen[rel] = struct{}{}
			rels = append(rels, rel)
		}
	}
	for rel := range d.Swift {
		if _, ok := seen[rel]; !ok {
			seen[rel] = struct{}{}
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels)

	var rows []row
	for _, rel := range rels {
		r := row{rel: rel}
		switch {
		case d.oldInfos[rel] == nil && d.newInfos[rel] != nil:
			r.newOrRemoved = "new"
		case d.oldInfos[rel] != nil && d.newInfos[rel] == nil:
			r.newOrRemoved = "removed"
		default:
			r.symAdd, r.symDel, r.csAdd, r.csDel, r.funcDelta = vmacho.DiffCounts(d.oldInfos[rel], d.newInfos[rel])
		}
		_, r.macho = d.Machos.Updated[rel]
		r.objc = d.ObjC[rel] != ""
		r.swift = d.Swift[rel] != ""
		if r.newOrRemoved == "" && !r.macho && !r.objc && !r.swift &&
			r.symAdd == 0 && r.symDel == 0 && r.csAdd == 0 && r.csDel == 0 && r.funcDelta == 0 {
			continue
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return ""
	}

	// Loudest first: total moved entries, then binary name for stability.
	sort.Slice(rows, func(i, j int) bool {
		ti := abs(rows[i].symAdd+rows[i].symDel+rows[i].csAdd+rows[i].csDel) + abs(rows[i].funcDelta)
		tj := abs(rows[j].symAdd+rows[j].symDel+rows[j].csAdd+rows[j].csDel) + abs(rows[j].funcDelta)
		if ti != tj {
			return ti > tj
		}
		return rows[i].rel < rows[j].rel
	})

	var b strings.Builder
	b.WriteString("| Binary | Symbols | Strings | Functions | Obj-C | Swift | Structural |\n")
	b.WriteString("| :-- | :-- | :-- | :-- | :-- | :-- | :-- |\n")
	for _, r := range rows {
		name := r.rel
		if links != nil {
			if file := links.binaryFiles[r.rel]; file != "" {
				name = fmt.Sprintf("[%s](./%s)", r.rel, file)
			}
		}
		sym := "—"
		if r.newOrRemoved != "" {
			sym = r.newOrRemoved
		} else if r.symAdd+r.symDel > 0 {
			sym = fmt.Sprintf("+%d / −%d", r.symAdd, r.symDel)
		}
		strs := "—"
		if r.csAdd+r.csDel > 0 {
			strs = fmt.Sprintf("+%d / −%d", r.csAdd, r.csDel)
		}
		fns := "—"
		if r.funcDelta != 0 {
			fns = fmt.Sprintf("%+d", r.funcDelta)
		}
		yesNo := func(v bool) string {
			if v {
				return "changed"
			}
			return "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			name, sym, strs, fns, yesNo(r.objc), yesNo(r.swift), yesNo(r.macho))
	}
	b.WriteString("\n")
	return b.String()
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
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

type resourcePage struct {
	displayPath string
	fileName    string
	body        string
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
	// dedupeKey identifies the diff content of the page: pages that share a
	// key show the same change (bundles replicated across appexes) and are
	// merged by dedupePlistPages. Empty means "dedupe on the body minus the
	// title line".
	dedupeKey string
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
				dedupeKey:   diff,
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
					dedupeKey:   diff,
				})
			}
			continue
		}
		pages = append(pages, plistPage{
			displayPath: group.displayPath,
			body:        renderLocalizedPlistPage(group),
			dedupeKey:   localizedRepresentativeDiff(group),
		})
	}

	sort.Slice(pages, func(i, j int) bool {
		return pages[i].displayPath < pages[j].displayPath
	})
	return dedupePlistPages(pages)
}

// dedupePlistPages merges pages whose diff content is identical: bundles
// replicated across appexes (the same momd, localization bundle, or framework
// copied into every extension) otherwise render the same diff once per copy.
// The alphabetically first path becomes the representative; the rest are
// listed under a "Same diff in" note.
func dedupePlistPages(pages []plistPage) []plistPage {
	if len(pages) < 2 {
		return pages
	}
	type group struct {
		paths []string
		page  plistPage
	}
	groups := make(map[string]*group)
	var order []string
	for _, p := range pages {
		key := p.dedupeKey
		if key == "" {
			// Fall back to the body without the leading "# <path>\n\n" title.
			key = p.body
			if idx := strings.Index(p.body, "\n"); idx >= 0 {
				key = p.body[idx+1:]
			}
		}
		g := groups[key]
		if g == nil {
			g = &group{page: p}
			groups[key] = g
			order = append(order, key)
		}
		g.paths = append(g.paths, p.displayPath)
	}

	var out []plistPage
	for _, key := range order {
		g := groups[key]
		p := g.page
		if len(g.paths) > 1 {
			p.body = insertSameDiffNote(p.body, g.paths[1:])
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].displayPath < out[j].displayPath
	})
	return out
}

// localizedRepresentativeDiff returns the diff of the localized group's
// representative locale, matching what renderLocalizedPlistPage renders.
func localizedRepresentativeDiff(group *localizedPlistGroup) string {
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
	return group.diffByRel[paths[0]]
}

// ----- binary page dedupe --------------------------------------------------

// binaryPage is one rendered per-binary report page on its way to disk.
type binaryPage struct {
	rel, fname, body string
}

// dedupeBinaryPages merges binary pages whose rendered bodies are identical
// after the "# path" title: the same framework binary copied into the main
// app and every appex produces one comparison, not one per copy. The first
// page in order keeps its full body with a "Same diff in" note; the rest
// become stubs linking to it, so every README link still resolves.
func dedupeBinaryPages(pages []binaryPage) []binaryPage {
	if len(pages) < 2 {
		return pages
	}
	type group struct {
		pages []binaryPage
	}
	groups := make(map[string]*group)
	var order []string
	for _, p := range pages {
		key := p.body
		if idx := strings.Index(p.body, "\n\n"); idx >= 0 {
			key = p.body[idx+2:]
		}
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
			order = append(order, key)
		}
		g.pages = append(g.pages, p)
	}

	var out []binaryPage
	for _, key := range order {
		g := groups[key]
		head := g.pages[0]
		if len(g.pages) > 1 {
			var rest []string
			for _, other := range g.pages[1:] {
				rest = append(rest, other.rel)
			}
			head.body = insertSameDiffNote(head.body, rest)
			out = append(out, head)
			for _, other := range g.pages[1:] {
				out = append(out, stubBinaryPage(head, other))
			}
			continue
		}
		out = append(out, head)
	}
	return out
}

// stubBinaryPage builds the short pointer page written for a duplicated
// binary copy, linking to the representative page by a root-relative path.
func stubBinaryPage(head, other binaryPage) binaryPage {
	link, err := filepath.Rel(filepath.Dir(other.fname), head.fname)
	if err != nil {
		link = head.fname
	}
	return binaryPage{
		rel:   other.rel,
		fname: other.fname,
		body: fmt.Sprintf("# %s\n\n> Same diff as [%s](%s) — this copy of the binary compared identically; the full page lives there.\n",
			other.rel, head.rel, link),
	}
}

// insertSameDiffNote inserts the "Same diff in" note between the page's
// title line and the diff content.
func insertSameDiffNote(body string, paths []string) string {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = "`" + p + "`"
	}
	note := "> Same diff in: " + strings.Join(quoted, ", ") + "\n"
	idx := strings.Index(body, "\n\n")
	if idx < 0 {
		return body + "\n" + note
	}
	return body[:idx] + "\n" + note + body[idx+1:]
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
