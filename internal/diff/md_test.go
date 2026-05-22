package diff

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
)

func testDiff() *Diff {
	return &Diff{
		Title: "demo",
		cfg:   &Config{Output: DefaultOutputDir, Workers: 2},
		Old: &bundle.Bundle{
			IPAPath:  "old.ipa",
			BundleID: "com.example.demo",
			Version:  "1.0",
			Build:    "100",
			ExeName:  "App",
			Files:    map[string]bundle.FileMeta{},
		},
		New: &bundle.Bundle{
			IPAPath:  "new.ipa",
			BundleID: "com.example.demo",
			Version:  "1.1",
			Build:    "110",
			ExeName:  "App",
			Files:    map[string]bundle.FileMeta{},
		},
		ObjC:  map[string]string{},
		Swift: map[string]string{},
	}
}

func TestBuildPlistPages_GroupsLocalizedFamily(t *testing.T) {
	pd := &PlistDiff{
		Updated: map[string]string{
			"en.lproj/AppShortcuts.strings": "```diff\n+en\n```",
			"fr.lproj/AppShortcuts.strings": "```diff\n+fr\n```",
			"Info.plist":                    "```diff\n+info\n```",
		},
	}

	pages := buildPlistPages(pd)
	if len(pages) != 2 {
		t.Fatalf("buildPlistPages returned %d pages, want 2", len(pages))
	}
	if got := plistUpdatedCount(pd); got != 2 {
		t.Fatalf("plistUpdatedCount = %d, want 2", got)
	}

	var grouped plistPage
	for _, page := range pages {
		if page.displayPath == "*.lproj/AppShortcuts.strings" {
			grouped = page
			break
		}
	}
	if grouped.displayPath == "" {
		t.Fatalf("missing grouped localized page: %#v", pages)
	}
	if !strings.Contains(grouped.body, "Representative path: `en.lproj/AppShortcuts.strings`") {
		t.Fatalf("grouped body missing representative path: %s", grouped.body)
	}
	if !strings.Contains(grouped.body, "Locales (2): `en`, `fr`") {
		t.Fatalf("grouped body missing locale list: %s", grouped.body)
	}
}

func TestRenderReadme_StatsStayNeutral(t *testing.T) {
	main := "App"
	framework := "Frameworks/Foo.framework/Foo"

	d := testDiff()
	d.Old.ExeName = main
	d.New.ExeName = main
	d.Old.Frameworks = []string{framework}
	d.New.Frameworks = []string{framework}
	d.Machos = &vmacho.MachoDiff{
		Updated: map[string]string{
			framework: "framework diff",
		},
	}
	d.ObjC = map[string]string{}
	d.Swift = map[string]string{}

	out := renderReadme(d, &readmeLinks{
		hasFrameworks: true,
	})

	if strings.Contains(out, "Binary intel") {
		t.Fatalf("README still contains binary intel rollup:\n%s", out)
	}
	if strings.Contains(out, "Top binaries") {
		t.Fatalf("README still contains top-binary rollup:\n%s", out)
	}
	if !strings.Contains(out, "- **Mach-Os** — 0 new, 0 removed, 1 updated → [FRAMEWORKS/](./FRAMEWORKS/)") {
		t.Fatalf("README missing neutral Mach-O stats:\n%s", out)
	}
}

func TestRenderReadme_RendersWarnings(t *testing.T) {
	d := testDiff()
	d.Warnings = []Warning{{
		Section: "plists",
		Path:    "Broken.plist",
		Message: "parse failed",
	}}

	out := renderReadme(d, nil)
	if !strings.Contains(out, "## Warnings") {
		t.Fatalf("README missing warnings section:\n%s", out)
	}
	if !strings.Contains(out, "`plists/Broken.plist` — parse failed") {
		t.Fatalf("README missing warning detail:\n%s", out)
	}
}

func TestConfigDefaults_SetsWorkerDefault(t *testing.T) {
	cfg := &Config{}
	cfg.Defaults()
	if cfg.Workers < 1 {
		t.Fatalf("Defaults left Workers=%d, want positive", cfg.Workers)
	}
}

func TestWriteMarkdown_IgnoresConfiguredOutput(t *testing.T) {
	d := testDiff()
	d.cfg.Output = t.TempDir()

	var b bytes.Buffer
	if err := d.WriteMarkdown(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "# demo") {
		t.Fatalf("streamed markdown missing title:\n%s", b.String())
	}
	if _, err := os.Stat(d.OutputDir()); !os.IsNotExist(err) {
		t.Fatalf("WriteMarkdown wrote output dir %s: %v", d.OutputDir(), err)
	}
}

func TestCollectPlists_AddsParseWarning(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Broken.plist"), []byte("not a plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Diff{cfg: &Config{Workers: 4}}
	got := d.collectPlists("old", &bundle.Bundle{
		AppDir: dir,
		Files: map[string]bundle.FileMeta{
			"Broken.plist": {Kind: bundle.KindPlist},
		},
	})
	if len(got) != 0 {
		t.Fatalf("collectPlists returned parsed data for invalid plist: %#v", got)
	}
	if len(d.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one parse warning", d.Warnings)
	}
	if d.Warnings[0].Section != "plists" || d.Warnings[0].Path != "Broken.plist" {
		t.Fatalf("unexpected warning: %#v", d.Warnings[0])
	}
	if !strings.Contains(d.Warnings[0].Message, "old: parse failed") {
		t.Fatalf("warning missing parse failure: %#v", d.Warnings[0])
	}
}

func TestDiffResources_AddsReadWarning(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(newDir, "config.json"), []byte(`{"b":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Diff{
		cfg: &Config{Workers: 4},
		Old: &bundle.Bundle{
			AppDir: oldDir,
			Files: map[string]bundle.FileMeta{
				"config.json": {Kind: bundle.KindText},
			},
		},
		New: &bundle.Bundle{
			AppDir: newDir,
			Files: map[string]bundle.FileMeta{
				"config.json": {Kind: bundle.KindText},
			},
		},
	}
	if err := d.diffResources(); err != nil {
		t.Fatal(err)
	}
	if len(d.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one read warning", d.Warnings)
	}
	if d.Warnings[0].Section != "resources" || d.Warnings[0].Path != "config.json" {
		t.Fatalf("unexpected warning: %#v", d.Warnings[0])
	}
	if !strings.Contains(d.Warnings[0].Message, "read old text failed") {
		t.Fatalf("warning missing read failure: %#v", d.Warnings[0])
	}
}

func TestDiffResources_WorkersProduceExpectedDiff(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	for _, rel := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(oldDir, rel), []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(newDir, rel), []byte("new\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Diff{
		cfg: &Config{Workers: 8},
		Old: &bundle.Bundle{
			AppDir: oldDir,
			Files: map[string]bundle.FileMeta{
				"a.json": {Kind: bundle.KindText},
				"b.json": {Kind: bundle.KindText},
			},
		},
		New: &bundle.Bundle{
			AppDir: newDir,
			Files: map[string]bundle.FileMeta{
				"a.json": {Kind: bundle.KindText},
				"b.json": {Kind: bundle.KindText},
			},
		},
	}
	if err := d.diffResources(); err != nil {
		t.Fatal(err)
	}
	if len(d.Resources.Updated) != 2 {
		t.Fatalf("updated resources = %#v, want two diffs", d.Resources.Updated)
	}
	for _, rel := range []string{"a.json", "b.json"} {
		if !strings.Contains(d.Resources.Updated[rel], "+new") {
			t.Fatalf("missing diff for %s: %s", rel, d.Resources.Updated[rel])
		}
	}
}

func TestDiffResources_IgnoresJSONKeyOrderOnlyChange(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "version.json"), []byte(`{
  "version" : "3.0",
  "toolsVersion" : "17C52"
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "version.json"), []byte(`{
  "toolsVersion" : "17C52",
  "version" : "3.0"
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Diff{
		cfg: &Config{Workers: 2},
		Old: &bundle.Bundle{
			AppDir: oldDir,
			Files: map[string]bundle.FileMeta{
				"version.json": {Kind: bundle.KindText},
			},
		},
		New: &bundle.Bundle{
			AppDir: newDir,
			Files: map[string]bundle.FileMeta{
				"version.json": {Kind: bundle.KindText},
			},
		},
	}
	if err := d.diffResources(); err != nil {
		t.Fatal(err)
	}
	if len(d.Resources.Updated) != 0 {
		t.Fatalf("JSON key-order-only change should not diff: %#v", d.Resources.Updated)
	}
}

func TestDiffResources_DiffsCanonicalJSONValueChange(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "version.json"), []byte(`{"version":"3.0","toolsVersion":"17C52"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "version.json"), []byte(`{"toolsVersion":"17C53","version":"3.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Diff{
		cfg: &Config{Workers: 2},
		Old: &bundle.Bundle{
			AppDir: oldDir,
			Files: map[string]bundle.FileMeta{
				"version.json": {Kind: bundle.KindText},
			},
		},
		New: &bundle.Bundle{
			AppDir: newDir,
			Files: map[string]bundle.FileMeta{
				"version.json": {Kind: bundle.KindText},
			},
		},
	}
	if err := d.diffResources(); err != nil {
		t.Fatal(err)
	}
	diff := d.Resources.Updated["version.json"]
	if !strings.Contains(diff, "-  \"toolsVersion\": \"17C52\"") || !strings.Contains(diff, "+  \"toolsVersion\": \"17C53\"") {
		t.Fatalf("canonical JSON value diff missing expected delta:\n%s", diff)
	}
}

func TestDiffResources_ExcludesHermesBytecode(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "main.jsbundle"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "main.jsbundle"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Diff{
		cfg: &Config{Workers: 2},
		Old: &bundle.Bundle{
			AppDir: oldDir,
			Files: map[string]bundle.FileMeta{
				"main.jsbundle": {Kind: bundle.KindHermes},
			},
		},
		New: &bundle.Bundle{
			AppDir: newDir,
			Files: map[string]bundle.FileMeta{
				"main.jsbundle": {Kind: bundle.KindHermes},
			},
		},
	}
	if err := d.diffResources(); err != nil {
		t.Fatal(err)
	}
	if len(d.Resources.Updated) != 0 || len(d.Resources.SizeOnly) != 0 {
		t.Fatalf("Hermes bundle leaked into resources: %#v", d.Resources)
	}
}

func TestDiffHermes_TracksChangedBundles(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	for _, item := range []struct {
		root string
		rel  string
		body string
	}{
		{oldDir, "main.jsbundle", "old"},
		{newDir, "main.jsbundle", "new"},
		{oldDir, "same.hbc", "same"},
		{newDir, "same.hbc", "same"},
		{newDir, "added.hbc", "added"},
	} {
		if err := os.WriteFile(filepath.Join(item.root, item.rel), []byte(item.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Diff{
		cfg: &Config{Workers: 2},
		Old: &bundle.Bundle{
			AppDir: oldDir,
			Files: map[string]bundle.FileMeta{
				"main.jsbundle": {Kind: bundle.KindHermes},
				"same.hbc":      {Kind: bundle.KindHermes},
			},
		},
		New: &bundle.Bundle{
			AppDir: newDir,
			Files: map[string]bundle.FileMeta{
				"main.jsbundle": {Kind: bundle.KindHermes},
				"same.hbc":      {Kind: bundle.KindHermes},
				"added.hbc":     {Kind: bundle.KindHermes},
			},
		},
	}
	if err := d.diffHermes(); err != nil {
		t.Fatal(err)
	}
	defer d.cleanupHermesInputs()
	if _, ok := d.Hermes.Updated["main.jsbundle"]; !ok {
		t.Fatalf("missing changed Hermes bundle: %#v", d.Hermes)
	}
	if _, ok := d.Hermes.Updated["same.hbc"]; ok {
		t.Fatalf("unchanged Hermes bundle marked updated: %#v", d.Hermes)
	}
	if len(d.Hermes.New) != 1 || d.Hermes.New[0] != "added.hbc" {
		t.Fatalf("new Hermes bundles = %#v, want added.hbc", d.Hermes.New)
	}
}

func TestWriteFiles_RunsHermesSidecarAndLinksOutput(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "main.jsbundle"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "main.jsbundle"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "hermes-diff")
	if err := os.WriteFile(tool, []byte(`#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--out-dir" ]; then
    shift
    out="$1"
  fi
  shift
done
mkdir -p "$out/artifacts/hermes" "$out/functions/partial_demo"
cat > "$out/manifest.json" <<'JSON'
{
  "stats": {
    "old_functions": 10,
    "new_functions": 11,
    "exact": 7,
    "partial": 1,
    "new": 2,
    "deleted": 1
  }
}
JSON
echo "# Hermes" > "$out/README.md"
`), 0o755); err != nil {
		t.Fatal(err)
	}

	d := testDiff()
	d.cfg.HermesTool = tool
	d.Old.AppDir = oldDir
	d.New.AppDir = newDir
	d.Old.Files = map[string]bundle.FileMeta{"main.jsbundle": {Kind: bundle.KindHermes}}
	d.New.Files = map[string]bundle.FileMeta{"main.jsbundle": {Kind: bundle.KindHermes}}
	d.Hermes = &HermesDiff{Updated: map[string]*HermesBundleDiff{
		"main.jsbundle": {Path: "main.jsbundle"},
	}}

	out := t.TempDir()
	if err := d.WriteFiles(out); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(out, d.BundleDirName())
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "[HERMES/](./HERMES/)") {
		t.Fatalf("README missing HERMES link:\n%s", string(readme))
	}
	if _, err := os.Stat(filepath.Join(root, "HERMES", "main_jsbundle", "manifest.json")); err != nil {
		t.Fatalf("missing Hermes manifest: %v", err)
	}
	got := d.Hermes.Updated["main.jsbundle"]
	if got.OldFunctions != 10 || got.NewFunctions != 11 || got.Partial != 1 || got.New != 2 || got.Deleted != 1 {
		t.Fatalf("Hermes manifest stats not loaded: %#v", got)
	}
}

func TestWriteFiles_RunsHermesSidecarAfterBundleDirsAreGone(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "main.jsbundle"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "main.jsbundle"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	item := &HermesBundleDiff{Path: "main.jsbundle"}
	if err := item.snapshotInputs(oldDir, newDir); err != nil {
		t.Fatal(err)
	}
	snapshotRoot := filepath.Dir(item.oldInput)
	if err := os.RemoveAll(oldDir); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(newDir); err != nil {
		t.Fatal(err)
	}

	tool := filepath.Join(t.TempDir(), "hermes-diff")
	if err := os.WriteFile(tool, []byte(`#!/bin/sh
old=""
new=""
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --old) shift; old="$1" ;;
    --new) shift; new="$1" ;;
    --out-dir) shift; out="$1" ;;
  esac
  shift
done
test -f "$old" || exit 11
test -f "$new" || exit 12
mkdir -p "$out"
cat > "$out/manifest.json" <<'JSON'
{"stats":{"old_functions":1,"new_functions":1,"exact":0,"partial":1,"new":0,"deleted":0}}
JSON
echo "# Hermes" > "$out/README.md"
`), 0o755); err != nil {
		t.Fatal(err)
	}

	d := testDiff()
	d.cfg.HermesTool = tool
	d.Old.AppDir = oldDir
	d.New.AppDir = newDir
	d.Hermes = &HermesDiff{Updated: map[string]*HermesBundleDiff{
		"main.jsbundle": item,
	}}

	if err := d.WriteFiles(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if item.Warning != "" {
		t.Fatalf("unexpected Hermes warning: %s", item.Warning)
	}
	if item.Partial != 1 {
		t.Fatalf("manifest stats not loaded after snapshot run: %#v", item)
	}
	if _, err := os.Stat(snapshotRoot); !os.IsNotExist(err) {
		t.Fatalf("Hermes input snapshot was not cleaned up: %s (%v)", snapshotRoot, err)
	}
}

func TestFindHermesTool_DoesNotUseRelativeBinCandidate(t *testing.T) {
	d := testDiff()
	wd := t.TempDir()
	if err := os.Mkdir(filepath.Join(wd, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(wd, "bin", "hermes-diff")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatal(err)
		}
	}()

	got, err := d.findHermesTool()
	if err == nil && got == filepath.Join("bin", "hermes-diff") {
		t.Fatalf("findHermesTool used cwd-relative sidecar: %q", got)
	}
}

func TestWriteFiles_HermesSidecarTimeout(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "main.jsbundle"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "main.jsbundle"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "hermes-diff")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	d := testDiff()
	d.cfg.HermesTool = tool
	d.cfg.HermesTimeout = 10 * time.Millisecond
	d.Old.AppDir = oldDir
	d.New.AppDir = newDir
	d.Old.Files = map[string]bundle.FileMeta{"main.jsbundle": {Kind: bundle.KindHermes}}
	d.New.Files = map[string]bundle.FileMeta{"main.jsbundle": {Kind: bundle.KindHermes}}
	d.Hermes = &HermesDiff{Updated: map[string]*HermesBundleDiff{
		"main.jsbundle": {Path: "main.jsbundle"},
	}}

	if err := d.WriteFiles(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	warning := d.Hermes.Updated["main.jsbundle"].Warning
	if !strings.Contains(warning, "timed out") {
		t.Fatalf("missing timeout warning: %#v", d.Hermes.Updated["main.jsbundle"])
	}
}

func TestWriteFiles_SpillsLargeResources(t *testing.T) {
	d := testDiff()
	d.Resources = &ResourcesDiff{
		Updated:  map[string]string{},
		SizeOnly: map[string]string{"Assets/blob.bin": "1 -> 2 bytes"},
	}
	for i := 0; i < spillEntryThreshold+1; i++ {
		rel := fmt.Sprintf("Resources/file-%02d.json", i)
		d.Resources.Updated[rel] = "```diff\n-old\n+new\n```"
	}

	out := t.TempDir()
	if err := d.WriteFiles(out); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(out, d.BundleDirName())
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "[RESOURCES/](./RESOURCES/)") {
		t.Fatalf("README missing RESOURCES link:\n%s", string(readme))
	}
	if strings.Contains(string(readme), "Resources/file-00.json") {
		t.Fatalf("README kept spilled resource details inline:\n%s", string(readme))
	}
	if _, err := os.Stat(filepath.Join(root, "RESOURCES", "README.md")); err != nil {
		t.Fatalf("missing resources index: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "RESOURCES", "Resources_file-00.json.md")); err != nil {
		t.Fatalf("missing resource page: %v", err)
	}
}

func TestWriteFiles_RejectsRepositoryRootDeletion(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	d := testDiff()
	d.Title = filepath.Base(cwd)
	d.Old.BundleID = ""
	d.New.BundleID = ""
	d.Old.Version = ""
	d.New.Version = ""

	err = d.WriteFiles(filepath.Dir(cwd))
	if err == nil {
		t.Fatal("expected unsafe output path error")
	}
	if !strings.Contains(err.Error(), "repository root") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderBinaryFile_MetadataAndRawOnly(t *testing.T) {
	rel := "Frameworks/Foo.framework/Foo"
	d := &Diff{
		Old: &bundle.Bundle{
			ExeName: "App",
			Files:   map[string]bundle.FileMeta{rel: {}},
		},
		New: &bundle.Bundle{
			ExeName: "App",
			Files:   map[string]bundle.FileMeta{rel: {}},
		},
		Machos: &vmacho.MachoDiff{
			Updated: map[string]string{
				rel: "```diff\n- old\n+ new\n```",
			},
		},
		ObjC: map[string]string{
			rel: "+@interface Foo : NSObject",
		},
		Swift: map[string]string{
			rel: "+struct Foo {}",
		},
		oldInfos: map[string]*vmacho.DiffInfo{
			rel: {
				UUID:      "old-uuid",
				Version:   "1",
				Imports:   []string{"libOld.dylib"},
				Symbols:   []string{"_old"},
				Functions: 3,
				CStrings:  []string{"old"},
			},
		},
		newInfos: map[string]*vmacho.DiffInfo{
			rel: {
				UUID:      "new-uuid",
				Version:   "2",
				Imports:   []string{"libOld.dylib", "libNew.dylib"},
				Symbols:   []string{"_old", "_new"},
				Functions: 4,
				CStrings:  []string{"old", "new"},
			},
		},
	}

	out := renderBinaryFile(rel, d)
	for _, want := range []string{
		"## Mach-O Metadata",
		"## Structural Diff",
		"## Obj-C",
		"## Swift",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("binary report missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{
		"Security-Relevant Findings",
		"Linked Libraries",
		"String Intelligence",
		"Obj-C Summary",
		"Swift Summary",
	} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("binary report still contains %q:\n%s", unwanted, out)
		}
	}
}
