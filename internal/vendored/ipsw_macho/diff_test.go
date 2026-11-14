package vmacho

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestDiffNormalizedSetsDuplicateSafety(t *testing.T) {
	// Generated-counter stripping must not turn duplicate occurrences into
	// false additions or removals: a.1 and a.2 both normalize to "a", so
	// sharing "a" across sides cancels even though each side lists it twice.
	old := []string{"a.1", "a.1"}
	next := []string{"a.1", "a.2"}
	added, removed := diffNormalizedSymbols(old, next)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("expected no diff, got added=%q removed=%q", added, removed)
	}

	// A genuinely new symbol still shows up.
	added, removed = diffNormalizedSymbols(old, []string{"a.1", "b"})
	if len(added) != 1 || added[0] != "b" || len(removed) != 0 {
		t.Fatalf("expected added=[b], got added=%q removed=%q", added, removed)
	}
}

func TestEquivalentLoadCommandPolicy(t *testing.T) {
	mk := func(loadCmdHash string) *DiffInfo {
		return &DiffInfo{
			Imports:     []string{"a", "b"},
			Sections:    []section{{Name: "__TEXT.__text", Size: 10}},
			Functions:   3,
			LoadCmdHash: loadCmdHash,
		}
	}
	old, next := mk("deadbeef"), mk("feedface")

	conf := &DiffConfig{CStrings: true, FuncStarts: true}
	if next.Equivalent(*old, conf) {
		t.Fatal("different load-command digests must not be equivalent")
	}
	conf.IgnoreLoadCommands = true
	if !next.Equivalent(*old, conf) {
		t.Fatal("IgnoreLoadCommands must skip the load-command leg")
	}

	// An empty digest on either side is "unavailable" and stays a wildcard.
	conf.IgnoreLoadCommands = false
	if !mk("").Equivalent(*old, conf) {
		t.Fatal("empty load-command digest must be a wildcard")
	}
}

func TestEquivalentFunctionsIgnoresAddresses(t *testing.T) {
	mk := func(base uint64) *DiffInfo {
		return &DiffInfo{
			Starts: []types.Function{
				{StartAddr: base, EndAddr: base + 8},
				{StartAddr: base + 16, EndAddr: base + 24},
				{StartAddr: base + 32, EndAddr: base + 40},
			},
		}
	}
	conf := &DiffConfig{FuncStarts: true}
	// Same size sequence at different addresses: equivalent.
	if !mk(0x1000).Equivalent(*mk(0x9000), conf) {
		t.Fatal("function starts must compare by size sequence, not address")
	}
	// A changed size breaks equivalence.
	shifted := mk(0x1000)
	shifted.Starts[1].EndAddr++
	if shifted.Equivalent(*mk(0x1000), conf) {
		t.Fatal("a changed function size must break equivalence")
	}
}

func TestSectionContentWildcardSemantics(t *testing.T) {
	skip := section{Name: "__TEXT.__text", Size: 8, HashMode: hashSkip}
	verbatim := section{Name: "__TEXT.__text", Size: 8, HashMode: hashVerbatim, Hash: "aa"}

	// In the same-size content check, a skipped hash is a wildcard: it means
	// "not compared" (code sections, FairPlay-degraded info), not "changed".
	if sameSizeContentChanged(skip, verbatim) {
		t.Fatal("hashSkip must stay a wildcard in the same-size content check")
	}
	if !sameSizeContentChanged(verbatim, section{Name: verbatim.Name, Size: verbatim.Size, HashMode: hashVerbatim, Hash: "bb"}) {
		t.Fatal("different digests at the same size must report changed content")
	}

	// In section equivalence a hash-MODE difference is a policy change: the
	// pair is not equivalent and must be formatted (FairPlay banner case).
	if equivalentSectionContent(skip, verbatim) {
		t.Fatal("hash mode difference must not compare equal in sections")
	}
}

func TestFormatUpdatedDiffEncryptedBanner(t *testing.T) {
	old := &DiffInfo{Encrypted: true, Sections: []section{{Name: "__TEXT.__text", Size: 10}}}
	next := &DiffInfo{Sections: []section{{Name: "__TEXT.__text", Size: 12}}}
	conf := &DiffConfig{Markdown: true, DiffTool: "git"}

	out, err := FormatUpdatedDiff(old, next, conf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff: %v", err)
	}
	if !strings.Contains(out, "encrypted: structural diff only") {
		t.Fatalf("expected encrypted banner in markdown output, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffSameSizeContentChange(t *testing.T) {
	old := &DiffInfo{Sections: []section{
		{Name: "__TEXT.__cstring", Size: 8, HashMode: hashVerbatim, Hash: "aa"},
	}}
	next := &DiffInfo{Sections: []section{
		{Name: "__TEXT.__cstring", Size: 8, HashMode: hashVerbatim, Hash: "bb"},
	}}
	conf := &DiffConfig{Markdown: true, DiffTool: "git"}

	out, err := FormatUpdatedDiff(old, next, conf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff: %v", err)
	}
	if !strings.Contains(out, "Sections with Same Size but Changed Content") ||
		!strings.Contains(out, "`__TEXT.__cstring`") {
		t.Fatalf("expected same-size content-change report, got:\n%s", out)
	}
}

func TestGenerateNilConfAndOrdering(t *testing.T) {
	prev := map[string]*DiffInfo{
		"b": {Imports: []string{"x"}},
		"a": {Imports: []string{"x"}},
	}
	next := map[string]*DiffInfo{
		"a": {Imports: []string{"x", "y"}},
		"c": {Imports: []string{"z"}},
	}
	diff := &MachoDiff{}
	// nil conf must not panic.
	if err := diff.Generate(prev, next, nil); err != nil {
		t.Fatalf("Generate(nil conf): %v", err)
	}
	if got := strings.Join(diff.New, ","); got != "c" {
		t.Fatalf("expected New=[c], got %q", got)
	}
	if got := strings.Join(diff.Removed, ","); got != "b" {
		t.Fatalf("expected Removed=[b], got %q", got)
	}
	if _, ok := diff.Updated["a"]; !ok {
		t.Fatal("expected updated entry for a")
	}
}

func TestGenerateSkipsEquivalentEncryptedPair(t *testing.T) {
	mk := func() *DiffInfo {
		return &DiffInfo{
			Sections:  []section{{Name: "__TEXT.__text", Size: 10, HashMode: hashSkip}},
			Encrypted: true,
		}
	}
	diff := &MachoDiff{}
	if err := diff.Generate(
		map[string]*DiffInfo{"m": mk()},
		map[string]*DiffInfo{"m": mk()},
		&DiffConfig{},
	); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(diff.Updated) != 0 {
		t.Fatalf("two identical degraded infos must be skipped, got updated=%q", diff.Updated)
	}
}

func TestJoinDiffSectionsShapeCheck(t *testing.T) {
	unchanged := "@@ Protocols: no changes @@\n"
	changed := "@@ Classes: +1 added, -0 removed, ~0 changed @@\n+ Foo : NSObject  (1 methods)\n"
	// A member line that merely mentions "no changes" must not be filtered.
	tricky := "@@ Classes: +1 added, -0 removed, ~0 changed @@\n+ some: no changes @@ handler\n"

	got := joinDiffSections([]string{unchanged, "", changed, tricky})
	want := changed + "\n" + tricky
	if got != want {
		t.Fatalf("joinDiffSections:\n got %q\nwant %q", got, want)
	}
	if joinDiffSections([]string{unchanged, unchanged}) != "" {
		t.Fatal("all-quiet sections must join to an empty diff")
	}
}
