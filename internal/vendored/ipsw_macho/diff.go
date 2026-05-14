// Package vmacho is vendored from
// github.com/blacktop/ipsw/internal/commands/macho at commit
// d8aec666867becf32f904a1d6338f9e23efd55c1. Pruned: dropped DiffIPSW,
// DiffFirmwares, *LowMemory variants (and the search/signature dependencies
// they pulled in). The remaining engine (DiffInfo, MachoDiff.Generate,
// FormatUpdatedDiff, normalizeCStringForDiff) operates on already-opened
// *macho.File handles supplied by the caller. Original copyright belongs to
// blacktop; see internal/vendored/LICENSE.ipsw.
package vmacho

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"

	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// xbsTemporaryBuildPathRE collapses build-server temp paths so they don't
// dominate the cstring diff with noise.
var xbsTemporaryBuildPathRE = regexp.MustCompile(`^/Library/Caches/com\.apple\.xbs/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/TemporaryDirectory\.[^/\s]+`)

const xbsTemporaryBuildPathPlaceholder = "/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>"

func normalizeCStringForDiff(value string) string {
	return xbsTemporaryBuildPathRE.ReplaceAllString(value, xbsTemporaryBuildPathPlaceholder)
}

func normalizeCStringsForDiff(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, len(values))
	for idx, value := range values {
		normalized[idx] = normalizeCStringForDiff(value)
	}
	return normalized
}

func diffNormalizedCStrings(oldValues, newValues []string) ([]string, []string) {
	normalizedOldValues := normalizeCStringsForDiff(oldValues)
	normalizedNewValues := normalizeCStringsForDiff(newValues)

	added := vutils.Difference(normalizedNewValues, normalizedOldValues)
	sort.Strings(added)
	removed := vutils.Difference(normalizedOldValues, normalizedNewValues)
	sort.Strings(removed)

	return added, removed
}

// DiffImports returns sorted (added, removed) sets across two DiffInfos'
// Imports lists. Safe with nil inputs (treated as empty).
func DiffImports(oldI, newI *DiffInfo) (added, removed []string) {
	return setDiff(infoImports(newI), infoImports(oldI))
}

// DiffCStringsTyped returns sorted (added, removed) sets across the
// cstring lists of two DiffInfos, after the same XBS path normalization
// that FormatUpdatedDiff uses. Safe with nil inputs (treated as empty).
func DiffCStringsTyped(oldI, newI *DiffInfo) (added, removed []string) {
	return diffNormalizedCStrings(infoCStrings(oldI), infoCStrings(newI))
}

// DiffSymbols returns sorted (added, removed) sets across the symbol
// lists of two DiffInfos. Safe with nil inputs (treated as empty).
func DiffSymbols(oldI, newI *DiffInfo) (added, removed []string) {
	return setDiff(infoSymbols(newI), infoSymbols(oldI))
}

func setDiff(a, b []string) (added, removed []string) {
	added = vutils.Difference(a, b)
	sort.Strings(added)
	removed = vutils.Difference(b, a)
	sort.Strings(removed)
	return
}

func infoImports(i *DiffInfo) []string {
	if i == nil {
		return nil
	}
	return i.Imports
}

func infoCStrings(i *DiffInfo) []string {
	if i == nil {
		return nil
	}
	return i.CStrings
}

func infoSymbols(i *DiffInfo) []string {
	if i == nil {
		return nil
	}
	return i.Symbols
}

type DiffConfig struct {
	Markdown   bool
	Color      bool
	DiffTool   string
	AllowList  []string
	BlockList  []string
	CStrings   bool
	FuncStarts bool
	Verbose    bool
}

type MachoDiff struct {
	New     []string          `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"updated,omitempty"`
}

type section struct {
	Name string `json:"name,omitempty"`
	Size uint64 `json:"size,omitempty"`
}

type DiffInfo struct {
	Version   string
	UUID      string
	Imports   []string
	Sections  []section
	Functions int
	Starts    []types.Function
	Symbols   []string
	CStrings  []string
	SymbolMap map[uint64]string
	Verbose   bool

	// Encrypted marks binaries with FairPlay (LC_ENCRYPTION_INFO.CryptID != 0).
	// When true, GenerateDiffInfo skips symbol/cstring extraction (those segments
	// are unreadable). Set externally before calling FormatUpdatedDiff.
	Encrypted bool
}

// GenerateDiffInfo extracts a structural fingerprint from a Mach-O.
// For encrypted binaries (FairPlay), pass conf with CStrings=false and
// FuncStarts=false, or use GenerateDiffInfoDegraded.
func GenerateDiffInfo(m *macho.File, conf *DiffConfig) *DiffInfo {
	var secs []section
	for _, s := range m.Sections {
		if len(conf.AllowList) > 0 {
			if !slices.Contains(conf.AllowList, s.Seg+"."+s.Name) {
				continue
			}
		}
		if len(conf.BlockList) > 0 {
			if slices.Contains(conf.BlockList, s.Seg+"."+s.Name) {
				continue
			}
		}
		secs = append(secs, section{
			Name: s.Seg + "." + s.Name,
			Size: s.Size,
		})
	}
	var starts []types.Function
	if fns := m.GetFunctions(); fns != nil {
		starts = fns
	}
	var sourceVersion string
	if m.SourceVersion() != nil {
		sourceVersion = m.SourceVersion().Version.String()
	}
	var uuidStr string
	if m.UUID() != nil {
		uuidStr = m.UUID().String()
	}
	smap := make(map[uint64]string)
	var syms []string
	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			syms = append(syms, sym.Name)
			if conf.FuncStarts {
				if len(sym.Name) != 0 && sym.Name != "<redacted>" {
					smap[sym.Value] = sym.Name
				}
			}
		}
		slices.Sort(syms)
	}
	var strs []string
	if conf.CStrings {
		if cs, err := m.GetCStrings(); err == nil {
			for _, val := range cs {
				str2addr := slices.Collect(maps.Keys(val))
				strs = append(strs, str2addr...)
			}
			slices.Sort(strs)
		}
		if cfstrs, err := m.GetCFStrings(); err == nil {
			for _, val := range cfstrs {
				strs = append(strs, val.Name)
			}
			slices.Sort(strs)
		}
	}
	return &DiffInfo{
		Version:   sourceVersion,
		UUID:      uuidStr,
		Imports:   m.ImportedLibraries(),
		Sections:  secs,
		Functions: len(starts),
		Starts:    starts,
		Symbols:   syms,
		CStrings:  strs,
		SymbolMap: smap,
		Verbose:   conf.Verbose,
	}
}

// GenerateDiffInfoDegraded builds a DiffInfo from an encrypted Mach-O,
// covering only the parts that are still readable (sections, imports,
// function starts table) and skipping anything that requires reading
// encrypted segments (symbols, cstrings).
func GenerateDiffInfoDegraded(m *macho.File, conf *DiffConfig) *DiffInfo {
	degraded := *conf
	degraded.CStrings = false
	degraded.FuncStarts = false
	info := GenerateDiffInfo(m, &degraded)
	info.Encrypted = true
	return info
}

// Equal performs a cheap structural equality check.
func (i DiffInfo) Equal(x DiffInfo) bool {
	if len(i.Imports) != len(x.Imports) {
		return false
	}
	for i, imp := range i.Imports {
		if imp != x.Imports[i] {
			return false
		}
	}
	if len(i.Sections) != len(x.Sections) {
		return false
	}
	for i, sec := range i.Sections {
		if sec != x.Sections[i] {
			return false
		}
	}
	if i.Functions != x.Functions {
		return false
	}
	if len(i.Symbols) != len(x.Symbols) {
		return false
	}
	if i.Verbose && x.Verbose {
		if i.Version != x.Version {
			return false
		}
		if i.UUID != x.UUID {
			return false
		}
	}
	return true
}

func (i *DiffInfo) String() string {
	var out strings.Builder
	out.WriteString(i.Version + "\n")
	for _, sec := range i.Sections {
		out.WriteString(fmt.Sprintf("  %s: %#x\n", sec.Name, sec.Size))
	}
	slices.Sort(i.Imports)
	for _, imp := range i.Imports {
		out.WriteString(fmt.Sprintf("  - %s\n", imp))
	}
	out.WriteString(fmt.Sprintf("  UUID: %s\n", i.UUID))
	out.WriteString(fmt.Sprintf("  Functions: %d\n", i.Functions))
	out.WriteString(fmt.Sprintf("  Symbols:   %d\n", len(i.Symbols)))
	out.WriteString(fmt.Sprintf("  CStrings:  %d\n", len(i.CStrings)))
	return out.String()
}

// FormatUpdatedDiff renders a single-binary unified diff: header, symbols,
// optional function-starts size deltas, optional cstring add/remove.
func FormatUpdatedDiff(oldInfo, newInfo *DiffInfo, conf *DiffConfig) (string, error) {
	if oldInfo == nil || newInfo == nil {
		return "", fmt.Errorf("nil diff info")
	}

	out, err := vutils.GitDiff(oldInfo.String()+"\n", newInfo.String()+"\n", &vutils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
	if err != nil {
		return "", err
	}
	if len(out) == 0 && len(oldInfo.Symbols) == len(newInfo.Symbols) && len(oldInfo.CStrings) == len(newInfo.CStrings) {
		return "", nil
	}

	var b strings.Builder
	if oldInfo.Encrypted || newInfo.Encrypted {
		b.WriteString("> ⚠️ encrypted: structural diff only (sections/imports)\n\n")
	}
	if conf.Markdown {
		b.WriteString("```diff\n")
		b.WriteString(out)
	} else {
		b.WriteString(out)
	}

	// Symbols
	newSyms := vutils.Difference(newInfo.Symbols, oldInfo.Symbols)
	sort.Strings(newSyms)
	rmSyms := vutils.Difference(oldInfo.Symbols, newInfo.Symbols)
	sort.Strings(rmSyms)
	if len(newSyms) > 0 || len(rmSyms) > 0 {
		b.WriteString("Symbols:\n")
		for _, s := range newSyms {
			b.WriteString(fmt.Sprintf("+ %s\n", s))
		}
		for _, s := range rmSyms {
			b.WriteString(fmt.Sprintf("- %s\n", s))
		}
	}

	// Functions
	if conf.FuncStarts {
		printable := func(f types.Function, smap map[uint64]string) string {
			if sym, ok := smap[f.StartAddr]; ok {
				return sym
			}
			return fmt.Sprintf("sub_%x", f.StartAddr)
		}

		funcs1 := oldInfo.Starts
		funcs2 := newInfo.Starts
		n1, n2 := len(funcs1), len(funcs2)

		var fb strings.Builder
		appendLine := func(s string) {
			if fb.Len() == 0 {
				fb.WriteString("Functions:\n")
			}
			fb.WriteString(s)
		}

		if n1 == n2 {
			consecutiveMismatch := 0
			const maxMismatch = 5

			for i := range n1 {
				f1 := funcs1[i]
				f2 := funcs2[i]
				f1.Name = printable(f1, oldInfo.SymbolMap)
				f2.Name = printable(f2, newInfo.SymbolMap)

				if f1.Name != "" && f1.Name == f2.Name {
					sz1 := f1.EndAddr - f1.StartAddr
					sz2 := f2.EndAddr - f2.StartAddr
					if sz1 != sz2 {
						appendLine(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
					}
					consecutiveMismatch = 0
					continue
				}

				sz1 := f1.EndAddr - f1.StartAddr
				sz2 := f2.EndAddr - f2.StartAddr

				if sz1 == sz2 {
					consecutiveMismatch = 0
					continue
				}

				appendLine(fmt.Sprintf("~ %s -> %s : %d -> %d\n", f1.Name, f2.Name, sz1, sz2))
				consecutiveMismatch++

				if consecutiveMismatch >= maxMismatch {
					recovered := false
					const seekAhead = 6
					if i+seekAhead < n1 {
						matches := 0
						for k := 1; k <= seekAhead && i+k < n1; k++ {
							if (funcs1[i+k].EndAddr - funcs1[i+k].StartAddr) == (funcs2[i+k].EndAddr - funcs2[i+k].StartAddr) {
								matches++
								if matches >= 3 {
									recovered = true
									break
								}
							} else {
								matches = 0
							}
						}
					}
					if !recovered {
						fb.Reset()
						break
					}
				}
			}

			if fb.Len() > 0 {
				b.WriteString(fb.String())
			}
		} else {
			i, j := 0, 0
			consecutiveNoise := 0
			const noiseLimit = 6

			for i < n1 && j < n2 {
				f1 := funcs1[i]
				f2 := funcs2[j]
				f1.Name = printable(f1, oldInfo.SymbolMap)
				f2.Name = printable(f2, newInfo.SymbolMap)
				if f1.Name != "" && f1.Name == f2.Name {
					sz1 := f1.EndAddr - f1.StartAddr
					sz2 := f2.EndAddr - f2.StartAddr
					if sz1 != sz2 {
						appendLine(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
					}
					i++
					j++
					consecutiveNoise = 0
					continue
				}

				if (f1.EndAddr - f1.StartAddr) == (f2.EndAddr - f2.StartAddr) {
					i++
					j++
					consecutiveNoise = 0
					continue
				}

				if j+1 < n2 && (f1.EndAddr-f1.StartAddr) == (funcs2[j+1].EndAddr-funcs2[j+1].StartAddr) {
					appendLine(fmt.Sprintf("+ %s\n", f2.Name))
					j++
					consecutiveNoise++
				} else if i+1 < n1 && (funcs1[i+1].EndAddr-funcs1[i+1].StartAddr) == (f2.EndAddr-f2.StartAddr) {
					appendLine(fmt.Sprintf("- %s\n", f1.Name))
					i++
					consecutiveNoise++
				} else {
					consecutiveNoise++
				}

				if consecutiveNoise >= noiseLimit {
					fb.Reset()
					break
				}
			}

			if fb.Len() > 0 {
				b.WriteString(fb.String())
			}
		}
	}

	// CStrings
	if conf.CStrings {
		newStrs, rmStrs := diffNormalizedCStrings(oldInfo.CStrings, newInfo.CStrings)
		if len(newStrs) > 0 || len(rmStrs) > 0 {
			b.WriteString("CStrings:\n")
			for _, s := range newStrs {
				b.WriteString(fmt.Sprintf("+ %#v\n", s))
			}
			for _, s := range rmStrs {
				b.WriteString(fmt.Sprintf("- %#v\n", s))
			}
		}
	}

	if conf.Markdown {
		b.WriteString("\n```\n")
	}

	return b.String(), nil
}

// Generate computes New/Removed/Updated across two parallel
// path->DiffInfo maps. The caller owns extraction; this function only
// performs the set diff and per-pair formatting.
func (diff *MachoDiff) Generate(prev, next map[string]*DiffInfo, conf *DiffConfig) error {
	diff.New = vutils.Difference(slices.Collect(maps.Keys(next)), slices.Collect(maps.Keys(prev)))
	diff.Removed = vutils.Difference(slices.Collect(maps.Keys(prev)), slices.Collect(maps.Keys(next)))
	sort.Strings(diff.New)
	sort.Strings(diff.Removed)

	for _, currentFileKey := range slices.Sorted(maps.Keys(next)) {
		dat2 := next[currentFileKey]
		if dat1, ok := prev[currentFileKey]; ok {
			if dat2.Equal(*dat1) && !(dat1.Encrypted || dat2.Encrypted) {
				continue
			}
			formatted, err := FormatUpdatedDiff(dat1, dat2, conf)
			if err != nil {
				return err
			}
			if formatted == "" {
				continue
			}
			diff.Updated[currentFileKey] = formatted
		}
	}

	return nil
}
