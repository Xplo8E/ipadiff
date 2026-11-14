package diff

import (
	"cmp"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
)

// diffMachos collects DiffInfo for the main app binary and every other
// Mach-O present in the bundle on both sides, then hands the two maps to
// the vendored engine.
func (d *Diff) diffMachos() error {
	conf := &vmacho.DiffConfig{
		Markdown:              true,
		Color:                 false,
		DiffTool:              "git",
		AllowList:             d.cfg.AllowList,
		BlockList:             d.cfg.BlockList,
		CStrings:              d.cfg.CStrings,
		FuncStarts:            d.cfg.FuncStarts,
		IgnoreBuildTimestamps: d.cfg.IgnoreBuildTimestamps,
		IgnoreLoadCommands:    d.cfg.IgnoreLoadCommands,
		Verbose:               d.cfg.Verbose,
	}

	prev := d.collectMachos("old", d.Old, conf)
	next := d.collectMachos("new", d.New, conf)
	d.oldInfos = prev
	d.newInfos = next

	// Snapshot main-exe DiffInfo on each side for compatibility with
	// callers that inspect the populated Diff directly.
	d.mainOld = prev[d.Old.ExeName]
	d.mainNew = next[d.New.ExeName]

	d.Machos = &vmacho.MachoDiff{Updated: make(map[string]string)}
	return d.Machos.Generate(prev, next, conf)
}

// collectMachos walks the main executable plus every non-main Mach-O in the
// bundle and produces a DiffInfo map keyed by bundle-relative path.
// Encrypted binaries get a degraded info (sections + imports only) so we can
// still report structural changes.
type machoInfoResult struct {
	rel     string
	info    *vmacho.DiffInfo
	warning string
}

func (d *Diff) collectMachos(side string, b *bundle.Bundle, conf *vmacho.DiffConfig) map[string]*vmacho.DiffInfo {
	out := make(map[string]*vmacho.DiffInfo)

	targets := append([]string{b.ExeName}, b.Frameworks...)
	sort.Strings(targets)
	log.WithField("count", len(targets)).Debug("collecting macho DiffInfo")
	results := runStringWorkers(targets, d.cfg.Workers, func(rel string) machoInfoResult {
		log.WithField("binary", rel).Debug("generating diff info")
		info, warning := buildInfo(b, rel, conf)
		return machoInfoResult{rel: rel, info: info, warning: warning}
	})
	for _, result := range results {
		if result.warning != "" {
			d.addWarning("machos", result.rel, side+": "+result.warning)
		}
		if result.info != nil {
			out[result.rel] = result.info
		}
	}
	return out
}

func buildInfo(b *bundle.Bundle, rel string, conf *vmacho.DiffConfig) (*vmacho.DiffInfo, string) {
	full := filepath.Join(b.AppDir, rel)
	m, err := openMacho(full)
	if err != nil {
		log.WithError(err).Debugf("skip macho %s: %v", rel, err)
		return nil, fmt.Sprintf("skipped Mach-O: %v", err)
	}
	defer m.Close()

	encrypted := b.Files[rel].Encrypted
	if encrypted {
		return vmacho.GenerateDiffInfoDegraded(m, conf), "FairPlay-encrypted; using structural diff only"
	}
	return vmacho.GenerateDiffInfo(m, conf), ""
}

// openMacho handles thin and fat binaries. For fat, picks the slice whose
// metadata represents the binary (see preferredSlice) instead of blindly
// taking the last arch.
func openMacho(path string) (*macho.File, error) {
	ms, _, err := openSlices(path)
	if err != nil {
		return nil, err
	}
	// Transfer ownership to the returned slice: closing the fat file would
	// close every slice, so the caller closes the picked slice directly.
	// (Same trick the pre-1.2 openMacho used for the last arch.)
	return preferredSlice(path, ms), nil
}

// openSlices returns every Mach-O slice in path (a single slice for thin
// files). The returned close func releases the underlying file(s); the slice
// pointers are only valid before it runs.
// Ported from ipsw internal/commands/ent/slices.go (vendored-update).
func openSlices(path string) ([]*macho.File, func(), error) {
	fat, err := macho.OpenFat(path)
	if err == nil {
		ms := make([]*macho.File, 0, len(fat.Arches))
		for _, arch := range fat.Arches {
			ms = append(ms, arch.File)
		}
		return ms, func() { fat.Close() }, nil
	}
	if errors.Is(err, macho.ErrNotFat) {
		m, openErr := macho.Open(path)
		if openErr != nil {
			return nil, nil, fmt.Errorf("open %s: %w", path, openErr)
		}
		return []*macho.File{m}, func() { m.Close() }, nil
	}
	return nil, nil, fmt.Errorf("open fat %s: %w", path, err)
}

// preferredSlice picks the slice whose entitlements and metadata represent a
// universal binary: ARM64e_X1, then ARM64_X1, then ARM64e, then other ARM64,
// then any other CPU; equal ranks prefer the larger CPU, then the full
// subtype (including feature bits). The slice list must be nonempty with
// unique CPU/subtype pairs, as in a FAT file. A warning is logged when
// entitlements or launch constraints disagree between slices.
// Ported from ipsw internal/commands/ent/slices.go (vendored-update).
func preferredSlice(path string, ms []*macho.File) *macho.File {
	best := ms[0]
	for _, m := range ms[1:] {
		if cmp.Or(cmp.Compare(sliceRank(m), sliceRank(best)),
			cmp.Compare(m.CPU, best.CPU), cmp.Compare(m.SubCPU, best.SubCPU)) > 0 {
			best = m
		}
	}
	want := sliceEntitlements(best)
	for _, m := range ms {
		if m != best && sliceEntitlements(m) != want {
			log.Warnf("entitlements differ between %s and %s slices of %s; using %s",
				sliceName(m), sliceName(best), path, sliceName(best))
		}
	}
	return best
}

// sliceRank orders slices by ABI preference; higher wins.
func sliceRank(m *macho.File) int {
	if m.CPU != types.CPUArm64 {
		return 0
	}
	switch {
	case m.SubCPU.HasArm64X1() && m.SubCPU.HasArm64E():
		return 4
	case m.SubCPU.HasArm64X1():
		return 3
	case m.SubCPU.HasArm64E():
		return 2
	default:
		return 1
	}
}

func sliceName(m *macho.File) string {
	return m.SubCPU.String(m.CPU)
}

type sliceEntitlementData struct {
	entitlements              string
	self, parent, responsible string
}

func sliceEntitlements(m *macho.File) sliceEntitlementData {
	cs := m.CodeSignature()
	if cs == nil {
		return sliceEntitlementData{}
	}
	raw := cs.Entitlements
	if raw == "" {
		raw = string(cs.EntitlementsDER)
	}
	return sliceEntitlementData{
		entitlements: raw,
		self:         string(cs.LaunchConstraintsSelf),
		parent:       string(cs.LaunchConstraintsParent),
		responsible:  string(cs.LaunchConstraintsResponsible),
	}
}
