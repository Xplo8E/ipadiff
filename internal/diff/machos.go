package diff

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
)

// diffMachos collects DiffInfo for the main app binary and every other
// Mach-O present in the bundle on both sides, then hands the two maps to
// the vendored engine.
func (d *Diff) diffMachos() error {
	conf := &vmacho.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  d.cfg.AllowList,
		BlockList:  d.cfg.BlockList,
		CStrings:   d.cfg.CStrings,
		FuncStarts: d.cfg.FuncStarts,
		Verbose:    d.cfg.Verbose,
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

// openMacho handles thin and fat binaries. For fat, picks the last arch
// (typically arm64e) to mirror ipsw's behavior.
func openMacho(path string) (*macho.File, error) {
	m, err := macho.Open(path)
	if err == nil {
		return m, nil
	}
	fat, fatErr := macho.OpenFat(path)
	if fatErr != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	last := fat.Arches[len(fat.Arches)-1].File
	// fat.Close() would also close the embedded files; transfer ownership
	// by NOT closing fat. The caller will Close() the returned macho.File.
	return last, nil
}
