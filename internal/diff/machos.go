package diff

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
)

// diffMachos collects DiffInfo for the main app binary and every framework
// on both sides, then hands the two maps to the vendored engine.
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

	prev := collectMachos(d.Old, conf)
	next := collectMachos(d.New, conf)

	// Snapshot main-exe DiffInfo on each side so the intel renderer can
	// reuse it later (it would otherwise be GC'd after Generate).
	d.mainOld = prev[d.Old.ExeName]
	d.mainNew = next[d.New.ExeName]

	d.Machos = &vmacho.MachoDiff{Updated: make(map[string]string)}
	return d.Machos.Generate(prev, next, conf)
}

// collectMachos walks (main exe + frameworks) and produces a DiffInfo map
// keyed by bundle-relative path. Encrypted binaries get a degraded info
// (sections + imports only) so we can still report structural changes.
func collectMachos(b *bundle.Bundle, conf *vmacho.DiffConfig) map[string]*vmacho.DiffInfo {
	out := make(map[string]*vmacho.DiffInfo)

	targets := append([]string{b.ExeName}, b.Frameworks...)
	log.WithField("count", len(targets)).Debug("collecting macho DiffInfo")
	for i, rel := range targets {
		log.WithField("binary", rel).Debugf("[%d/%d] generating diff info", i+1, len(targets))
		info := buildInfo(b, rel, conf)
		if info == nil {
			continue
		}
		out[rel] = info
	}
	return out
}

func buildInfo(b *bundle.Bundle, rel string, conf *vmacho.DiffConfig) *vmacho.DiffInfo {
	full := filepath.Join(b.AppDir, rel)
	m, err := openMacho(full)
	if err != nil {
		log.WithError(err).Debugf("skip macho %s: %v", rel, err)
		return nil
	}
	defer m.Close()

	encrypted := b.Files[rel].Encrypted
	if encrypted {
		return vmacho.GenerateDiffInfoDegraded(m, conf)
	}
	return vmacho.GenerateDiffInfo(m, conf)
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
