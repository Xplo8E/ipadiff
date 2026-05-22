package diff

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

func (d *Diff) diffObjC() error {
	if d.cfg.NoObjC {
		return nil
	}
	d.ObjC = d.diffPerBinary("objc", vmacho.DumpObjC)
	return nil
}

func (d *Diff) diffSwift() error {
	if d.cfg.NoSwift {
		return nil
	}
	d.Swift = d.diffPerBinary("swift", vmacho.DumpSwift)
	return nil
}

// diffPerBinary computes a textual dump for every Mach-O present on BOTH
// sides, then unified-diffs the two dumps. Returns a map keyed by
// bundle-relative path so the renderer can co-locate each binary's
// metadata with its structural diff. Encrypted binaries are skipped —
// their ObjC/Swift sections live in encrypted segments. The dumper
// itself recovers from panics (see vmacho/dump.go) so a single bad
// binary cannot bring the whole section down.
type metadataDiffResult struct {
	rel      string
	diff     string
	warnings []string
}

func (d *Diff) diffPerBinary(section string, dump func(*macho.File) (string, error)) map[string]string {
	keys := commonMachoKeys(d.Old, d.New)
	sort.Strings(keys)

	out := make(map[string]string)
	results := runStringWorkers(keys, d.cfg.Workers, func(rel string) metadataDiffResult {
		log.WithFields(log.Fields{
			"binary": rel,
		}).Debug("dumping")
		result := metadataDiffResult{rel: rel}
		if d.Old.Files[rel].Encrypted || d.New.Files[rel].Encrypted {
			result.warnings = append(result.warnings, "encrypted binary skipped")
			return result
		}

		oldDump, err := dumpAt(d.Old, rel, dump)
		if err != nil {
			result.warnings = append(result.warnings, "old dump failed: "+err.Error())
			return result
		}
		newDump, err := dumpAt(d.New, rel, dump)
		if err != nil {
			result.warnings = append(result.warnings, "new dump failed: "+err.Error())
			return result
		}
		if oldDump == "" && newDump == "" {
			return result
		}
		if oldDump == newDump {
			return result
		}

		diff, err := vutils.GitDiff(oldDump+"\n", newDump+"\n", &vutils.GitDiffConfig{Tool: "git"})
		if err != nil || len(strings.TrimSpace(diff)) == 0 {
			if err != nil {
				result.warnings = append(result.warnings, "diff failed: "+err.Error())
			}
			return result
		}
		result.diff = diff
		return result
	})
	for _, result := range results {
		for _, warning := range result.warnings {
			d.addWarning(section, result.rel, warning)
		}
		if result.diff != "" {
			out[result.rel] = result.diff
		}
	}
	return out
}

func commonMachoKeys(o, n *bundle.Bundle) []string {
	collect := func(b *bundle.Bundle) []string {
		return append([]string{b.ExeName}, b.Frameworks...)
	}
	oset := make(map[string]struct{})
	for _, r := range collect(o) {
		oset[r] = struct{}{}
	}
	var keys []string
	for _, r := range collect(n) {
		if _, ok := oset[r]; ok {
			keys = append(keys, r)
		}
	}
	return keys
}

func dumpAt(b *bundle.Bundle, rel string, dump func(*macho.File) (string, error)) (string, error) {
	full := filepath.Join(b.AppDir, rel)
	m, err := openMacho(full)
	if err != nil {
		return "", err
	}
	defer m.Close()
	return dump(m)
}
