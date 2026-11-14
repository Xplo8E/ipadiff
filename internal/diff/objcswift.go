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
	// The Swift/ObjC library renderers can leak debug prints to stdout (see
	// swallowStdoutDuring); run the whole phase behind the capture.
	d.ObjC = swallowStdoutDuring(func() map[string]string {
		return d.diffPerBinary("objc", vmacho.DiffObjC, vmacho.DumpObjC)
	})
	return nil
}

func (d *Diff) diffSwift() error {
	if d.cfg.NoSwift {
		return nil
	}
	d.Swift = swallowStdoutDuring(func() map[string]string {
		return d.diffPerBinary("swift", vmacho.DiffSwift, vmacho.DumpSwift)
	})
	return nil
}

// diffPerBinary structurally compares (compare) the ObjC/Swift metadata of
// every Mach-O present on BOTH sides, keyed by bundle-relative path so the
// renderer can co-locate each binary's metadata with its structural diff.
// If the structural pass fails (the metadata parsers are known to panic on
// adversarial binaries), it falls back to unified-diffing the deterministic
// textual dumps produced by textualDump. Encrypted binaries are skipped —
// their ObjC/Swift metadata lives in encrypted segments. A single bad
// binary cannot bring the whole section down.
type metadataDiffResult struct {
	rel      string
	diff     string
	warnings []string
}

func (d *Diff) diffPerBinary(section string, compare func(oldM, newM *macho.File) (string, error), textualDump func(*macho.File) (string, error)) map[string]string {
	keys := commonMachoKeys(d.Old, d.New)
	sort.Strings(keys)

	out := make(map[string]string)
	results := runStringWorkers(keys, d.cfg.Workers, func(rel string) metadataDiffResult {
		log.WithFields(log.Fields{
			"binary": rel,
		}).Debug("diffing metadata")
		result := metadataDiffResult{rel: rel}
		if d.Old.Files[rel].Encrypted || d.New.Files[rel].Encrypted {
			result.warnings = append(result.warnings, "encrypted binary skipped")
			return result
		}

		diff, err := compareMachoMetadata(d.Old, d.New, rel, compare)
		if err == nil {
			result.diff = diff
			return result
		}
		result.warnings = append(result.warnings, "structural metadata diff failed: "+err.Error())

		// Fall back to the textual dumps: lower fidelity, but resilient.
		diff, err = textualMetadataDiff(d.Old, d.New, rel, textualDump)
		if err != nil {
			result.warnings = append(result.warnings, "textual metadata dump failed: "+err.Error())
			return result
		}
		if diff != "" {
			result.warnings = append(result.warnings, "using textual metadata dump fallback")
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

// compareMachoMetadata opens rel on both sides and runs compare against the
// two open Mach-Os.
func compareMachoMetadata(o, n *bundle.Bundle, rel string, compare func(oldM, newM *macho.File) (string, error)) (string, error) {
	oldM, err := openMacho(filepath.Join(o.AppDir, rel))
	if err != nil {
		return "", err
	}
	newM, err := openMacho(filepath.Join(n.AppDir, rel))
	if err != nil {
		oldM.Close()
		return "", err
	}
	defer newM.Close()
	defer oldM.Close()
	return compare(oldM, newM)
}

// textualMetadataDiff is the pre-1.2 path: deterministic dumps of both sides,
// unified-diffed. Returns "" when either side has no metadata or the dumps
// match.
func textualMetadataDiff(o, n *bundle.Bundle, rel string, dump func(*macho.File) (string, error)) (string, error) {
	oldDump, err := dumpAt(o, rel, dump)
	if err != nil {
		return "", err
	}
	newDump, err := dumpAt(n, rel, dump)
	if err != nil {
		return "", err
	}
	if oldDump == "" && newDump == "" {
		return "", nil
	}
	if oldDump == newDump {
		return "", nil
	}
	diff, err := vutils.GitDiff(oldDump+"\n", newDump+"\n", &vutils.GitDiffConfig{Tool: "git"})
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(diff)) == 0 {
		return "", nil
	}
	return diff, nil
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
