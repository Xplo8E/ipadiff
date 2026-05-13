package diff

import (
	"fmt"
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
	d.ObjC = diffPerBinary(d.Old, d.New, vmacho.DumpObjC)
	return nil
}

func (d *Diff) diffSwift() error {
	if d.cfg.NoSwift {
		return nil
	}
	d.Swift = diffPerBinary(d.Old, d.New, vmacho.DumpSwift)
	return nil
}

// diffPerBinary computes a textual dump for every Mach-O present on
// BOTH sides, then unified-diffs the two dumps. Encrypted binaries are
// skipped — their ObjC/Swift sections live in encrypted segments.
// The dumper itself recovers from panics (see vmacho/dump.go) so a single
// bad binary cannot bring the whole section down.
func diffPerBinary(oldB, newB *bundle.Bundle, dump func(*macho.File) (string, error)) string {
	keys := commonMachoKeys(oldB, newB)
	sort.Strings(keys)

	var b strings.Builder
	for i, rel := range keys {
		log.WithFields(log.Fields{
			"binary": rel,
			"i":      fmt.Sprintf("%d/%d", i+1, len(keys)),
		}).Debug("dumping")
		if oldB.Files[rel].Encrypted || newB.Files[rel].Encrypted {
			continue
		}

		oldDump, _ := dumpAt(oldB, rel, dump)
		newDump, _ := dumpAt(newB, rel, dump)
		if oldDump == "" && newDump == "" {
			continue
		}
		if oldDump == newDump {
			continue
		}

		out, err := vutils.GitDiff(oldDump+"\n", newDump+"\n", &vutils.GitDiffConfig{Tool: "git"})
		if err != nil || len(strings.TrimSpace(out)) == 0 {
			continue
		}
		// Collapsed per-binary block — the diff body inside <details> stays
		// off-screen until the user expands it.
		fmt.Fprintf(&b, "<details>\n<summary><code>%s</code></summary>\n\n```diff\n%s\n```\n\n</details>\n\n", rel, out)
	}
	return b.String()
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
