package diff

import (
	"path/filepath"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	"github.com/Xplo8E/ipadiff/internal/parsers"
	vent "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_ent"
)

func (d *Diff) diffEntitlements() error {
	if !d.cfg.Entitlements {
		return nil
	}
	oldDB := buildEntDB(d.Old)
	newDB := buildEntDB(d.New)
	out, err := vent.DiffDatabases(oldDB, newDB)
	if err != nil {
		return err
	}
	d.Ents = out
	return nil
}

// buildEntDB walks (main + frameworks) and pulls entitlements+launch-constraints
// out of each Mach-O's code signature. Returns map[bundle-relpath]combined-text.
func buildEntDB(b *bundle.Bundle) map[string]string {
	db := make(map[string]string)
	targets := append([]string{b.ExeName}, b.Frameworks...)
	for _, rel := range targets {
		full := filepath.Join(b.AppDir, rel)
		m, err := openMacho(full)
		if err != nil {
			continue
		}
		ent := parsers.ReadFromMacho(m)
		m.Close()

		combined := ent.Combined()
		if combined == "" {
			continue
		}
		db[rel] = combined
	}
	return db
}
