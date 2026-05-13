package diff

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	"github.com/Xplo8E/ipadiff/internal/parsers"
	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// diffProvisioning reads embedded.mobileprovision (CMS-signed plist) on
// both sides, extracts the inner XML plist, canonicalizes it, and emits a
// unified diff. Missing-on-both is a no-op.
func (d *Diff) diffProvisioning() error {
	a := readProv(d.Old)
	b := readProv(d.New)

	if a == "" && b == "" {
		return nil
	}
	if a == b {
		return nil
	}

	out, err := vutils.GitDiff(a+"\n", b+"\n", &vutils.GitDiffConfig{Tool: "git"})
	if err != nil {
		return err
	}
	if out == "" {
		return nil
	}
	d.Provisioning = fmt.Sprintf("```diff\n%s\n```", out)
	return nil
}

func readProv(b *bundle.Bundle) string {
	path := filepath.Join(b.AppDir, "embedded.mobileprovision")
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	canon, err := parsers.ReadMobileProvision(path)
	if err != nil {
		return ""
	}
	return string(canon)
}
