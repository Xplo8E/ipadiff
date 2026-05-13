// Package vent is vendored (and trimmed) from
// github.com/blacktop/ipsw/internal/commands/ent at commit
// d8aec666867becf32f904a1d6338f9e23efd55c1. Only DiffDatabases is kept;
// the color/non-Markdown branches and the chroma highlighter are dropped
// because ipadiff only renders Markdown. Original copyright belongs to
// blacktop; see internal/vendored/LICENSE.ipsw.
package vent

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"sort"

	vutils "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_utils"
)

// DiffDatabases compares two relpath->entitlement-xml maps and returns a
// Markdown-formatted diff. Identical entries are skipped; new entries (only
// in db2) are emitted as a "🆕" section with the full XML; updated entries
// show a unified diff.
func DiffDatabases(db1, db2 map[string]string) (string, error) {
	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	var files []string
	for f := range db2 {
		files = append(files, f)
	}
	sort.Strings(files)

	found := false
	for _, f2 := range files {
		e2 := db2[f2]
		if e1, ok := db1[f2]; ok {
			out, err := vutils.GitDiff(e1+"\n", e2+"\n", &vutils.GitDiffConfig{Color: false, Tool: "git"})
			if err != nil {
				return "", err
			}
			if len(out) == 0 {
				continue
			}
			found = true
			buf.WriteString(fmt.Sprintf("### %s\n\n> `%s`\n\n", filepath.Base(f2), f2))
			buf.WriteString("```diff\n" + out + "\n```\n")
		} else {
			found = true
			buf.WriteString(fmt.Sprintf("\n### 🆕 %s\n\n> `%s`\n\n", filepath.Base(f2), f2))
			if len(e2) == 0 {
				buf.WriteString("- No entitlements *(yet)*\n")
			} else {
				buf.WriteString("```xml\n" + e2 + "\n```\n")
			}
		}
	}

	if !found {
		buf.WriteString("- No differences found\n")
	}

	buf.Flush()
	return dat.String(), nil
}
