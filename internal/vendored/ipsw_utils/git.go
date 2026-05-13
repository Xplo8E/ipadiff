// Vendored from github.com/blacktop/ipsw/internal/utils/git.go at commit
// d8aec666867becf32f904a1d6338f9e23efd55c1. Pruned: removed GitClone /
// GitRefresh / ClangFormat / delta / chroma-color paths. v1 uses git+diffmatchpatch only.
package vutils

import (
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

type GitDiffConfig struct {
	Tool  string
	Color bool // currently unused in v1 (we render Markdown only)
}

// GitDiff returns a unified-diff-style patch between src and dst.
// Backend preference: explicit Tool ("git"/"go") > git on PATH > pure-Go diffmatchpatch.
func GitDiff(src, dst string, conf *GitDiffConfig) (string, error) {
	switch conf.Tool {
	case "git":
		return createGitDiffPatch(src, dst, conf)
	case "go":
		return createGoDiff(src, dst, conf)
	default:
		if _, err := exec.LookPath("git"); err == nil {
			return createGitDiffPatch(src, dst, conf)
		}
		return createGoDiff(src, dst, conf)
	}
}

func createGoDiff(src, dst string, _ *GitDiffConfig) (string, error) {
	dmp := diffmatchpatch.New()

	diffs := dmp.DiffMain(src, dst, false)
	if len(diffs) > 2 {
		diffs = dmp.DiffCleanupSemanticLossless(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}

	if len(diffs) == 1 && diffs[0].Type == diffmatchpatch.DiffEqual {
		return "", nil
	}

	return dmp.DiffPrettyText(diffs), nil
}

func createGitDiffPatch(src, dst string, _ *GitDiffConfig) (string, error) {
	tmpSrc, err := os.CreateTemp("", "src")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpSrc.Name())
	_ = os.WriteFile(tmpSrc.Name(), []byte(src), 0644)

	tmpDst, err := os.CreateTemp("", "dst")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpDst.Name())
	_ = os.WriteFile(tmpDst.Name(), []byte(dst), 0644)

	cmd := exec.Command("git", "diff", "--no-index", tmpSrc.Name(), tmpDst.Name())
	dat, _ := cmd.CombinedOutput()

	out := string(dat)
	// strip the first 4 lines of the patch header
	_, out, _ = strings.Cut(out, "\n")
	_, out, _ = strings.Cut(out, "\n")
	_, out, _ = strings.Cut(out, "\n")
	_, out, _ = strings.Cut(out, "\n")
	// strip the @@ hunk markers
	re := regexp.MustCompile("(?m)^@@ .*$")
	out = re.ReplaceAllString(out, "")
	return out, nil
}
