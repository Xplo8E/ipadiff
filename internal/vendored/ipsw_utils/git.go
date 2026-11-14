// Vendored from github.com/blacktop/ipsw/internal/utils/git.go at commit
// 27f1f0a5b30338fb6406e52e2c0d62f98f9ab16e. Pruned: removed GitClone /
// GitRefresh / ClangFormat / delta / chroma-color paths and the go-git and
// execabs dependencies; upstream spawn.Command is replaced with os/exec.
// v1 uses git+diffmatchpatch only, with upstream's exit-code-1 handling.
package vutils

import (
	"errors"
	"fmt"
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
	if src == dst {
		return "", nil
	}
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

func createGoDiff(src, dst string, conf *GitDiffConfig) (string, error) {
	dmp := diffmatchpatch.New()

	diffs := dmp.DiffMain(src, dst, false)
	if len(diffs) > 2 {
		diffs = dmp.DiffCleanupSemanticLossless(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}

	if len(diffs) == 1 && diffs[0].Type == diffmatchpatch.DiffEqual {
		return "", nil
	}

	if conf.Color {
		return dmp.DiffPrettyText(diffs), nil
	}
	var out strings.Builder
	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffDelete:
			fmt.Fprintf(&out, "[-%s-]", diff.Text)
		case diffmatchpatch.DiffInsert:
			fmt.Fprintf(&out, "{+%s+}", diff.Text)
		default:
			out.WriteString(diff.Text)
		}
	}
	return out.String(), nil
}

// createGitDiffPatch renders a unified diff by shelling out to the host git
// binary. The output bytes (hunk boundaries, context-line algorithm) depend on
// the installed git version.
func createGitDiffPatch(src, dst string, _ *GitDiffConfig) (string, error) {
	tmpSrc, err := writeDiffInput("src", src)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpSrc)

	tmpDst, err := writeDiffInput("dst", dst)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpDst)

	out, err := runDiffTool(exec.Command("git", "diff", "--no-color", "--no-index", tmpSrc, tmpDst))
	if err != nil {
		return "", err
	}
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

// writeDiffInput writes content to a closed temp file for an external diff
// tool and returns its path. The caller removes the file.
func writeDiffInput(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	_, writeErr := f.WriteString(content)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write diff input %s: %w", f.Name(), err)
	}
	return f.Name(), nil
}

// runDiffTool returns the stdout of an external diff command. Diff tools exit 1
// when the inputs differ, so only other failures are errors.
func runDiffTool(cmd *exec.Cmd) (string, error) {
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return "", fmt.Errorf("failed to run %s: %w", cmd.Args[0], err)
	}
	if exitErr.ExitCode() == 1 {
		return string(out), nil
	}
	return "", fmt.Errorf("%s failed: %w: %s", cmd.Args[0], err, strings.TrimSpace(string(exitErr.Stderr)))
}
