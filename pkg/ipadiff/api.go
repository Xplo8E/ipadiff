// Package ipadiff is the public library entry point for the ipadiff tool.
// Library users get the same orchestrator as the CLI plus a single
// Markdown renderer. Higher-level callers can also inspect the *diff.Diff
// directly if they want to render their own output.
package ipadiff

import (
	"io"

	"github.com/Xplo8E/ipadiff/internal/diff"
)

// Version is the released ipadiff version. Bump on every tagged release.
const Version = "1.0.0"

// Config is re-exported for library convenience.
type Config = diff.Config

// Diff is re-exported so callers can inspect populated fields.
type Diff = diff.Diff

// Run loads both IPAs, populates every section of the Diff, and returns it.
// Callers can then write Markdown via d.Markdown(w) or inspect fields directly.
// Call d.Close() when done if you keep the returned Diff.
func Run(cfg *Config) (*Diff, error) {
	cfg.Defaults()
	d := diff.New(cfg)
	if err := d.Run(); err != nil {
		return nil, err
	}
	return d, nil
}

// RunAndWrite is the one-shot helper: Run + render via d.Markdown(w).
// When cfg.Output is non-empty, the multi-file layout is written there.
func RunAndWrite(cfg *Config, w io.Writer) error {
	d, err := Run(cfg)
	if err != nil {
		return err
	}
	return d.Markdown(w)
}
