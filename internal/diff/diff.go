// Package diff orchestrates the per-section comparison of two iOS app
// bundles and assembles a single Diff document. Section parsers all
// follow the same contract: log errors, never abort the whole run.
package diff

import (
	"errors"
	"runtime"
	"time"

	"github.com/apex/log"

	"github.com/Xplo8E/ipadiff/internal/bundle"
	vmacho "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_macho"
)

// Config is the user-facing knob set for a diff run.
type Config struct {
	Title  string
	OldIPA string
	NewIPA string
	Output string // empty => stdout

	CStrings      bool // diff cstrings
	FuncStarts    bool // diff function-starts size deltas
	Entitlements  bool
	NoObjC        bool
	NoSwift       bool
	SkipResources bool

	AllowList []string // glob filter on Mach-O section names (Seg.Section)
	BlockList []string

	HermesTool    string        // optional path to hermes-diff sidecar
	HermesTimeout time.Duration // per-bundle sidecar timeout; zero => default

	Workers int
	Verbose bool
}

// DefaultOutputDir is the directory used when Config.Output is empty.
// Layout mirrors ipsw diff: <cwd>/ipa-diffs/<bundleID>_<oldVer>_<newVer>/.
const DefaultOutputDir = "ipa-diffs"

// DefaultHermesTimeout bounds a single hermes-diff sidecar run. Hermes parsing
// can be expensive, but an unbounded subprocess can wedge the whole report.
const DefaultHermesTimeout = 15 * time.Minute

// Defaults sets the sensible v1 defaults for every "on by default" field.
// Call this before applying CLI overrides.
func (c *Config) Defaults() {
	c.CStrings = true
	c.FuncStarts = true
	c.Entitlements = true
	if c.Output == "" {
		c.Output = DefaultOutputDir
	}
	if c.Workers <= 0 {
		c.Workers = runtime.GOMAXPROCS(0)
	}
	if c.HermesTimeout <= 0 {
		c.HermesTimeout = DefaultHermesTimeout
	}
}

// PlistDiff records new / removed / updated plists (by bundle-relative path).
type PlistDiff struct {
	New     []string          `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"updated,omitempty"`
}

// ResourcesDiff splits non-plist, non-macho file diffs by treatment.
type ResourcesDiff struct {
	New      []string          `json:"new,omitempty"`
	Removed  []string          `json:"removed,omitempty"`
	Updated  map[string]string `json:"updated,omitempty"`   // text diffs
	SizeOnly map[string]string `json:"size_only,omitempty"` // binary "size: X -> Y" deltas
}

// HermesDiff records React Native Hermes bytecode bundle changes.
type HermesDiff struct {
	New     []string                     `json:"new,omitempty"`
	Removed []string                     `json:"removed,omitempty"`
	Updated map[string]*HermesBundleDiff `json:"updated,omitempty"`
}

// HermesBundleDiff is populated by the renderer after the hermes-diff sidecar
// writes its artifact tree.
type HermesBundleDiff struct {
	Path         string `json:"path,omitempty"`
	OutputDir    string `json:"output_dir,omitempty"`
	OldFunctions int    `json:"old_functions,omitempty"`
	NewFunctions int    `json:"new_functions,omitempty"`
	Exact        int    `json:"exact,omitempty"`
	Partial      int    `json:"partial,omitempty"`
	New          int    `json:"new,omitempty"`
	Deleted      int    `json:"deleted,omitempty"`
	Warning      string `json:"warning,omitempty"`

	oldInput string
	newInput string
}

// FileTreeDiff captures top-level file-tree set differences across the bundle.
type FileTreeDiff struct {
	New     []string `json:"new,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// Diff is the assembled report.
type Diff struct {
	Title string `json:"title,omitempty"`

	Old *bundle.Bundle `json:"-"`
	New *bundle.Bundle `json:"-"`

	Machos *vmacho.MachoDiff `json:"machos,omitempty"`
	// ObjC and Swift are keyed by bundle-relative path so the renderer
	// can co-locate each binary's metadata diff with its structural diff.
	ObjC         map[string]string `json:"objc,omitempty"`
	Swift        map[string]string `json:"swift,omitempty"`
	Plists       *PlistDiff        `json:"plists,omitempty"`
	Ents         string            `json:"entitlements,omitempty"`
	Provisioning string            `json:"provisioning,omitempty"`
	Hermes       *HermesDiff       `json:"hermes,omitempty"`
	Resources    *ResourcesDiff    `json:"resources,omitempty"`
	FileTree     *FileTreeDiff     `json:"file_tree,omitempty"`
	Warnings     []Warning         `json:"warnings,omitempty"`

	// DiffInfo snapshots are retained so the renderer can emit neutral
	// metadata for each binary without re-parsing the raw ```diff body.
	mainOld  *vmacho.DiffInfo
	mainNew  *vmacho.DiffInfo
	oldInfos map[string]*vmacho.DiffInfo
	newInfos map[string]*vmacho.DiffInfo

	cfg *Config
}

// New constructs a Diff bound to cfg. Call Run to populate it.
func New(cfg *Config) *Diff {
	return &Diff{cfg: cfg}
}

// Close releases any temporary state retained after Run. It is safe to call
// multiple times. WriteFiles cleans Hermes snapshots after rendering, but
// library callers that only inspect Diff or stream WriteMarkdown should call
// Close when done.
func (d *Diff) Close() error {
	if d == nil {
		return nil
	}
	d.cleanupHermesInputs()
	var err error
	if d.Old != nil {
		err = errors.Join(err, d.Old.Close())
	}
	if d.New != nil {
		err = errors.Join(err, d.New.Close())
	}
	return err
}

// Run is the top-level entry point. It loads both bundles, then invokes
// each section parser in order, logging (but never returning) per-section
// errors so a single bad section doesn't abort the rest of the run.
func (d *Diff) Run() error {
	var err error
	log.WithField("ipa", d.cfg.OldIPA).Info("loading 'old' IPA")
	if d.Old, err = bundle.Load(d.cfg.OldIPA); err != nil {
		return err
	}
	log.WithField("ipa", d.cfg.NewIPA).Info("loading 'new' IPA")
	if d.New, err = bundle.Load(d.cfg.NewIPA); err != nil {
		d.Old.Close()
		return err
	}
	defer d.Old.Close()
	defer d.New.Close()

	if d.Title == "" {
		d.Title = defaultTitle(d.Old, d.New)
	}

	if d.Old.MainEncrypted {
		log.Warnf("'old' main binary is FairPlay-encrypted; symbol/cstring/objc/swift skipped for it")
		d.addWarning("machos", d.Old.ExeName, "old main binary is FairPlay-encrypted; using structural diff only")
	}
	if d.New.MainEncrypted {
		log.Warnf("'new' main binary is FairPlay-encrypted; symbol/cstring/objc/swift skipped for it")
		d.addWarning("machos", d.New.ExeName, "new main binary is FairPlay-encrypted; using structural diff only")
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"machos", d.diffMachos},
		{"objc", d.diffObjC},
		{"swift", d.diffSwift},
		{"plists", d.diffPlists},
		{"entitlements", d.diffEntitlements},
		{"provisioning", d.diffProvisioning},
		{"hermes", d.diffHermes},
		{"resources", d.diffResources},
		{"filetree", d.diffFileTree},
	}
	for _, s := range steps {
		log.WithField("section", s.name).Info("diffing")
		t := time.Now()
		if err := s.fn(); err != nil {
			log.WithError(err).Warnf("section %s failed", s.name)
			d.addWarning(s.name, "", err.Error())
			continue
		}
		log.WithFields(log.Fields{
			"section": s.name,
			"took":    time.Since(t).Truncate(time.Millisecond),
		}).Info("done")
	}
	d.sortWarnings()
	return nil
}

func defaultTitle(o, n *bundle.Bundle) string {
	switch {
	case o.BundleID != "" && (o.Version != "" || n.Version != ""):
		return o.BundleID + " " + o.Version + " (" + o.Build + ") .vs " + n.Version + " (" + n.Build + ")"
	case o.BundleID != "":
		return o.BundleID
	}
	return "ipadiff"
}
