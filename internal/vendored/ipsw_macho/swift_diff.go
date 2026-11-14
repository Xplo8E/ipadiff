// swift_diff.go is vendored from
// github.com/blacktop/ipsw/internal/commands/macho/swift_diff.go at commit
// 27f1f0a5b30338fb6406e52e2c0d62f98f9ab16e. Adapted: the Swift wrapper type and
// its SwiftConfig (DSC cache, deps, demangle, addrs) are dropped — ipadiff
// diffs standalone IPA binaries with raw (mangled) names, matching the
// demangle-off default of the upstream swift-dump --diff command. Parsing is
// split from entity building so the Type.String() render calls (which hit the
// go-macho debug print leak, see dump.go) run under renderMu with stdout
// captured, while the two files' parsing stays parallel. DiffSwift replaces
// the (s *Swift) Diff method and returns the raw diff body without the
// "# Swift diff" header and code fence; unchanged groups are filtered.
// Original copyright belongs to blacktop; see internal/vendored/LICENSE.ipsw.
package vmacho

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"

	"github.com/blacktop/go-macho"
	stypes "github.com/blacktop/go-macho/types/swift"
)

// swiftSubAddr matches the address-derived placeholder names the Swift dumper
// gives unnamed functions. They move on every rebuild, so they are normalized
// away; the __ptrauth discriminator on the same line still identifies the method.
var swiftSubAddr = regexp.MustCompile(`\bsub_[0-9a-f]+`)

// swiftEntity is one Swift declaration (type, protocol, conformance or
// associated-type extension): a stable identity built from its typed
// descriptor, and every rendered line of its declaration as a member, so two
// builds can be compared regardless of layout or addresses.
type swiftEntity struct {
	key     string
	members map[string]struct{}
}

// swiftModel is the structural snapshot of a dylib's Swift metadata, keyed by
// declaration identity.
type swiftModel struct {
	types        map[string]*swiftEntity
	protocols    map[string]*swiftEntity
	conformances map[string]*swiftEntity
	assocTypes   map[string]*swiftEntity
}

// swiftRaw holds the parsed-but-unrendered Swift metadata slices. The Get*
// calls below do not render, so they are print-leak-free and may run outside
// the renderMu guard.
type swiftRaw struct {
	types        []stypes.Type
	protocols    []stypes.Protocol
	conformances []stypes.ConformanceDescriptor
	assocTypes   []stypes.AssociatedType
}

// swiftRawMetadata parses (without rendering) the Swift metadata of f.
// A missing Swift section yields empty slices, not an error.
func swiftRawMetadata(f *macho.File) (*swiftRaw, error) {
	if err := f.PreCache(); err != nil {
		return nil, fmt.Errorf("failed to precache swift fields/types: %w", err)
	}
	raw := &swiftRaw{}
	var err error
	raw.types, err = f.GetSwiftTypes()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift types: %w", err)
	}
	raw.protocols, err = f.GetSwiftProtocols()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift protocols: %w", err)
	}
	raw.conformances, err = f.GetSwiftProtocolConformances()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift protocol conformances: %w", err)
	}
	raw.assocTypes, err = f.GetSwiftAssociatedTypes()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift associated types: %w", err)
	}
	return raw, nil
}

// newSwiftEntity turns the dumper's rendered text for one declaration into
// members: every non-blank line minus closing braces and the "/* fields */"
// section labels, with body-opening braces and function addresses normalized.
// The header line stays a member so a changed superclass or generic signature
// shows as a changed line under a stable key.
func newSwiftEntity(key, rendered string) *swiftEntity {
	e := &swiftEntity{key: key, members: map[string]struct{}{}}
	for line := range strings.SplitSeq(rendered, "\n") {
		line = strings.TrimSpace(swiftSubAddr.ReplaceAllString(line, "sub_"))
		if line == "" || line == "}" {
			continue
		}
		if strings.HasPrefix(line, "/*") && strings.HasSuffix(line, "*/") {
			continue
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, " {}"), " {")
		e.members[line] = struct{}{}
	}
	return e
}

// addSwiftEntity files a declaration under its key, merging members when two
// declarations share one (opaque types have no name of their own).
func addSwiftEntity(into map[string]*swiftEntity, key, rendered string) {
	e := newSwiftEntity(key, rendered)
	if prev, ok := into[key]; ok {
		maps.Copy(prev.members, e.members)
		return
	}
	into[key] = e
}

// swiftTypeKey mirrors how the dumper prints a type's qualified name (up to
// two enclosing contexts) without its generic signature, so the key survives
// signature and superclass changes.
func swiftTypeKey(t stypes.Type) string {
	var parent string
	if t.Parent != nil {
		if t.Parent.Parent != nil && t.Parent.Parent.Name != "" {
			parent += t.Parent.Parent.Name + "."
		}
		if t.Parent.Name != "" {
			parent += t.Parent.Name + "."
		}
	}
	return fmt.Sprintf("%s %s%s", t.Kind, parent, t.Name)
}

func swiftProtocolKey(p stypes.Protocol) string {
	var parent string
	if p.Parent != nil && p.Parent.Name != "" {
		parent = p.Parent.Name + "."
	}
	return "protocol " + parent + p.Name
}

func swiftConformanceKey(c stypes.ConformanceDescriptor) string {
	var parent string
	if c.TypeRef != nil && c.TypeRef.Parent != nil && c.TypeRef.Parent.Name != "" {
		parent = c.TypeRef.Parent.Name + "."
	}
	var name string
	if c.TypeRef != nil {
		name = c.TypeRef.Name
	}
	return "protocol conformance " + parent + name + " : " + c.Protocol
}

func swiftAssociatedTypeKey(a stypes.AssociatedType) string {
	return "extension " + a.ConformingTypeName + ": " + a.ProtocolTypeName
}

// buildSwiftModel renders each parsed declaration into an entity. Rendering
// calls Type.String() etc., so callers must hold renderMu (see dump.go).
func buildSwiftModel(raw *swiftRaw) *swiftModel {
	m := &swiftModel{
		types:        map[string]*swiftEntity{},
		protocols:    map[string]*swiftEntity{},
		conformances: map[string]*swiftEntity{},
		assocTypes:   map[string]*swiftEntity{},
	}
	for _, t := range raw.types {
		addSwiftEntity(m.types, swiftTypeKey(t), t.String())
	}
	for _, p := range raw.protocols {
		addSwiftEntity(m.protocols, swiftProtocolKey(p), p.String())
	}
	for _, c := range raw.conformances {
		addSwiftEntity(m.conformances, swiftConformanceKey(c), c.String())
	}
	for _, a := range raw.assocTypes {
		addSwiftEntity(m.assocTypes, swiftAssociatedTypeKey(a), a.String())
	}
	return m
}

// DiffSwift structurally compares the Swift metadata of newM against oldM:
// added/removed/changed types, protocols, conformances and associated types,
// identity from the typed descriptors and members from rendered lines with
// function addresses normalized, so a rebuild with no source change is
// reported as no change. Returns "" when nothing changed. Panics from the
// underlying parser are converted to errors.
func DiffSwift(oldM, newM *macho.File) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("swift structural diff panic: %v", r)
		}
	}()
	oldRaw, err := swiftRawMetadata(oldM)
	if err != nil {
		return "", err
	}
	newRaw, err := swiftRawMetadata(newM)
	if err != nil {
		return "", err
	}

	// Entity building renders Swift declarations, which can trigger the
	// go-macho debug print leak; serialize under renderMu with stdout captured.
	renderMu.Lock()
	defer renderMu.Unlock()
	var oldModel, newModel *swiftModel
	swallowStdout(func() {
		oldModel = buildSwiftModel(oldRaw)
		newModel = buildSwiftModel(newRaw)
	})

	return joinDiffSections([]string{
		diffSwiftEntities("Types", oldModel.types, newModel.types),
		diffSwiftEntities("Protocols", oldModel.protocols, newModel.protocols),
		diffSwiftEntities("Conformances", oldModel.conformances, newModel.conformances),
		diffSwiftEntities("Associated Types", oldModel.assocTypes, newModel.assocTypes),
	}), nil
}

func diffSwiftEntities(title string, prev, next map[string]*swiftEntity) string {
	return diffSection(title, prev, next,
		func(e *swiftEntity) map[string]struct{} { return e.members },
		func(e *swiftEntity) string { return fmt.Sprintf("%s  (%d members)", e.key, len(e.members)) })
}
