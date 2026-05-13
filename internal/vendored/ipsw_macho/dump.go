// dump.go — fresh ipadiff code (NOT vendored). Produces deterministic
// text dumps of ObjC and Swift metadata for use as input to the textual
// diff engine. We deliberately do not vendor ipsw's class-dump / swift-dump
// machinery (~2300 LoC) because it pulls in dyld_shared_cache, tbd, chroma,
// and other deps we don't need. The go-macho library already exposes
// Verbose() / String() methods on the relevant types — we just walk them.
package vmacho

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types/objc"
)

// DumpObjC returns a stable text representation of all ObjC classes,
// categories, and protocols in m. Empty string if the binary has no ObjC.
// Wraps panics from the underlying parser into a soft error.
func DumpObjC(m *macho.File) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("objc parser panic: %v", r)
		}
	}()
	if !m.HasObjC() {
		return "", nil
	}

	var b strings.Builder

	if classes, e := m.GetObjCClasses(); e == nil {
		slices.SortStableFunc(classes, func(a, b objc.Class) int { return cmp.Compare(a.Name, b.Name) })
		for i := range classes {
			b.WriteString(classes[i].Verbose())
			b.WriteString("\n")
		}
	}

	if cats, e := m.GetObjCCategories(); e == nil {
		slices.SortStableFunc(cats, func(a, b objc.Category) int { return cmp.Compare(a.Name, b.Name) })
		for i := range cats {
			b.WriteString(cats[i].Verbose())
			b.WriteString("\n")
		}
	}

	if protos, e := m.GetObjCProtocols(); e == nil {
		slices.SortStableFunc(protos, func(a, b objc.Protocol) int { return cmp.Compare(a.Name, b.Name) })
		for i := range protos {
			b.WriteString(protos[i].Verbose())
			b.WriteString("\n")
		}
	}

	return b.String(), nil
}

// DumpSwift returns a stable text representation of Swift types and
// protocols in m. Empty string if the binary has no Swift.
// Wraps panics from the underlying parser into a soft error — the
// blacktop/go-macho swift parser is known to occasionally panic on
// adversarial binaries.
func DumpSwift(m *macho.File) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("swift parser panic: %v", r)
		}
	}()
	if !m.HasSwift() {
		return "", nil
	}

	var b strings.Builder

	if types, e := m.GetSwiftTypes(); e == nil {
		// Type has no exported Name field at top level; sort by Verbose() output
		// to keep output deterministic across runs.
		dumps := make([]string, 0, len(types))
		for _, t := range types {
			dumps = append(dumps, t.Verbose())
		}
		slices.Sort(dumps)
		for _, d := range dumps {
			b.WriteString(d)
			b.WriteString("\n")
		}
	}

	if protos, e := m.GetSwiftProtocols(); e == nil {
		dumps := make([]string, 0, len(protos))
		for _, p := range protos {
			dumps = append(dumps, fmt.Sprintf("%+v", p))
		}
		slices.Sort(dumps)
		for _, d := range dumps {
			b.WriteString(d)
			b.WriteString("\n")
		}
	}

	return b.String(), nil
}
