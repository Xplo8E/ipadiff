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
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types/objc"
	stypes "github.com/blacktop/go-macho/types/swift"
)

// renderMu serializes Swift type rendering across workers. go-macho
// v1.1.296's Swift Type.dump prints stray debug lines to the process stdout
// when a class or struct generic requirement hits the default branch
// (types/swift/types.go: `fmt.Println(req.Flags.String())`); the bug is also
// on go-macho master as of 2026-11-14. Parsing (GetSwiftTypes etc.) does not
// render, so it stays parallel; only the fast rendering loop runs under this
// lock with stdout briefly redirected. Drop this mechanism when a go-macho
// release removes the debug prints.
var renderMu sync.Mutex

// swallowStdout runs fn while capturing and discarding everything written to
// the process stdout. Callers must hold renderMu. apex/log writes to stderr
// and the Markdown report is rendered after all sections complete, so nothing
// legitimate writes to stdout during library rendering. If the pipe cannot be
// created, fn still runs and any leak is accepted rather than failing the dump.
func swallowStdout(fn func()) {
	realStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		fn()
		return
	}
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(done)
	}()
	func() {
		defer func() {
			os.Stdout = realStdout
			_ = w.Close()
			<-done
			_ = r.Close()
		}()
		fn()
	}()
}

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

	// Parse unguarded (no rendering happens here) so the per-binary workers
	// stay parallel, then render under the lock with stdout captured.
	var swiftTypes []stypes.Type
	var swiftProtos []stypes.Protocol
	if types, e := m.GetSwiftTypes(); e == nil {
		swiftTypes = types
	}
	if protos, e := m.GetSwiftProtocols(); e == nil {
		swiftProtos = protos
	}
	if len(swiftTypes) == 0 && len(swiftProtos) == 0 {
		return "", nil
	}

	var b strings.Builder
	renderMu.Lock()
	swallowStdout(func() {
		// Type has no exported Name field at top level; sort by Verbose() output
		// to keep output deterministic across runs.
		dumps := make([]string, 0, len(swiftTypes))
		for _, t := range swiftTypes {
			dumps = append(dumps, t.Verbose())
		}
		slices.Sort(dumps)
		for _, d := range dumps {
			b.WriteString(d)
			b.WriteString("\n")
		}

		protoDumps := make([]string, 0, len(swiftProtos))
		for _, p := range swiftProtos {
			protoDumps = append(protoDumps, fmt.Sprintf("%+v", p))
		}
		slices.Sort(protoDumps)
		for _, d := range protoDumps {
			b.WriteString(d)
			b.WriteString("\n")
		}
	})
	renderMu.Unlock()

	return b.String(), nil
}
