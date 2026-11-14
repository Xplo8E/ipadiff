package diff

import (
	"io"
	"os"
	"sync"
)

// stdoutMu serializes the process-global stdout capture windows: two library
// callers running ipadiff.Run concurrently would otherwise each swap
// os.Stdout and restore their own saved value, racing the variable and
// potentially leaving it pointed at a closed capture pipe. The lock covers
// only the capture window, so unrelated work in concurrent runs stays
// parallel.
var stdoutMu sync.Mutex

// swallowStdoutDuring runs fn while the process stdout is redirected to a
// drained pipe. go-macho v1.1.296's Swift type renderer prints stray debug
// lines to the process stdout when a class or struct generic requirement hits
// the default branch of its kind switch (types/swift/types.go:
// `fmt.Println(req.Flags.String())`; still present on go-macho master as of
// 2026-11-14). The metadata diff phases write nothing legitimate to stdout —
// apex/log writes to stderr and the Markdown report is rendered after all
// sections complete — so the whole phase runs behind the capture. The swap is
// done by the orchestrating goroutine before the workers spawn and restored
// after they join, so os.Stdout has no concurrent writers and no per-call
// locking is needed; workers keep full parallelism.
//
// Remove this wrapper once a go-macho release drops the debug prints.
func swallowStdoutDuring[T any](fn func() T) T {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()

	realStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		// Cannot redirect; run unguarded and accept any leak rather than
		// failing the section.
		return fn()
	}
	os.Stdout = w
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(drained)
	}()
	defer func() {
		os.Stdout = realStdout
		_ = w.Close()
		<-drained
		_ = r.Close()
	}()
	return fn()
}
