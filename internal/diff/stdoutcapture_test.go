package diff

import (
	"fmt"
	"os"
	"testing"
)

func TestSwallowStdoutDuringCapturesAndRestores(t *testing.T) {
	realStdout := os.Stdout

	got := swallowStdoutDuring(func() string {
		// Anything written to os.Stdout inside fn must be discarded: this is
		// where the go-macho Swift renderer's stray fmt.Println lands.
		fmt.Println("ipadiff-leak-test-marker")
		if os.Stdout == realStdout {
			t.Error("os.Stdout must be redirected inside the capture window")
		}
		return "result"
	})

	if got != "result" {
		t.Fatalf("capture must pass through the fn result, got %q", got)
	}
	if os.Stdout != realStdout {
		t.Fatal("os.Stdout must be restored after the capture window")
	}
}

func TestSwallowStdoutDuringPropagatesPanic(t *testing.T) {
	realStdout := os.Stdout
	defer func() {
		if recover() == nil {
			t.Fatal("expected the fn panic to propagate")
		}
		if os.Stdout != realStdout {
			t.Fatal("os.Stdout must be restored even when fn panics")
		}
	}()
	swallowStdoutDuring(func() int {
		panic("boom")
	})
}
