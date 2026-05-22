package bundle

import "testing"

func TestClassifyDetectsHermesBytecodeByMagic(t *testing.T) {
	head := []byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f, 0x60, 0x00}
	if got := Classify("main.jsbundle", head); got != KindHermes {
		t.Fatalf("Classify(main.jsbundle) = %s, want hermes", got)
	}
}

func TestClassifyPlainJSBundleStaysText(t *testing.T) {
	if got := Classify("main.jsbundle", []byte("var App = true;\n")); got != KindText {
		t.Fatalf("Classify(plain main.jsbundle) = %s, want text", got)
	}
}
