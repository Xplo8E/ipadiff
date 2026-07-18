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

func TestClassifyCompiledNibIsBinary(t *testing.T) {
	// Modern compiled nib: NIBArchive header → size-only, not a plist parse.
	head := append([]byte("NIBArchive"), 0x01, 0x00, 0x00, 0x00)
	if got := Classify("Main.storyboardc/UIViewController.nib", head); got != KindBinary {
		t.Fatalf("Classify(NIBArchive .nib) = %s, want binary", got)
	}
}

func TestClassifyBinaryPlistNibStaysPlist(t *testing.T) {
	// Legacy nib stored as a binary plist must still be diffed as a plist.
	head := append([]byte("bplist00"), 0xd1, 0x01, 0x02)
	if got := Classify("Legacy.nib", head); got != KindPlist {
		t.Fatalf("Classify(bplist00 .nib) = %s, want plist", got)
	}
}
