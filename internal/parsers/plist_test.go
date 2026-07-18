package parsers

import (
	"strings"
	"testing"
)

const buildPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleShortVersionString</key><string>2.0</string>
<key>DTXcode</key><string>1620</string>
<key>DTSDKBuild</key><string>22A123</string>
<key>NSExtension</key><dict><key>DTXcode</key><string>nested-should-stay</string></dict>
</dict></plist>`

func TestDropBuildKeys(t *testing.T) {
	out, dropped, err := CanonicalizePlistDropBuild([]byte(buildPlist))
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2 (DTXcode, DTSDKBuild)", dropped)
	}
	s := string(out)
	// Real keys survive.
	if !strings.Contains(s, "CFBundleShortVersionString") || !strings.Contains(s, "2.0") {
		t.Fatal("version key was wrongly dropped")
	}
	if !strings.Contains(s, "NSExtension") {
		t.Fatal("NSExtension was wrongly dropped")
	}
	// Top-level build keys gone.
	if strings.Contains(s, "1620") || strings.Contains(s, "22A123") {
		t.Fatal("top-level build key survived")
	}
	// Nested DTXcode inside NSExtension must remain — we only prune the root.
	if !strings.Contains(s, "nested-should-stay") {
		t.Fatal("nested same-named key was wrongly pruned")
	}
}

func TestDropBuildKeysNoneToDrop(t *testing.T) {
	clean := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleName</key><string>App</string></dict></plist>`
	_, dropped, err := CanonicalizePlistDropBuild([]byte(clean))
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
}

func TestCanonicalizePlistKeepsBuildKeys(t *testing.T) {
	// The non-dropping path must leave build keys intact.
	out, err := CanonicalizePlist([]byte(buildPlist))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "1620") {
		t.Fatal("CanonicalizePlist should not drop build keys")
	}
}
