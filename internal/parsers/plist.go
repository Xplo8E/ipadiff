// Package parsers contains thin readers for IPA artifacts (plists,
// mobileprovision, Mach-O entitlements). Each parser is self-contained
// and returns canonicalized text that can be fed straight into a
// text-level diff engine.
package parsers

import (
	"bytes"
	"fmt"

	plist "github.com/blacktop/go-plist"
)

// buildMetadataKeys are top-level Info.plist keys stamped by Xcode/the build
// toolchain. They change on every rebuild with a newer toolchain and carry no
// release-to-release meaning, so DropBuildKeys removes them before diffing.
//
// Deliberately excluded even though they look build-related: MinimumOSVersion,
// LSMinimumSystemVersion (deployment target = mitigation surface), and the
// CFBundle*Version keys (the actual version bump a reviewer wants to see).
var buildMetadataKeys = map[string]struct{}{
	"BuildMachineOSBuild":  {},
	"DTCompiler":           {},
	"DTPlatformBuild":      {},
	"DTPlatformName":       {},
	"DTPlatformVersion":    {},
	"DTSDKBuild":           {},
	"DTSDKName":            {},
	"DTXcode":              {},
	"DTXcodeBuild":         {},
	"DTAppStoreToolsBuild": {},
}

// CanonicalizePlist accepts XML or binary plist bytes and returns a
// pretty-printed XML form. The round-trip removes ordering noise and
// makes binary plists diffable.
func CanonicalizePlist(data []byte) ([]byte, error) {
	var v any
	if _, err := plist.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("plist unmarshal: %w", err)
	}
	return encodePlist(v)
}

// CanonicalizePlistDropBuild is CanonicalizePlist with top-level build-metadata
// keys (see buildMetadataKeys) removed. Returns the number of keys dropped so
// the caller can report how much noise was suppressed.
func CanonicalizePlistDropBuild(data []byte) (out []byte, dropped int, err error) {
	var v any
	if _, err := plist.Unmarshal(data, &v); err != nil {
		return nil, 0, fmt.Errorf("plist unmarshal: %w", err)
	}
	// Build keys only ever live at the plist root; prune there only so a
	// same-named nested key (unlikely, but possible) is never touched.
	if root, ok := v.(map[string]any); ok {
		for k := range buildMetadataKeys {
			if _, present := root[k]; present {
				delete(root, k)
				dropped++
			}
		}
	}
	out, err = encodePlist(v)
	return out, dropped, err
}

func encodePlist(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	enc.Indent("\t")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("plist marshal: %w", err)
	}
	return buf.Bytes(), nil
}
