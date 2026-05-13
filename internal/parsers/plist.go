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

// CanonicalizePlist accepts XML or binary plist bytes and returns a
// pretty-printed XML form. The round-trip removes ordering noise and
// makes binary plists diffable.
func CanonicalizePlist(data []byte) ([]byte, error) {
	var v any
	if _, err := plist.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("plist unmarshal: %w", err)
	}
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	enc.Indent("\t")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("plist marshal: %w", err)
	}
	return buf.Bytes(), nil
}
