package parsers

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// ExtractInnerPlist pulls the XML plist payload out of a CMS-signed
// .mobileprovision file by scanning for <?xml ... </plist> markers.
// This skips signature verification by design — we just want the plist
// content for diffing.
func ExtractInnerPlist(data []byte) ([]byte, error) {
	start := bytes.Index(data, []byte("<?xml"))
	end := bytes.LastIndex(data, []byte("</plist>"))
	if start < 0 || end < 0 || end <= start {
		return nil, errors.New("no inner XML plist found in mobileprovision")
	}
	return data[start : end+len("</plist>")], nil
}

// ReadMobileProvision reads embedded.mobileprovision from disk and returns
// the canonicalized inner plist XML.
func ReadMobileProvision(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mobileprovision: %w", err)
	}
	inner, err := ExtractInnerPlist(data)
	if err != nil {
		return nil, err
	}
	return CanonicalizePlist(inner)
}
