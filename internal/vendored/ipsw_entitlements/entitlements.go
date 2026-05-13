// Package ventitlements is vendored from
// github.com/blacktop/ipsw/internal/codesign/entitlements at commit
// d8aec666867becf32f904a1d6338f9e23efd55c1. Original copyright belongs to
// blacktop; see internal/vendored/LICENSE.ipsw.
package ventitlements

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"github.com/blacktop/go-plist"
)

type item struct {
	Key string `asn1:"utf8"`
	Val any
}

type boolItem struct {
	Key string `asn1:"utf8"`
	Val bool
}

type stringItem struct {
	Key string `asn1:"utf8"`
	Val string `asn1:"utf8"`
}

type stringSliceItem struct {
	Key string   `asn1:"utf8"`
	Val []string `asn1:"set,tag:12"`
}

func DerEncode(input []byte) ([]byte, error) {
	var entitlements map[string]any

	if err := plist.NewDecoder(bytes.NewReader(input)).Decode(&entitlements); err != nil {
		return nil, fmt.Errorf("failed to decode entitlements plist: %w", err)
	}

	var items []any
	for k, v := range entitlements {
		switch t := v.(type) {
		case bool:
			items = append(items, boolItem{k, t})
		case string:
			items = append(items, stringItem{k, t})
		case []any:
			var stringSlice []string
			for _, s := range t {
				stringSlice = append(stringSlice, s.(string))
			}
			items = append(items, stringSliceItem{k, stringSlice})
		default:
			items = append(items, item{k, v})
		}
	}

	return asn1.MarshalWithParams(items, "set")
}

// DerDecode parses DER-encoded entitlements and returns a plist XML string.
// Supports Apple's official DER entitlements format (APPLICATION [16] wrapper).
func DerDecode(derData []byte) (string, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(derData, &outer)
	if err != nil {
		return "", fmt.Errorf("failed to parse outer DER structure: %w", err)
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("unexpected trailing data after DER entitlements")
	}
	if outer.Class != 1 || outer.Tag != 16 {
		return "", fmt.Errorf("unsupported DER entitlements format (expected APPLICATION [16], got class:%d tag:%d)", outer.Class, outer.Tag)
	}
	var version int
	var itemsContainer asn1.RawValue
	innerRest, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil {
		return "", fmt.Errorf("failed to parse version: %w", err)
	}
	if _, err := asn1.Unmarshal(innerRest, &itemsContainer); err != nil {
		return "", fmt.Errorf("failed to parse items container: %w", err)
	}
	entitlements := make(map[string]any)
	remaining := itemsContainer.Bytes

	for len(remaining) > 0 {
		var item asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &item)
		if err != nil {
			break
		}
		var itemSeq struct {
			Key   string `asn1:"utf8"`
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &itemSeq); err != nil {
			continue
		}
		switch itemSeq.Value.Tag {
		case asn1.TagBoolean:
			var boolVal bool
			if _, err := asn1.Unmarshal(itemSeq.Value.FullBytes, &boolVal); err == nil {
				entitlements[itemSeq.Key] = boolVal
			}
		case asn1.TagUTF8String:
			var strVal string
			if _, err := asn1.Unmarshal(itemSeq.Value.FullBytes, &strVal); err == nil {
				entitlements[itemSeq.Key] = strVal
			}
		case asn1.TagSequence:
			var strSlice []string
			itemRemaining := itemSeq.Value.Bytes
			for len(itemRemaining) > 0 {
				var str string
				var err error
				itemRemaining, err = asn1.Unmarshal(itemRemaining, &str)
				if err != nil {
					break
				}
				strSlice = append(strSlice, str)
			}
			if len(strSlice) > 0 {
				entitlements[itemSeq.Key] = strSlice
			}
		default:
			entitlements[itemSeq.Key] = itemSeq.Value.Bytes
		}
	}
	var buf bytes.Buffer
	encoder := plist.NewEncoder(&buf)
	encoder.Indent("  ")
	if err := encoder.Encode(entitlements); err != nil {
		return "", fmt.Errorf("failed to encode entitlements as plist: %w", err)
	}

	return buf.String(), nil
}
