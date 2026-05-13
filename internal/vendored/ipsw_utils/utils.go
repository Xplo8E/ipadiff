// Package vutils is vendored from
// github.com/blacktop/ipsw/internal/utils at commit
// d8aec666867becf32f904a1d6338f9e23efd55c1. Pruned to the subset used by the
// vendored macho-diff engine and the ipadiff archive extractor. Original
// copyright belongs to blacktop; see internal/vendored/LICENSE.ipsw.
package vutils

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// Difference returns elements in a that are not in b.
func Difference[T comparable](a []T, b []T) []T {
	amap := make(map[T]bool)
	for _, item := range a {
		amap[item] = true
	}
	for _, item := range b {
		delete(amap, item)
	}
	return slices.Collect(maps.Keys(amap))
}

// SanitizeArchivePath joins an untrusted archive entry name to a destination
// directory and verifies the result stays within that directory. Returns an
// error if the entry name would escape via path traversal (zip-slip).
//
// Lexical check only: does NOT resolve symlinks. If dest already contains a
// symlink pointing outside, writes through it will escape. Callers must not
// create symlinks from untrusted archive entries.
func SanitizeArchivePath(dest, name string) (string, error) {
	target := filepath.Join(dest, name)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("failed to resolve destination: %w", err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target: %w", err)
	}
	rel, err := filepath.Rel(absDest, absTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry %q escapes destination directory", name)
	}
	return target, nil
}
