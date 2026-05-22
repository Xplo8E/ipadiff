package bundle

import (
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Kind is the broad category of a file inside an IPA bundle.
type Kind int

const (
	KindUnknown Kind = iota
	KindMacho        // Mach-O binary (main app, framework, dylib, bundle)
	KindHermes       // Hermes bytecode bundle (React Native main.jsbundle/.hbc)
	KindPlist        // any plist (XML or binary), strings, storyboardc, nib, xib
	KindText         // diffable text (json, js, html, xml, txt, md, css, yaml)
	KindMedia        // images, audio, video, fonts — skipped at file-tree level
	KindBinary       // other binary blob — size-only diff
)

func (k Kind) String() string {
	switch k {
	case KindMacho:
		return "macho"
	case KindHermes:
		return "hermes"
	case KindPlist:
		return "plist"
	case KindText:
		return "text"
	case KindMedia:
		return "media"
	case KindBinary:
		return "binary"
	}
	return "unknown"
}

// FileMeta describes a single file inside an extracted bundle.
type FileMeta struct {
	RelPath   string
	Kind      Kind
	Size      int64
	Encrypted bool // true only for Mach-Os with LC_ENCRYPTION_INFO.CryptID != 0
}

var hermesMagic = []byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f}

// mediaExts is the suffix set we never diff content for.
var mediaExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {},
	".heic": {}, ".heif": {}, ".tiff": {}, ".tif": {}, ".bmp": {},
	".car": {}, ".icns": {},
	".mp4": {}, ".mov": {}, ".m4v": {}, ".mkv": {}, ".webm": {},
	".mp3": {}, ".m4a": {}, ".aac": {}, ".wav": {}, ".flac": {}, ".ogg": {},
	".ttf": {}, ".otf": {}, ".woff": {}, ".woff2": {}, ".eot": {},
}

// plistExts groups plist-shaped resources. Storyboards/nibs are compiled plists.
var plistExts = map[string]struct{}{
	".plist":       {},
	".strings":     {},
	".storyboardc": {},
	".nib":         {},
	".xib":         {},
}

// textExts is conservative: only files we are confident render usefully
// as line-oriented diffs.
var textExts = map[string]struct{}{
	".json": {}, ".js": {}, ".jsx": {}, ".ts": {}, ".tsx": {},
	".html": {}, ".htm": {}, ".xml": {}, ".svg": {},
	".txt": {}, ".md": {}, ".markdown": {},
	".css": {}, ".scss": {}, ".less": {},
	".yaml": {}, ".yml": {}, ".toml": {}, ".ini": {}, ".cfg": {}, ".conf": {},
	".sh": {}, ".bash": {}, ".zsh": {},
	".c": {}, ".h": {}, ".m": {}, ".mm": {}, ".swift": {},
	".pem": {}, ".crt": {}, ".cer": {}, ".cnf": {},
}

// machoMagic checks the first 4 bytes for any Mach-O variant
// (32/64-bit, big/little-endian, fat).
func machoMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	switch {
	case head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE: // FAT_MAGIC
		return true
	case head[0] == 0xBE && head[1] == 0xBA && head[2] == 0xFE && head[3] == 0xCA:
		return true
	case head[0] == 0xCF && head[1] == 0xFA && head[2] == 0xED && head[3] == 0xFE: // MH_MAGIC_64
		return true
	case head[0] == 0xFE && head[1] == 0xED && head[2] == 0xFA && head[3] == 0xCF:
		return true
	case head[0] == 0xCE && head[1] == 0xFA && head[2] == 0xED && head[3] == 0xFE: // MH_MAGIC (32)
		return true
	case head[0] == 0xFE && head[1] == 0xED && head[2] == 0xFA && head[3] == 0xCE:
		return true
	}
	return false
}

func hermesBytecodeMagic(head []byte) bool {
	if len(head) < len(hermesMagic) {
		return false
	}
	for i, b := range hermesMagic {
		if head[i] != b {
			return false
		}
	}
	return true
}

// Classify maps (relpath, head-bytes) to a Kind.
// head should be ~512 bytes from the start of the file when available.
func Classify(relPath string, head []byte) Kind {
	if machoMagic(head) {
		return KindMacho
	}
	if hermesBytecodeMagic(head) {
		return KindHermes
	}
	ext := strings.ToLower(filepath.Ext(relPath))
	if _, ok := mediaExts[ext]; ok {
		return KindMedia
	}
	if _, ok := plistExts[ext]; ok {
		return KindPlist
	}
	if _, ok := textExts[ext]; ok {
		return KindText
	}
	// Heuristic fallback: small valid-UTF-8 buffer with no NUL → text.
	if len(head) > 0 && utf8.Valid(head) && !containsNUL(head) {
		return KindText
	}
	if len(head) == 0 {
		return KindUnknown
	}
	return KindBinary
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}
