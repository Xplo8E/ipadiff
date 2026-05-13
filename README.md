# ipadiff

Structural diff for two iOS `.ipa` files. Inspired by [`ipsw diff`](https://github.com/blacktop/ipsw) — same architecture, scoped down to app bundles.

Given two IPAs, `ipadiff` produces a Markdown report covering:

- **Mach-Os** — main app **plus every Mach-O anywhere in the bundle**: frameworks, app extensions (`*.appex`), nested frameworks inside extensions, watchOS companion binaries, XPC services, loose dylibs. Sections, symbols, function-starts size deltas, cstrings, imports.
- **Obj-C / Swift metadata** — class/method/protocol dumps, textual diff.
- **Plists** — Info.plist + every embedded plist (binary or XML, auto-canonicalized).
- **Entitlements** — from each binary's code signature (XML or DER), with launch constraints.
- **Provisioning profile** — diff of the embedded.mobileprovision inner plist.
- **Resources** — `.strings`, `.json`, `.js`, `.html`, `.xml`, source files. Media (images/audio/video/fonts) is tracked at the file-tree level only.
- **File tree** — bundle-wide new/removed paths.

`_CodeSignature/` directories are skipped (signing metadata, not app content). No external reverse engineering tools needed — no disassembly, no decompilation — just format-aware extraction and textual diffing.

## Install

```bash
go build -o bin/ipadiff ./cmd/ipadiff
```

Requires Go 1.23+. `git` on PATH is recommended (used for prettier unified diffs); the tool falls back to a pure-Go diff engine otherwise.

## Usage

```bash
ipadiff <old.ipa> <new.ipa> [flags]
```

With no flags, output is written to `./ipa-diffs/<bundleID>_<oldVer>_<newVer>/`:

```bash
ipadiff App-v1.ipa App-v2.ipa
# wrote diff to ipa-diffs/com.example.app_1.0_2.0/
```

Pass `-o` to rename only the **outer** container directory. The inner `<bundleID>_<oldVer>_<newVer>/` folder name is always derived from the parsed bundle metadata:

```bash
ipadiff App-v1.ipa App-v2.ipa -o myout
# wrote diff to myout/com.example.app_1.0_2.0/
```

### Output layout

```
<outer>/<bundleID>_<oldVer>_<newVer>/
├── README.md              ← index: title, links to main + spill subdirs
├── <BundleName>.md        ← main report (e.g. ChatGPT.md, derived from CFBundleName)
├── MACHOS/                ← per-binary diff files (only created when section spills)
│   ├── ChatGPT.md
│   ├── Frameworks_PhoneNumberKit.framework_PhoneNumberKit.md
│   ├── PlugIns_ShareExtension.appex_ShareExtension.md
│   └── …
├── PLISTS/                ← only created when section spills (>25 entries or >200KB)
└── RESOURCES/             ← only created when section spills
```

Inside the main report, each per-binary diff is wrapped in a collapsible `<details>` block (path shown as the summary line) so the file is navigable instead of one long scroll. Large sections (>25 updated entries or >200KB rendered) instead spill into the per-section subdirectories listed above.

### Flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-t, --title` | auto | Document title; defaults to `<bundleID> <oldVer> .vs <newVer>` |
| `-o, --output` | `./ipa-diffs` | Outer output directory. Inner folder is always `<bundleID>_<oldVer>_<newVer>` |
| `--no-strs` | false | Skip cstring diffs |
| `--no-starts` | false | Skip function-starts size deltas |
| `--no-ent` | false | Skip entitlements diff |
| `--no-objc` | false | Skip Obj-C metadata diff |
| `--no-swift` | false | Skip Swift metadata diff |
| `--skip-resources` | false | Skip text-resource diffs |
| `--allow-list` | _none_ | Mach-O sections to include (e.g. `__TEXT.__text`) |
| `--block-list` | _none_ | Mach-O sections to exclude |
| `-v, --verbose` | false | Verbose logging (per-binary progress) |

## FairPlay-encrypted IPAs

Store-purchased IPAs have their main binary encrypted with FairPlay DRM. `ipadiff` detects encryption (`LC_ENCRYPTION_INFO.CryptID != 0`) and degrades gracefully:

- Encrypted binaries get a **structural diff only** (sections, imports). Symbols, cstrings, Obj-C, and Swift are skipped — those bytes aren't readable.
- Plists, entitlements, provisioning, resources, and the file tree are unaffected and still diff cleanly.

For full binary insight, supply decrypted IPAs. Frameworks shipped inside an App Store IPA are usually unencrypted anyway.

## Library use

```go
import "github.com/Xplo8E/ipadiff/pkg/ipadiff"

cfg := &ipadiff.Config{OldIPA: "a.ipa", NewIPA: "b.ipa"}
cfg.Defaults()
d, err := ipadiff.Run(cfg)
// inspect d.Machos, d.Plists, d.Ents, ...
_ = d.Markdown(os.Stdout) // writes to cfg.Output dir; arg is ignored when Output is set
```

## Layout

```
cmd/ipadiff/          CLI (cobra root)
internal/
  bundle/              unzip IPA, classify files, detect FairPlay
  parsers/             plist, mobileprovision, entitlements readers
  diff/                orchestrator + per-section diffs + Markdown renderer
  vendored/            pruned MIT-licensed code from blacktop/ipsw
    ipsw_macho/        DiffInfo + ObjC/Swift dump
    ipsw_ent/          DiffDatabases
    ipsw_entitlements/ DER decode
    ipsw_utils/        Difference, SanitizeArchivePath, GitDiff
pkg/ipadiff/           public library entry
```

## Credits

The Mach-O DiffInfo engine, entitlement diff, and `git diff` fallback logic
are vendored from [blacktop/ipsw](https://github.com/blacktop/ipsw)
(MIT). See `NOTICE` for the pinned upstream commit and the vendor map.

## License

MIT — see `LICENSE`.
