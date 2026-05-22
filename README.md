# ipadiff

Structural diffing for two iOS `.ipa` files.

`ipadiff` extracts both app bundles, compares the parts that matter, and writes a Markdown report. It is built for iOS reverse engineering, release review, and mobile security diffing.

## Features

- Mach-O coverage for the main binary, frameworks, app extensions, nested frameworks, watch apps, XPC services, and loose dylibs.
- Section, symbol, function-start, cstring, import, Obj-C, and Swift metadata diffs.
- Entitlements and launch constraint diffs from code signatures.
- `Info.plist`, embedded plist, and provisioning profile diffs.
- React Native Hermes bytecode bundle diffs, including `main.jsbundle`, detected automatically by Hermes bytecode magic.
- Resource diffs for text-like files such as `.json`, `.js`, `.html`, `.xml`, `.strings`, and source files.
- Canonical JSON comparison, so key-order-only `.json` churn is ignored.
- File-tree diff for new and removed bundle paths.
- Multi-file Markdown output with spill directories for large sections.

`_CodeSignature/` directories are skipped because they are signing metadata, not app content.

## Requirements

- Go
- Rust / Cargo
- `git` on `PATH` for cleaner unified text diffs

`git` is recommended, not mandatory. `ipadiff` falls back to the built-in Go diff path when needed.

## Build

```bash
git clone https://github.com/Xplo8E/ipadiff
cd ipadiff
make build
```

This builds `bin/ipadiff` and `bin/hermes-diff`.

```bash
make build   # build both binaries
make install # install to $HOME/.local/bin
make clean   # remove build artifacts
```

This installs both binaries into `$HOME/.local/bin`.

Use `PREFIX` to install somewhere else:

```bash
make install PREFIX=/usr/local
```

## Usage

```bash
./bin/ipadiff <old.ipa> <new.ipa>
```

Default output:

```text
ipa-diffs/<bundleID>_<oldVersion>_<newVersion>/
```

Example:

```bash
./bin/ipadiff App-1.0.ipa App-2.0.ipa
```

Use `-o` to choose the outer output directory:

```bash
./bin/ipadiff App-1.0.ipa App-2.0.ipa -o /tmp/ipa-review
```

The inner report directory is still derived from bundle metadata:

```text
/tmp/ipa-review/com.example.app_1.0_2.0/
```

## Flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-t, --title` | auto | Report title |
| `-o, --output` | `./ipa-diffs` | Outer output directory |
| `--no-strs` | false | Skip cstring diffs |
| `--no-starts` | false | Skip function-start size deltas |
| `--no-ent` | false | Skip entitlement diffs |
| `--no-objc` | false | Skip Obj-C metadata diffs |
| `--no-swift` | false | Skip Swift metadata diffs |
| `--skip-resources` | false | Skip text-resource diffs |
| `--allow-list` | none | Mach-O sections to include, for example `__TEXT.__text` |
| `--block-list` | none | Mach-O sections to exclude |
| `--workers` | `GOMAXPROCS` | Parallel workers for per-binary and per-file phases |
| `-v, --verbose` | false | Verbose logging |

## Output Layout

```text
<outer>/<bundleID>_<oldVersion>_<newVersion>/
├── README.md
├── <BundleName>.md
├── MACHOS/
├── HERMES/
│   └── main_jsbundle/
│       ├── README.md
│       ├── manifest.json
│       ├── artifacts/hermes/diff.json
│       └── functions/
├── PLISTS/
└── RESOURCES/
```

Only sections with content are written. Large sections spill into their own directories and are linked from the top-level report.

## Hermes Support

Hermes support is automatic.

If the IPA contains changed React Native Hermes bytecode, `ipadiff` runs `hermes-diff` and writes a `HERMES/` report. No Hermes-specific CLI flags are needed.

Hermes detection is based on the bytecode magic:

```text
c6 1f bc 03 c1 03 19 1f
```

Tool lookup order:

```text
1. explicit config path
2. IPADIFF_HERMES_TOOL
3. hermes-diff next to the running ipadiff binary
4. hermes-diff on PATH
```

Plain JavaScript bundles that are not Hermes bytecode stay in the normal resource diff path.

## FairPlay Encrypted IPAs

Store IPAs may contain FairPlay-encrypted main binaries.

When a binary is encrypted, `ipadiff` keeps the report usable:

- structural Mach-O data is still compared
- imports and sections are still listed where readable
- symbols, cstrings, Obj-C, and Swift metadata may be skipped
- plists, entitlements, provisioning profiles, resources, Hermes bundles, and file-tree diffs still run

Use decrypted IPAs when full binary-level detail is needed.

## Library Use

```go
package main

import (
	"os"

	"github.com/Xplo8E/ipadiff/pkg/ipadiff"
)

func main() {
	cfg := &ipadiff.Config{
		OldIPA:     "old.ipa",
		NewIPA:     "new.ipa",
		Output:     "ipa-diffs",
		// Required only when you want Hermes bytecode reports from package use.
		// If omitted and Hermes changes exist, the run continues with a warning.
		HermesTool: "bin/hermes-diff",
	}
	cfg.Defaults()

	d, err := ipadiff.Run(cfg)
	if err != nil {
		panic(err)
	}
	defer d.Close()

	_ = d.WriteMarkdown(os.Stdout)
	_ = d.WriteFiles(cfg.Output)
}
```

## Project Layout

```text
cmd/ipadiff/          CLI entrypoint
pkg/ipadiff/          public Go API
internal/bundle/      IPA extraction, bundle metadata, file classification
internal/parsers/     plist, mobileprovision, entitlement readers
internal/diff/        diff engine, sidecar orchestration, Markdown renderer
internal/vendored/    pruned MIT-licensed code from blacktop/ipsw
tools/hermes-diff/    Rust Hermes bytecode diff sidecar
```

## Development

```bash
make test
make build
git diff --check
```

Useful real-run shape:

```bash
./bin/ipadiff old.ipa new.ipa -o /tmp/ipadiff-check --workers 4
```

## Credits

- Inspired by [`blacktop/ipsw`](https://github.com/blacktop/ipsw).
- Mach-O diff, entitlement diff, and diff utility code are vendored from [`blacktop/ipsw`](https://github.com/blacktop/ipsw) under the MIT license. See [`NOTICE`](./NOTICE).
- Hermes bytecode parsing uses [`hermes_rs`](https://github.com/Pilfer/hermes_rs).
- Hermes JavaScript decompilation uses [`hermes-decomp`](https://github.com/SymbioticSec/hermes-decomp).

## License

MIT. See [`LICENSE`](./LICENSE).
