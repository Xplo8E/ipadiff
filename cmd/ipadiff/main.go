// Command ipadiff prints the differences between two iOS .ipa files
// as Markdown. See the project README for full flag documentation.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/spf13/cobra"

	"github.com/Xplo8E/ipadiff/pkg/ipadiff"
)

func main() {
	log.SetHandler(cli.Default)

	var (
		title         string
		output        string
		noCStrings    bool
		noFuncStarts  bool
		noEnts        bool
		noObjC        bool
		noSwift       bool
		skipResources bool
		allowList     []string
		blockList     []string
		workers       int
		verbose       bool
	)

	root := &cobra.Command{
		Use:           "ipadiff <old.ipa> <new.ipa>",
		Short:         "Diff two iOS .ipa bundles (Mach-Os, ObjC/Swift, plists, entitlements, resources).",
		Version:       ipadiff.Version,
		Args:          cobra.MaximumNArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if len(args) != 2 {
				return fmt.Errorf("need exactly 2 IPA paths, got %d", len(args))
			}
			if verbose {
				log.SetLevel(log.DebugLevel)
			}
			oldIPA, newIPA := filepath.Clean(args[0]), filepath.Clean(args[1])
			for _, p := range []string{oldIPA, newIPA} {
				if !strings.EqualFold(filepath.Ext(p), ".ipa") {
					log.Warnf("%s does not end in .ipa — continuing anyway", p)
				}
			}

			cfg := &ipadiff.Config{
				Title:         title,
				OldIPA:        oldIPA,
				NewIPA:        newIPA,
				Output:        output,
				NoObjC:        noObjC,
				NoSwift:       noSwift,
				SkipResources: skipResources,
				AllowList:     allowList,
				BlockList:     blockList,
				Workers:       workers,
				Verbose:       verbose,
			}
			cfg.Defaults()
			// Apply negative overrides after Defaults so disabling works.
			if noCStrings {
				cfg.CStrings = false
			}
			if noFuncStarts {
				cfg.FuncStarts = false
			}
			if noEnts {
				cfg.Entitlements = false
			}

			d, err := ipadiff.Run(cfg)
			if err != nil {
				return fmt.Errorf("diff: %w", err)
			}

			if err := d.Markdown(os.Stdout); err != nil {
				return fmt.Errorf("write markdown: %w", err)
			}
			log.Infof("wrote diff to %s", d.OutputDir())
			return nil
		},
	}

	root.SetVersionTemplate("ipadiff {{.Version}}\n")
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the ipadiff version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("ipadiff %s\n", ipadiff.Version)
		},
	})

	f := root.Flags()
	f.StringVarP(&title, "title", "t", "", "Title for the diff document (auto-derived if empty)")
	f.StringVarP(&output, "output", "o", "", "Outer output directory (default: ./ipa-diffs). Inner folder is always <bundleID>_<oldVer>_<newVer>")
	f.BoolVar(&noCStrings, "no-strs", false, "Skip cstring diffs (default: include)")
	f.BoolVar(&noFuncStarts, "no-starts", false, "Skip function-starts size deltas (default: include)")
	f.BoolVar(&noEnts, "no-ent", false, "Skip entitlements diff (default: include)")
	f.BoolVar(&noObjC, "no-objc", false, "Skip Obj-C metadata diff")
	f.BoolVar(&noSwift, "no-swift", false, "Skip Swift metadata diff")
	f.BoolVar(&skipResources, "skip-resources", false, "Skip text-resource diffs")
	f.StringSliceVar(&allowList, "allow-list", nil, "Mach-O sections to include (e.g. __TEXT.__text)")
	f.StringSliceVar(&blockList, "block-list", nil, "Mach-O sections to exclude")
	f.IntVar(&workers, "workers", 0, "Parallel workers for per-binary and per-file diff phases (default: GOMAXPROCS)")
	f.BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")

	if err := root.Execute(); err != nil {
		log.WithError(err).Fatal("ipadiff failed")
	}
}
