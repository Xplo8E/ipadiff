package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type hermesManifest struct {
	Stats hermesManifestStats `json:"stats"`
}

type hermesManifestStats struct {
	OldFunctions int `json:"old_functions"`
	NewFunctions int `json:"new_functions"`
	Exact        int `json:"exact"`
	Partial      int `json:"partial"`
	New          int `json:"new"`
	Deleted      int `json:"deleted"`
}

func (d *Diff) writeHermesFiles(root string) (bool, error) {
	if d.Hermes == nil || len(d.Hermes.Updated) == 0 {
		return false, nil
	}

	tool, err := d.findHermesTool()
	if err != nil {
		for rel, item := range d.Hermes.Updated {
			item.Warning = err.Error()
			d.addWarning("hermes", rel, err.Error())
			item.cleanupInputs()
		}
		d.sortWarnings()
		return false, nil
	}

	hermesRoot := filepath.Join(root, "HERMES")
	if err := os.MkdirAll(hermesRoot, 0o755); err != nil {
		return false, err
	}

	keys := mapKeysHermes(d.Hermes.Updated)
	sort.Strings(keys)

	// Reserve one output dir per bundle up front so names stay deterministic
	// when the sidecar runs are parallelized below.
	used := map[string]bool{}
	dirNames := make(map[string]string, len(keys))
	for _, rel := range keys {
		dirNames[rel] = uniqueDirName(used, TitleToFilename(safeName(rel)))
	}

	// Run one sidecar invocation per changed bundle, in parallel like every
	// other per-file phase. The snapshot inputs live in private temp dirs, so
	// the workers share no mutable state; results (including warnings) are
	// applied serially afterwards to keep ordering deterministic.
	type sidecarResult struct {
		rel       string
		outputDir string
		warning   string
	}
	results := runStringWorkers(keys, d.cfg.Workers, func(rel string) sidecarResult {
		item := d.Hermes.Updated[rel]
		oldInput, newInput := item.sidecarInputs()
		if oldInput == "" || newInput == "" {
			return sidecarResult{rel: rel, warning: "Hermes input snapshot unavailable"}
		}
		dirName := dirNames[rel]
		outDir := filepath.Join(hermesRoot, dirName)

		ctx, cancel := context.WithTimeout(context.Background(), d.hermesTimeout())
		defer cancel()
		cmd := exec.CommandContext(
			ctx,
			tool,
			"--old", oldInput,
			"--new", newInput,
			"--old-label", d.hermesInputLabel(d.Old.IPAPath, rel),
			"--new-label", d.hermesInputLabel(d.New.IPAPath, rel),
			"--out-dir", outDir,
		)
		output, err := cmd.CombinedOutput()
		item.cleanupInputs()
		if err != nil {
			msg := fmt.Sprintf("hermes-diff failed: %v", err)
			if ctx.Err() == context.DeadlineExceeded {
				msg = fmt.Sprintf("hermes-diff timed out after %s", d.hermesTimeout())
			}
			if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
				msg += ": " + truncateWarning(trimmed, 800)
			}
			return sidecarResult{rel: rel, warning: msg}
		}

		res := sidecarResult{
			rel:       rel,
			outputDir: filepath.ToSlash(filepath.Join("HERMES", dirName)),
		}
		if err := item.loadHermesManifest(filepath.Join(outDir, "manifest.json")); err != nil {
			res.warning = "read manifest failed: " + err.Error()
		}
		return res
	})
	for _, result := range results {
		item := d.Hermes.Updated[result.rel]
		if result.outputDir != "" {
			item.OutputDir = result.outputDir
		}
		if result.warning != "" {
			item.Warning = result.warning
			d.addWarning("hermes", result.rel, result.warning)
		}
	}
	d.sortWarnings()
	return true, nil
}

// sidecarInputs returns the private snapshot paths for both sides. Snapshots
// are written during diffHermes because the IPA temp extraction dirs are torn
// down when Run returns — a missing snapshot is an error, never a fallback to
// the (already deleted) extraction paths.
func (h *HermesBundleDiff) sidecarInputs() (string, string) {
	if h.oldInput != "" && h.newInput != "" {
		return h.oldInput, h.newInput
	}
	return "", ""
}

func (d *Diff) hermesInputLabel(ipaPath, rel string) string {
	if ipaPath == "" {
		return rel
	}
	return filepath.Base(ipaPath) + ":" + rel
}

func (d *Diff) findHermesTool() (string, error) {
	var candidates []string
	if d.cfg != nil && strings.TrimSpace(d.cfg.HermesTool) != "" {
		candidates = append(candidates, d.cfg.HermesTool)
	}
	if env := strings.TrimSpace(os.Getenv("IPADIFF_HERMES_TOOL")); env != "" {
		candidates = append(candidates, env)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "hermes-diff"))
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	if tool, err := exec.LookPath("hermes-diff"); err == nil {
		return tool, nil
	}
	return "", fmt.Errorf("Hermes bytecode changed, but hermes-diff sidecar was not found; run `make build` or set IPADIFF_HERMES_TOOL")
}

func (d *Diff) hermesTimeout() time.Duration {
	if d != nil && d.cfg != nil && d.cfg.HermesTimeout > 0 {
		return d.cfg.HermesTimeout
	}
	return DefaultHermesTimeout
}

func (h *HermesBundleDiff) loadHermesManifest(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var manifest hermesManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	h.OldFunctions = manifest.Stats.OldFunctions
	h.NewFunctions = manifest.Stats.NewFunctions
	h.Exact = manifest.Stats.Exact
	h.Partial = manifest.Stats.Partial
	h.New = manifest.Stats.New
	h.Deleted = manifest.Stats.Deleted
	return nil
}

func mapKeysHermes(m map[string]*HermesBundleDiff) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func uniqueDirName(used map[string]bool, candidate string) string {
	if !used[candidate] {
		used[candidate] = true
		return candidate
	}
	for i := 1; ; i++ {
		try := fmt.Sprintf("%s_%d", candidate, i)
		if !used[try] {
			used[try] = true
			return try
		}
	}
}

func truncateWarning(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "..."
}
