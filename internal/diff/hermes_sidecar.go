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
	used := map[string]bool{}
	for _, rel := range keys {
		item := d.Hermes.Updated[rel]
		oldInput, newInput := item.sidecarInputs(d.Old.AppDir, d.New.AppDir)
		if oldInput == "" || newInput == "" {
			msg := "Hermes input snapshot unavailable"
			item.Warning = msg
			d.addWarning("hermes", rel, msg)
			continue
		}
		dirName := uniqueDirName(used, TitleToFilename(safeName(rel)))
		outDir := filepath.Join(hermesRoot, dirName)

		ctx, cancel := context.WithTimeout(context.Background(), d.hermesTimeout())
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
		cancel()
		item.cleanupInputs()
		if err != nil {
			msg := fmt.Sprintf("hermes-diff failed: %v", err)
			if ctx.Err() == context.DeadlineExceeded {
				msg = fmt.Sprintf("hermes-diff timed out after %s", d.hermesTimeout())
			}
			if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
				msg += ": " + truncateWarning(trimmed, 800)
			}
			item.Warning = msg
			d.addWarning("hermes", rel, msg)
			continue
		}

		item.OutputDir = filepath.ToSlash(filepath.Join("HERMES", dirName))
		if err := item.loadHermesManifest(filepath.Join(outDir, "manifest.json")); err != nil {
			msg := "read manifest failed: " + err.Error()
			item.Warning = msg
			d.addWarning("hermes", rel, msg)
		}
	}
	d.sortWarnings()
	return true, nil
}

func (h *HermesBundleDiff) sidecarInputs(oldRoot, newRoot string) (string, string) {
	if h.oldInput != "" && h.newInput != "" {
		return h.oldInput, h.newInput
	}
	if h.Path == "" {
		return "", ""
	}
	return filepath.Join(oldRoot, h.Path), filepath.Join(newRoot, h.Path)
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
