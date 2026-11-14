// facts.go is vendored from
// github.com/blacktop/ipsw/internal/commands/macho/diff_facts.go at commit
// 27f1f0a5b30338fb6406e52e2c0d62f98f9ab16e. Adapted for ipadiff: there is no
// container-image mode (IPA binaries are standalone), the fixed reference
// policy of the upstream symbols-command emitter is replaced by the caller's
// DiffConfig so the recorded policy matches the run that produced the
// DiffInfo, and GenerateComparisonFacts consumes an already-built DiffInfo
// instead of re-running the extractor. Original copyright belongs to
// blacktop; see internal/vendored/LICENSE.ipsw.
package vmacho

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	gomacho "github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-plist"

	ents "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_entitlements"
)

// ComparisonFactsSchemaVersion is the wire schema emitted per binary.
// It is intentionally independent of any consumer schema.
const ComparisonFactsSchemaVersion uint32 = 1

// ComparisonFactsPolicy describes every comparison option applied to a
// ComparisonFacts payload.
type ComparisonFactsPolicy struct {
	Version               uint32   `json:"version"`
	NameNormalization     string   `json:"name_normalization"`
	ContainerSections     string   `json:"container_sections"`
	LiteralPoolHashing    bool     `json:"literal_pool_hashing"`
	CompareCStrings       bool     `json:"compare_cstrings"`
	CompareFunctionStarts bool     `json:"compare_function_starts"`
	IgnoreBuildTimestamps bool     `json:"ignore_build_timestamps"`
	IgnoreLoadCommands    bool     `json:"ignore_load_commands"`
	SectionAllowlist      []string `json:"section_allowlist"`
	SectionBlocklist      []string `json:"section_blocklist"`
}

// ComparisonFactsProvenance names the components that selected and normalized
// the comparison values. Consumers pin these identifiers as a policy contract,
// so they change only when the policy they name changes.
type ComparisonFactsProvenance struct {
	// ReferenceSource names the ipsw commit whose diff semantics the vendored
	// engine froze. Change it only together with the vendored engine.
	ReferenceSource      string `json:"reference_source"`
	DiffInfoGenerator    string `json:"diff_info_generator"`
	NameNormalization    string `json:"name_normalization"`
	EntitlementSelection string `json:"entitlement_selection"`
	LaunchConstraints    string `json:"launch_constraints"`
}

// ComparisonFactsCPU identifies the CPU type, subtype, and normalized architecture.
type ComparisonFactsCPU struct {
	Type         uint32 `json:"type"`
	Subtype      uint32 `json:"subtype"`
	Architecture string `json:"architecture"`
}

// ComparisonHashFact records a hashing policy, availability state, and digest.
type ComparisonHashFact struct {
	Policy string `json:"policy"`
	State  string `json:"state"`
	SHA256 string `json:"sha256"`
}

// ComparisonSectionFact preserves section order, size, type, and the exact
// content-hash decision made by GenerateDiffInfo.
type ComparisonSectionFact struct {
	Name string             `json:"name"`
	Size uint64             `json:"size"`
	Type uint32             `json:"type"`
	Hash ComparisonHashFact `json:"hash"`
}

// ComparisonFunctionStart records the start and end addresses of a function.
type ComparisonFunctionStart struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// ComparisonPlistFact holds normalized JSON plus the digest of the source bytes
// that were actually selected. Unreadable data remains unavailable rather than
// being reported as absent.
type ComparisonPlistFact struct {
	Status         string          `json:"status"`
	SourceEncoding string          `json:"source_encoding"`
	SourceSHA256   string          `json:"source_sha256"`
	Value          json.RawMessage `json:"value,omitempty"`
}

// ComparisonLaunchConstraintFacts holds the self, parent, and responsible
// launch-constraint plists as normalized comparison facts.
type ComparisonLaunchConstraintFacts struct {
	Self        ComparisonPlistFact `json:"self"`
	Parent      ComparisonPlistFact `json:"parent"`
	Responsible ComparisonPlistFact `json:"responsible"`
}

// ComparisonFacts is a small provider-neutral wire payload.
type ComparisonFacts struct {
	SchemaVersion       uint32                          `json:"schema_version"`
	Policy              ComparisonFactsPolicy           `json:"policy"`
	Provenance          ComparisonFactsProvenance       `json:"provenance"`
	CPU                 ComparisonFactsCPU              `json:"cpu"`
	NormalizedRawNames  []string                        `json:"normalized_raw_names"`
	Imports             []string                        `json:"imports"`
	Sections            []ComparisonSectionFact         `json:"sections"`
	LoadCommands        ComparisonHashFact              `json:"load_commands"`
	FunctionCount       uint64                          `json:"function_count"`
	FunctionStarts      []ComparisonFunctionStart       `json:"function_starts"`
	Entitlements        ComparisonPlistFact             `json:"entitlements"`
	LaunchConstraints   ComparisonLaunchConstraintFacts `json:"launch_constraints"`
	SymbolTableCoverage string                          `json:"symbol_table_coverage"`
}

// GenerateComparisonFacts translates an already-built DiffInfo and the open
// Mach-O's code signature into the provider wire without introducing a second
// comparison. The facts reflect exactly the policy that produced info.
func GenerateComparisonFacts(m *gomacho.File, info *DiffInfo, conf *DiffConfig) ComparisonFacts {
	if conf == nil {
		conf = &DiffConfig{}
	}
	cpu := ComparisonFactsCPU{
		Type:         uint32(m.CPU),
		Subtype:      uint32(m.SubCPU),
		Architecture: normalizeArchitecture(m.SubCPU.String(m.CPU)),
	}
	facts := comparisonFactsFromDiffInfo(info, cpu, conf)
	facts.Entitlements, facts.LaunchConstraints = codeSignatureFacts(m.CodeSignature())
	return facts
}

func comparisonFactsFromDiffInfo(info *DiffInfo, cpu ComparisonFactsCPU, conf *DiffConfig) ComparisonFacts {
	sections := make([]ComparisonSectionFact, 0, len(info.Sections))
	for _, sec := range info.Sections {
		sections = append(sections, ComparisonSectionFact{
			Name: sec.Name,
			Size: sec.Size,
			Type: uint32(sec.Type),
			Hash: comparisonSectionHash(sec),
		})
	}
	starts := make([]ComparisonFunctionStart, 0, len(info.Starts))
	for _, fn := range info.Starts {
		starts = append(starts, ComparisonFunctionStart{Start: fn.StartAddr, End: fn.EndAddr})
	}
	return ComparisonFacts{
		SchemaVersion: ComparisonFactsSchemaVersion,
		Policy: ComparisonFactsPolicy{
			Version:               ReferenceComparisonPolicyVersion,
			NameNormalization:     "ipsw_macho_raw_names_v1",
			ContainerSections:     "ipsw_container_literal_sections_v1",
			LiteralPoolHashing:    true,
			CompareCStrings:       conf.CStrings,
			CompareFunctionStarts: conf.FuncStarts,
			IgnoreBuildTimestamps: conf.IgnoreBuildTimestamps,
			IgnoreLoadCommands:    conf.IgnoreLoadCommands,
			SectionAllowlist:      cloneStrings(conf.AllowList),
			SectionBlocklist:      cloneStrings(conf.BlockList),
		},
		Provenance: ComparisonFactsProvenance{
			ReferenceSource:      "ipsw@27f1f0a5b30338fb6406e52e2c0d62f98f9ab16e",
			DiffInfoGenerator:    "internal/commands/macho.GenerateDiffInfo",
			NameNormalization:    "internal/commands/macho.normalizeSymbolForDiff",
			EntitlementSelection: "xml_preferred_internal/codesign/entitlements.DerDecode_fallback",
			LaunchConstraints:    "go-macho/pkg/codesign/types.ParseLaunchContraints",
		},
		CPU:                cpu,
		NormalizedRawNames: stringSet(info.Symbols, normalizeSymbolForDiff),
		Imports:            stringSet(info.Imports, func(value string) string { return value }),
		Sections:           sections,
		LoadCommands:       comparisonLoadCommandHash(info.LoadCmdHash, conf.IgnoreLoadCommands),
		FunctionCount:      uint64(info.Functions),
		FunctionStarts:     starts,
		Entitlements:       absentPlistFact(),
		LaunchConstraints: ComparisonLaunchConstraintFacts{
			Self: absentPlistFact(), Parent: absentPlistFact(), Responsible: absentPlistFact(),
		},
		SymbolTableCoverage: "unsupported",
	}
}

// ReferenceComparisonPolicyVersion identifies the fixed comparison policy the
// vendored engine applies when the caller does not override the relevant
// DiffConfig options.
const ReferenceComparisonPolicyVersion uint32 = 2

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values)
}

func stringSet(values []string, normalize func(string) string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := normalizedStringSet(values, normalize)
	if len(result) == 0 {
		return []string{}
	}
	return result
}

func comparisonSectionHash(sec section) ComparisonHashFact {
	policy := "skip"
	switch sec.HashMode {
	case hashVerbatim:
		policy = "verbatim_sha256"
	case hashCStringsOrdered:
		policy = "normalized_cstring_ordered_sha256"
	case hashCStringsMultiset:
		policy = "normalized_cstring_multiset_sha256"
	}
	if sec.HashMode == hashSkip {
		return ComparisonHashFact{Policy: policy, State: "excluded", SHA256: ""}
	}
	if sec.Hash == "" {
		return ComparisonHashFact{Policy: policy, State: "unavailable", SHA256: ""}
	}
	return ComparisonHashFact{Policy: policy, State: "present", SHA256: sec.Hash}
}

func comparisonLoadCommandHash(digest string, ignored bool) ComparisonHashFact {
	if ignored {
		return ComparisonHashFact{Policy: "skip", State: "excluded", SHA256: ""}
	}
	if digest == "" {
		return ComparisonHashFact{Policy: "normalized_load_commands_sha256", State: "unavailable", SHA256: ""}
	}
	return ComparisonHashFact{Policy: "normalized_load_commands_sha256", State: "present", SHA256: digest}
}

func normalizeArchitecture(value string) string {
	return strings.ToLower(value)
}

func codeSignatureFacts(cs *gomacho.CodeSignature) (ComparisonPlistFact, ComparisonLaunchConstraintFacts) {
	missing := absentPlistFact()
	if cs == nil {
		constraints := ComparisonLaunchConstraintFacts{Self: missing, Parent: missing, Responsible: missing}
		return missing, constraints
	}
	if len(cs.Errors) > 0 {
		missing = unavailablePlistFact()
	}
	constraints := ComparisonLaunchConstraintFacts{Self: missing, Parent: missing, Responsible: missing}

	entitlements := missing
	switch {
	case len(cs.Entitlements) > 0:
		source := []byte(cs.Entitlements)
		entitlements = normalizedPlistFact("xml", source, func() (any, error) {
			return decodePlist(source)
		})
	case len(cs.EntitlementsDER) > 0:
		source := cs.EntitlementsDER
		entitlements = normalizedPlistFact("der", source, func() (any, error) {
			decoded, err := ents.DerDecode(source)
			if err != nil {
				return nil, err
			}
			return decodePlist([]byte(decoded))
		})
	}
	constraints.Self = launchConstraintFact(cs.LaunchConstraintsSelf, missing)
	constraints.Parent = launchConstraintFact(cs.LaunchConstraintsParent, missing)
	constraints.Responsible = launchConstraintFact(cs.LaunchConstraintsResponsible, missing)
	return entitlements, constraints
}

func decodePlist(source []byte) (any, error) {
	values := make(map[string]any)
	if err := plist.NewDecoder(bytes.NewReader(source)).Decode(&values); err != nil {
		return nil, err
	}
	return values, nil
}

func launchConstraintFact(source []byte, missing ComparisonPlistFact) ComparisonPlistFact {
	if len(source) == 0 {
		return missing
	}
	return normalizedPlistFact("der", source, func() (any, error) {
		return cstypes.ParseLaunchContraints(source)
	})
}

func normalizedPlistFact(encoding string, source []byte, parse func() (any, error)) ComparisonPlistFact {
	fact := ComparisonPlistFact{
		Status:         "unavailable",
		SourceEncoding: encoding,
		SourceSHA256:   sha256Hex(source),
	}
	value, err := parse()
	if err != nil {
		return fact
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fact
	}
	fact.Status = "present"
	fact.Value = data
	return fact
}

func absentPlistFact() ComparisonPlistFact {
	return ComparisonPlistFact{Status: "absent", SourceEncoding: "", SourceSHA256: ""}
}

func unavailablePlistFact() ComparisonPlistFact {
	return ComparisonPlistFact{Status: "unavailable", SourceEncoding: "", SourceSHA256: ""}
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
