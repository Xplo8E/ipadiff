package parsers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"

	ventitlements "github.com/Xplo8E/ipadiff/internal/vendored/ipsw_entitlements"
)

// Entitlements holds everything we extract from one binary's code signature.
type Entitlements struct {
	XML               string // empty if no entitlements found
	LaunchSelf        string // JSON if present
	LaunchParent      string
	LaunchResponsible string
}

// ReadFromMacho extracts entitlements and launch constraints from m.
// Tries the standard XML blob first, falls back to DER. Never fails on a
// missing or unsigned binary — returns a zero-valued Entitlements.
func ReadFromMacho(m *macho.File) Entitlements {
	cs := m.CodeSignature()
	if cs == nil {
		return Entitlements{}
	}
	var ent Entitlements

	switch {
	case cs.Entitlements != "":
		ent.XML = cs.Entitlements
	case len(cs.EntitlementsDER) > 0:
		if decoded, err := ventitlements.DerDecode(cs.EntitlementsDER); err == nil {
			ent.XML = decoded
		}
	}

	ent.LaunchSelf = parseLC(cs.LaunchConstraintsSelf)
	ent.LaunchParent = parseLC(cs.LaunchConstraintsParent)
	ent.LaunchResponsible = parseLC(cs.LaunchConstraintsResponsible)

	return ent
}

// Combined returns a single diff-friendly string concatenating the
// entitlements XML and any launch constraints with header comments,
// matching the ipsw `--lc` mode output style.
func (e Entitlements) Combined() string {
	var b strings.Builder
	if e.XML != "" {
		b.WriteString(e.XML)
	}
	if e.LaunchSelf != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("<!-- Launch Constraints (Self) -->\n")
		b.WriteString(e.LaunchSelf)
		b.WriteString("\n")
	}
	if e.LaunchParent != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("<!-- Launch Constraints (Parent) -->\n")
		b.WriteString(e.LaunchParent)
		b.WriteString("\n")
	}
	if e.LaunchResponsible != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("<!-- Launch Constraints (Responsible) -->\n")
		b.WriteString(e.LaunchResponsible)
		b.WriteString("\n")
	}
	return b.String()
}

func parseLC(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	lc, err := cstypes.ParseLaunchContraints(raw)
	if err != nil {
		return fmt.Sprintf("<!-- failed to parse launch constraints: %v -->", err)
	}
	data, err := json.MarshalIndent(lc, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}
