// Package diff: intelligence layer.
//
// intel.go contains pure-function classifiers and aggregators that turn
// the structural diff data (imports, cstrings, ObjC/Swift text diffs)
// into a researcher-facing report:
//
//   - classifyString    → which "kind" of string changed (URL, API path,
//                         auth token, jailbreak keyword, etc.)
//   - classifyFramework → which "kind" of library was added/removed
//                         (Crypto, Auth, Analytics, Apple-system, …)
//   - summarize{ObjC,Swift}Diff
//                       → +N classes / -N methods style counts from the
//                         line shapes inside an already-rendered unified
//                         diff body
//   - AggregateFindings → produces a tiered list (High/Medium/Info) from
//                         all of the above
//
// Everything is testable in isolation (no I/O, no globals besides the
// rule tables). Heuristic by design — when a rule misfires, the raw
// unified ```diff blocks below the intel layer remain ground truth.
package diff

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// string classification
// ---------------------------------------------------------------------------

type stringCategory string

const (
	catURL          stringCategory = "URLs / Domains"
	catAPI          stringCategory = "API Paths"
	catGraphQL      stringCategory = "GraphQL"
	catAuthToken    stringCategory = "Auth / Token"
	catCrypto       stringCategory = "Crypto / Security"
	catJailbreak    stringCategory = "Jailbreak / Runtime Detection"
	catFilePath     stringCategory = "File Paths"
	catThirdParty   stringCategory = "Third-Party SDKs"
	catFeatureFlag  stringCategory = "Feature Flags"
	catError        stringCategory = "Error / Log Messages"
	catUnclassified stringCategory = "Unclassified"
)

// stringCategoryOrder is the render order. catUnclassified is last so
// the categorized signal floats to the top.
var stringCategoryOrder = []stringCategory{
	catURL, catAPI, catGraphQL, catAuthToken, catCrypto,
	catJailbreak, catThirdParty, catFilePath, catFeatureFlag, catError,
	catUnclassified,
}

var (
	reURL = regexp.MustCompile(`^(https?|wss?)://`)
	// API path: leading "/", at least one path segment, may have more.
	// Accepts /graphql, /v3/auth, /api/v1/users, etc.
	reAPIPath  = regexp.MustCompile(`^/[A-Za-z][A-Za-z0-9_-]*(/[A-Za-z0-9._:{}-]+)*/?$`)
	reGraphQL  = regexp.MustCompile(`(?i)(^|\b)(query|mutation|subscription)\s+\w|__typename`)
	reJWTLike  = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}$`)
	reFilePath = regexp.MustCompile(`^/(usr|System|Library|var|private|Applications|tmp|dev|bin|sbin|etc)/`)
	reUUID     = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	reAllDigit = regexp.MustCompile(`^[0-9]+$`)
	reB64Long  = regexp.MustCompile(`^[A-Za-z0-9+/=]{60,}$`)
)

// authTokens / cryptoNeedles / etc. are substring lists; checked case-
// insensitively. Order doesn't matter — first hit wins per category.
var (
	authTokens = []string{
		"refresh_token", "access_token", "id_token", "bearer ",
		"oauth", "x-api-key", "x-auth-token", "x-session-token",
		"session_id", "session_token", "csrf_token",
		"authorization", "Bearer ",
	}
	cryptoNeedles = []string{
		"AES", "RSA", "HMAC", "PBKDF2", "scrypt", "Argon2",
		"SecKey", "SecTrust", "SecCertificate", "kSec",
		"CommonCrypto", "CryptoKit", "secp256", "Curve25519",
		"libsodium", "ChaCha20", "Poly1305",
	}
	jailbreakNeedles = []string{
		"jailbreak", "jailbroken", "/Applications/Cydia", "/Library/MobileSubstrate",
		"MobileSubstrate", "frida", "Frida", "ptrace", "PT_DENY_ATTACH",
		"sysctl", "SecTrustEvaluateWithError", "deviceIntegrity",
		"checkra", "unc0ver", "Substitute", "RocketBootstrap",
		"checkm8", "dopamine",
	}
	thirdPartyNeedles = []string{
		"firebase", "FirebaseApp", "Firebase/", "FIREBASE",
		"Sentry", "io.sentry",
		"Amplitude", "Mixpanel", "Segment", "Datadog", "Heap",
		"Adjust", "AppsFlyer", "Branch",
		"OneSignal", "Optimizely",
		"GraphQLClient", "Apollo", "URBranch",
	}
	featureFlagNeedles = []string{
		"feature_flag", "feature-flag", "FeatureFlag",
		"experiment_", "ab_test_",
		"RemoteConfig", "remote_config",
	}
	errorMessagePrefixes = []string{
		`failed to `, `error: `, `Error: `, `unable to `, `Unable to `,
		`panic:`, `fatal error`,
	}
)

// classifyString returns the first matching category for s. Ordered to
// avoid generic categories swallowing specific ones (e.g. "auth token"
// before "url" — a refresh token could appear inside a URL fragment).
func classifyString(s string) stringCategory {
	low := strings.ToLower(s)

	// Specific lexical hits first.
	if containsAnyCI(low, authTokens) {
		return catAuthToken
	}
	if containsAnyCI(low, jailbreakNeedles) || containsAny(s, jailbreakNeedles) {
		// jailbreak needles are sometimes case-sensitive (e.g. PT_DENY_ATTACH).
		return catJailbreak
	}
	if containsAny(s, cryptoNeedles) {
		// crypto identifiers are usually case-significant.
		return catCrypto
	}
	if reGraphQL.MatchString(s) {
		return catGraphQL
	}
	if containsAnyCI(low, thirdPartyNeedles) || containsAny(s, thirdPartyNeedles) {
		return catThirdParty
	}
	if containsAnyCI(low, featureFlagNeedles) {
		return catFeatureFlag
	}

	// URLs first; file-system paths *before* API paths so /usr/lib/dyld
	// doesn't get mis-classified as an HTTP path.
	if reURL.MatchString(s) {
		return catURL
	}
	if reFilePath.MatchString(s) {
		return catFilePath
	}
	if reAPIPath.MatchString(s) {
		return catAPI
	}

	// Error messages — match case-insensitively to handle both
	// "Failed to ..." and "failed to ..." styles.
	if hasAnyPrefixCI(low, errorMessagePrefixes) {
		return catError
	}

	return catUnclassified
}

// isNoise drops strings that are clearly not researcher-actionable.
// Conservative — false negatives (noise classed as signal) are far less
// harmful than dropping a meaningful indicator.
func isNoise(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 6 {
		return true
	}
	if reUUID.MatchString(t) {
		return true
	}
	if reAllDigit.MatchString(t) {
		return true
	}
	if reB64Long.MatchString(t) && !reJWTLike.MatchString(t) {
		// Big base64 blob with no dots → almost certainly an opaque
		// resource, hash, or embedded binary. Skip. JWT-shaped values
		// (header.payload.sig) pass through and land in catAuthToken.
		return true
	}
	return false
}

// StringIntel groups added/removed strings by category. Categories with
// no entries are absent from the map.
type StringIntel struct {
	Added   map[stringCategory][]string
	Removed map[stringCategory][]string
}

// ClassifyStringDelta categorizes the added/removed string sets,
// dropping noise. Caller passes the already-set-diffed slices (e.g.
// from vmacho.DiffCStringsTyped).
func ClassifyStringDelta(added, removed []string) *StringIntel {
	out := &StringIntel{
		Added:   map[stringCategory][]string{},
		Removed: map[stringCategory][]string{},
	}
	for _, s := range added {
		if isNoise(s) {
			continue
		}
		c := classifyString(s)
		out.Added[c] = append(out.Added[c], s)
	}
	for _, s := range removed {
		if isNoise(s) {
			continue
		}
		c := classifyString(s)
		out.Removed[c] = append(out.Removed[c], s)
	}
	// Stable sort each bucket so render output is deterministic.
	for _, m := range []map[stringCategory][]string{out.Added, out.Removed} {
		for k := range m {
			sort.Strings(m[k])
		}
	}
	return out
}

// addedHosts returns the unique URL hosts in the added bucket, useful
// for the findings aggregator to detect "new domain reached".
func (si *StringIntel) addedHosts() []string {
	seen := map[string]bool{}
	for _, s := range si.Added[catURL] {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			seen[u.Host] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// framework / dylib classification
// ---------------------------------------------------------------------------

type frameworkCategory string

const (
	fwApple        frameworkCategory = "Apple system"
	fwCrypto       frameworkCategory = "Crypto / Security"
	fwAuth         frameworkCategory = "Auth / Identity"
	fwNetworking   frameworkCategory = "Networking"
	fwAnalytics    frameworkCategory = "Analytics"
	fwAds          frameworkCategory = "Ads / Tracking"
	fwPayments     frameworkCategory = "Payments"
	fwStorage      frameworkCategory = "Storage"
	fwUI           frameworkCategory = "UI"
	fwUnknownThird frameworkCategory = "Unknown third-party"
)

var fwCategoryOrder = []frameworkCategory{
	fwCrypto, fwAuth, fwPayments, fwAds, fwAnalytics, fwNetworking,
	fwStorage, fwUI, fwApple, fwUnknownThird,
}

// fwRule matches an imported-library path. Order matters: specific
// security categories run before broad "Apple system" so that
// CryptoKit.framework lands in Crypto, not Apple.
type fwRule struct {
	cat   frameworkCategory
	match func(string) bool
}

var fwRules = []fwRule{
	{fwCrypto, hasAnyContains("CryptoKit", "CommonCrypto", "DeviceCheck", "AppAttest", "/Security.framework", "/Security ")},
	{fwAuth, hasAnyContains("LocalAuthentication", "AuthenticationServices", "ASWebAuthenticationSession", "ASAuth")},
	{fwAds, hasAnyContains("AdSupport", "AdServices", "AppTrackingTransparency")},
	{fwPayments, hasAnyContains("PassKit", "StoreKit", "ApplePay")},
	{fwAnalytics, hasAnyContainsCI("Firebase", "Sentry", "Amplitude", "Datadog", "Mixpanel", "Segment", "Adjust", "AppsFlyer", "Branch", "Heap", "OneSignal")},
	{fwNetworking, hasAnyContains("/Network.framework", "CFNetwork", "Alamofire", "AFNetworking", "URLSession")},
	{fwStorage, hasAnyContains("CoreData", "Realm", "GRDB", "SQLite", "libsqlite")},
	{fwUI, hasAnyContains("/UIKit.framework", "/SwiftUI.framework")},
	// Final Apple-system fallback runs after every specific match.
	{fwApple, isApplePath},
}

func classifyFramework(name string) frameworkCategory {
	for _, r := range fwRules {
		if r.match(name) {
			return r.cat
		}
	}
	return fwUnknownThird
}

// isApplePath flags Apple-shipped libraries by path prefix.
func isApplePath(s string) bool {
	return strings.HasPrefix(s, "/System/Library/") ||
		strings.HasPrefix(s, "/usr/lib/") ||
		strings.Contains(s, "/Frameworks/") && strings.HasPrefix(s, "/System/")
}

// ImportIntel groups added/removed imports by framework category.
type ImportIntel struct {
	Added   map[frameworkCategory][]string
	Removed map[frameworkCategory][]string
}

func ClassifyImportDelta(added, removed []string) *ImportIntel {
	out := &ImportIntel{
		Added:   map[frameworkCategory][]string{},
		Removed: map[frameworkCategory][]string{},
	}
	for _, n := range added {
		c := classifyFramework(n)
		out.Added[c] = append(out.Added[c], n)
	}
	for _, n := range removed {
		c := classifyFramework(n)
		out.Removed[c] = append(out.Removed[c], n)
	}
	for _, m := range []map[frameworkCategory][]string{out.Added, out.Removed} {
		for k := range m {
			sort.Strings(m[k])
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// ObjC / Swift line-prefix counters
// ---------------------------------------------------------------------------

// metaSummary is a coarse tally of structural changes inside an ObjC or
// Swift unified diff body. Used only for the one-line preamble above
// the raw ```diff block; the underlying diff is authoritative.
type metaSummary struct {
	AddedClasses, RemovedClasses     int
	AddedMethods, RemovedMethods     int
	AddedProtocols, RemovedProtocols int
}

func (s metaSummary) empty() bool {
	return s.AddedClasses+s.RemovedClasses+s.AddedMethods+s.RemovedMethods+
		s.AddedProtocols+s.RemovedProtocols == 0
}

// summarizeObjCDiff counts the line shapes produced by go-macho's
// objc.{Class,Protocol,Category}.Verbose():
//
//   "@interface FooBar :"  → a class line
//   "@protocol FooProto"   → a protocol line
//   "+ ..." / "- ..."      → ObjC method declarations  (also git-diff prefixes!)
//
// The "+/-" overload is tricky: a unified diff already uses '+' and '-'
// at line start for added/removed lines. We only count an ObjC method
// if the second char after the diff prefix is '(' (return-type opener).
func summarizeObjCDiff(diff string) metaSummary {
	var s metaSummary
	for _, line := range strings.Split(diff, "\n") {
		if len(line) < 2 {
			continue
		}
		prefix := line[0]
		body := line[1:]
		switch prefix {
		case '+':
			if isObjCClassLine(body) {
				s.AddedClasses++
			} else if isObjCProtocolLine(body) {
				s.AddedProtocols++
			} else if isObjCMethodLine(body) {
				s.AddedMethods++
			}
		case '-':
			if isObjCClassLine(body) {
				s.RemovedClasses++
			} else if isObjCProtocolLine(body) {
				s.RemovedProtocols++
			} else if isObjCMethodLine(body) {
				s.RemovedMethods++
			}
		}
	}
	return s
}

func isObjCClassLine(body string) bool {
	t := strings.TrimSpace(body)
	return strings.HasPrefix(t, "@interface ")
}

func isObjCProtocolLine(body string) bool {
	t := strings.TrimSpace(body)
	return strings.HasPrefix(t, "@protocol ")
}

// isObjCMethodLine recognises "+ (TypeName)name" / "- (TypeName)name"
// after any leading whitespace. The leading "+" or "-" here is part of
// the ObjC syntax, not the diff prefix — by the time we get here the
// diff prefix has already been stripped.
func isObjCMethodLine(body string) bool {
	t := strings.TrimLeft(body, " \t")
	if len(t) < 4 {
		return false
	}
	if t[0] != '+' && t[0] != '-' {
		return false
	}
	// Require space-then-'(' after the +/-.
	t2 := strings.TrimLeft(t[1:], " \t")
	return strings.HasPrefix(t2, "(")
}

// summarizeSwiftDiff counts shapes from swift.Type.Verbose() and the
// protocol dump fallback (fmt.Sprintf "%+v" of swift.Protocol). The
// upstream output uses "struct ", "class ", "enum ", "protocol ", and
// function declarations as "func ".
func summarizeSwiftDiff(diff string) metaSummary {
	var s metaSummary
	for _, line := range strings.Split(diff, "\n") {
		if len(line) < 2 {
			continue
		}
		prefix := line[0]
		body := strings.TrimLeft(line[1:], " \t")
		switch prefix {
		case '+':
			switch {
			case startsWith(body, "struct ", "class ", "enum ", "actor "):
				s.AddedClasses++
			case startsWith(body, "protocol "):
				s.AddedProtocols++
			case startsWith(body, "func "):
				s.AddedMethods++
			}
		case '-':
			switch {
			case startsWith(body, "struct ", "class ", "enum ", "actor "):
				s.RemovedClasses++
			case startsWith(body, "protocol "):
				s.RemovedProtocols++
			case startsWith(body, "func "):
				s.RemovedMethods++
			}
		}
	}
	return s
}

func startsWith(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// findings aggregator
// ---------------------------------------------------------------------------

// Tier represents the urgency of a finding. Higher = more interesting.
type Tier int

const (
	TierInfo Tier = iota
	TierMedium
	TierHigh
)

func (t Tier) icon() string {
	switch t {
	case TierHigh:
		return "🔴"
	case TierMedium:
		return "🟡"
	}
	return "⚪"
}

// Finding is one line in the security-findings rollup.
type Finding struct {
	Tier   Tier
	Text   string
	Reason string
}

// AggregateFindings turns the classified intel into a tiered finding
// list. Heuristic — false positives are acceptable; the raw diffs below
// the intel layer always tell the truth.
func AggregateFindings(imp *ImportIntel, strs *StringIntel, objc, swift metaSummary) []Finding {
	var out []Finding
	add := func(t Tier, text, reason string) {
		out = append(out, Finding{Tier: t, Text: text, Reason: reason})
	}

	// --- imports ---
	if imp != nil {
		for _, lib := range imp.Added[fwCrypto] {
			add(TierHigh, "New "+lib+" linked", "Crypto / security framework — affects threat model")
		}
		for _, lib := range imp.Added[fwAuth] {
			add(TierHigh, "New "+lib+" linked", "Authentication / identity framework")
		}
		for _, lib := range imp.Added[fwPayments] {
			add(TierHigh, "New "+lib+" linked", "Payments framework — sensitive code paths")
		}
		for _, lib := range imp.Added[fwAnalytics] {
			add(TierMedium, "New "+lib+" linked", "Analytics SDK — data egress surface")
		}
		for _, lib := range imp.Added[fwAds] {
			add(TierMedium, "New "+lib+" linked", "Ads / tracking framework")
		}
		for _, lib := range imp.Removed[fwCrypto] {
			add(TierMedium, "Removed "+lib, "Crypto / security framework removed")
		}
	}

	// --- strings ---
	if strs != nil {
		if jb := strs.Added[catJailbreak]; len(jb) > 0 {
			label := jb[0]
			extra := ""
			if len(jb) > 1 {
				extra = fmt.Sprintf(" (+%d more)", len(jb)-1)
			}
			add(TierHigh, "New jailbreak/runtime-detection string `"+label+"`"+extra,
				"May affect dynamic analysis / Frida hooks")
		}
		if at := strs.Added[catAuthToken]; len(at) > 0 {
			add(TierHigh,
				fmt.Sprintf("%d new auth/token-related string(s)", len(at)),
				"Auth or session-handling logic changed")
		}
		if cr := strs.Added[catCrypto]; len(cr) > 0 {
			add(TierMedium,
				fmt.Sprintf("%d new crypto-related string(s)", len(cr)),
				"Crypto API usage changed")
		}
		if hosts := strs.addedHosts(); len(hosts) > 0 {
			label := hosts[0]
			extra := ""
			if len(hosts) > 1 {
				extra = fmt.Sprintf(" (+%d more)", len(hosts)-1)
			}
			add(TierMedium, "New host contacted: `"+label+"`"+extra,
				"New domain in URLs — networking surface changed")
		}
		if api := strs.Added[catAPI]; len(api) > 0 {
			add(TierMedium,
				fmt.Sprintf("%d new API path(s)", len(api)),
				"New backend endpoints — review for auth / rate limiting")
		}
		if tp := strs.Added[catThirdParty]; len(tp) > 0 {
			add(TierInfo,
				fmt.Sprintf("%d new third-party-SDK string(s)", len(tp)),
				"Third-party library identifiers")
		}
	}

	// --- ObjC / Swift classes that look security-relevant ---
	if !objc.empty() {
		add(TierInfo,
			fmt.Sprintf("Obj-C: +%d classes / -%d, +%d methods / -%d, +%d protocols / -%d",
				objc.AddedClasses, objc.RemovedClasses,
				objc.AddedMethods, objc.RemovedMethods,
				objc.AddedProtocols, objc.RemovedProtocols),
			"Coarse counts from unified diff")
	}
	if !swift.empty() {
		add(TierInfo,
			fmt.Sprintf("Swift: +%d types / -%d, +%d funcs / -%d, +%d protocols / -%d",
				swift.AddedClasses, swift.RemovedClasses,
				swift.AddedMethods, swift.RemovedMethods,
				swift.AddedProtocols, swift.RemovedProtocols),
			"Coarse counts from unified diff")
	}

	return out
}

// FindingCounts returns counts per tier — useful for the README rollup.
func FindingCounts(fs []Finding) (high, medium, info int) {
	for _, f := range fs {
		switch f.Tier {
		case TierHigh:
			high++
		case TierMedium:
			medium++
		case TierInfo:
			info++
		}
	}
	return
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// containsAny reports whether s contains any of needles (case-sensitive).
func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// containsAnyCI reports whether lowered-s contains any of needles
// (lower-cased by caller for hot-path efficiency).
func containsAnyCI(lower string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(lower, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hasAnyPrefixCI checks lower-cased s against lower-cased prefixes.
// Caller passes already-lowered s for hot-path efficiency.
func hasAnyPrefixCI(lower string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// hasAnyContains returns a predicate: "does the input contain any needle"
// (case-sensitive). For Framework path matching.
func hasAnyContains(needles ...string) func(string) bool {
	return func(s string) bool {
		for _, n := range needles {
			if strings.Contains(s, n) {
				return true
			}
		}
		return false
	}
}

// hasAnyContainsCI is the case-insensitive variant.
func hasAnyContainsCI(needles ...string) func(string) bool {
	return func(s string) bool {
		low := strings.ToLower(s)
		for _, n := range needles {
			if strings.Contains(low, strings.ToLower(n)) {
				return true
			}
		}
		return false
	}
}
