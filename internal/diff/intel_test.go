package diff

import "testing"

func TestClassifyString(t *testing.T) {
	cases := []struct {
		in   string
		want stringCategory
	}{
		{"https://api.example.com/v3/foo", catURL},
		{"ws://realtime.example.com/sock", catURL},

		{"/v3/session/refresh", catAPI},
		{"/graphql", catAPI},

		{"query MeWithBilling { __typename }", catGraphQL},
		{"mutation UpdateProfile($id: ID!)", catGraphQL},

		{"refresh_token", catAuthToken},
		{"x-api-key", catAuthToken},
		{"Bearer ", catAuthToken},

		{"SecTrustEvaluateWithError", catJailbreak}, // crypto-adjacent but listed in jailbreak needles
		{"PT_DENY_ATTACH", catJailbreak},
		{"/Applications/Cydia.app", catJailbreak},

		{"AES-256-GCM", catCrypto},
		{"PBKDF2", catCrypto},
		{"kSecAttrKeyType", catCrypto},

		{"firebase_remote_config", catThirdParty},
		{"io.sentry.transport", catThirdParty},

		{"feature_flag_login_v2", catFeatureFlag},
		{"experiment_login_revamp", catFeatureFlag},

		{"/usr/lib/dyld", catFilePath},
		{"/System/Library/Frameworks/Foundation.framework/Foundation", catFilePath},

		{"Failed to fetch user", catError},
		{"Error: bad request", catError},

		// Nothing matches → unclassified.
		{"some random literal", catUnclassified},
		{"FooBarBaz", catUnclassified},
	}
	for _, tc := range cases {
		got := classifyString(tc.in)
		if got != tc.want {
			t.Errorf("classifyString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsNoise(t *testing.T) {
	noise := []string{
		"abc",                                          // too short
		"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",         // uuid
		"12345678901234567890",                         // all digits
		"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5IEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla", // long base64 blob
	}
	for _, s := range noise {
		if !isNoise(s) {
			t.Errorf("isNoise(%q) = false, want true", s)
		}
	}
	signal := []string{
		"/v3/auth/login",
		"refresh_token",
		"https://api.example.com",
		"AES-256-GCM",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123",  // JWT-shaped survives
	}
	for _, s := range signal {
		if isNoise(s) {
			t.Errorf("isNoise(%q) = true, want false", s)
		}
	}
}

func TestClassifyFramework(t *testing.T) {
	cases := []struct {
		in   string
		want frameworkCategory
	}{
		{"/System/Library/Frameworks/CryptoKit.framework/CryptoKit", fwCrypto},
		{"/System/Library/Frameworks/DeviceCheck.framework/DeviceCheck", fwCrypto},
		{"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication", fwAuth},
		{"/System/Library/Frameworks/AdSupport.framework/AdSupport", fwAds},
		{"/System/Library/Frameworks/PassKit.framework/PassKit", fwPayments},
		{"@rpath/Sentry.framework/Sentry", fwAnalytics},
		{"@rpath/Firebase.framework/Firebase", fwAnalytics},
		{"/System/Library/Frameworks/UIKit.framework/UIKit", fwUI},
		{"/usr/lib/libSystem.B.dylib", fwApple},
		{"/usr/lib/swift/libswiftCore.dylib", fwApple},
		{"@rpath/SomeRandomThirdParty.framework/SomeRandomThirdParty", fwUnknownThird},
	}
	for _, tc := range cases {
		got := classifyFramework(tc.in)
		if got != tc.want {
			t.Errorf("classifyFramework(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSummarizeObjCDiff(t *testing.T) {
	// Synthetic unified diff body. The "+"/"-" at line start are diff prefixes;
	// the ObjC syntax "@interface" / "+ (Type)method" is the body we count.
	diff := `
+@interface NewClass : NSObject
-@interface OldClass : NSObject
+@protocol NewProto <NSObject>
+ - (void)addedInstanceMethod;
+ + (NSString *)addedClassMethod;
- - (void)removedMethod:(id)arg;
 @end
`
	s := summarizeObjCDiff(diff)
	if s.AddedClasses != 1 {
		t.Errorf("AddedClasses = %d, want 1", s.AddedClasses)
	}
	if s.RemovedClasses != 1 {
		t.Errorf("RemovedClasses = %d, want 1", s.RemovedClasses)
	}
	if s.AddedProtocols != 1 {
		t.Errorf("AddedProtocols = %d, want 1", s.AddedProtocols)
	}
	if s.AddedMethods != 2 {
		t.Errorf("AddedMethods = %d, want 2", s.AddedMethods)
	}
	if s.RemovedMethods != 1 {
		t.Errorf("RemovedMethods = %d, want 1", s.RemovedMethods)
	}
}

func TestSummarizeSwiftDiff(t *testing.T) {
	diff := `
+struct NewStruct {
+    func newMethod() {}
+}
-class OldThing {
-    func obsoleteMethod() {}
-}
+protocol NewProto {}
+enum NewEnum { case a, b }
+actor NewActor {}
`
	s := summarizeSwiftDiff(diff)
	if s.AddedClasses != 3 { // struct + enum + actor
		t.Errorf("AddedClasses = %d, want 3", s.AddedClasses)
	}
	if s.RemovedClasses != 1 {
		t.Errorf("RemovedClasses = %d, want 1", s.RemovedClasses)
	}
	if s.AddedMethods != 1 {
		t.Errorf("AddedMethods = %d, want 1", s.AddedMethods)
	}
	if s.RemovedMethods != 1 {
		t.Errorf("RemovedMethods = %d, want 1", s.RemovedMethods)
	}
	if s.AddedProtocols != 1 {
		t.Errorf("AddedProtocols = %d, want 1", s.AddedProtocols)
	}
}

func TestAggregateFindings(t *testing.T) {
	imp := &ImportIntel{
		Added: map[frameworkCategory][]string{
			fwCrypto:    {"DeviceCheck.framework"},
			fwAnalytics: {"Firebase.framework"},
		},
		Removed: map[frameworkCategory][]string{},
	}
	strs := &StringIntel{
		Added: map[stringCategory][]string{
			catJailbreak: {"jailbreak"},
			catAuthToken: {"refresh_token"},
			catURL:       {"https://new.example.com/api"},
		},
		Removed: map[stringCategory][]string{},
	}
	objc := metaSummary{AddedClasses: 2, AddedMethods: 5}
	swift := metaSummary{}

	fs := AggregateFindings(imp, strs, objc, swift)
	high, med, info := FindingCounts(fs)
	if high == 0 {
		t.Errorf("expected at least one high finding, got 0")
	}
	if med == 0 {
		t.Errorf("expected at least one medium finding, got 0")
	}
	if info == 0 {
		t.Errorf("expected at least one info finding (objc summary), got 0")
	}
}

func TestAggregateFindings_Empty(t *testing.T) {
	fs := AggregateFindings(
		&ImportIntel{Added: map[frameworkCategory][]string{}, Removed: map[frameworkCategory][]string{}},
		&StringIntel{Added: map[stringCategory][]string{}, Removed: map[stringCategory][]string{}},
		metaSummary{}, metaSummary{},
	)
	if len(fs) != 0 {
		t.Errorf("expected no findings, got %d: %+v", len(fs), fs)
	}
}

func TestStringIntel_AddedHosts(t *testing.T) {
	si := &StringIntel{
		Added: map[stringCategory][]string{
			catURL: {
				"https://api.example.com/v3/auth",
				"https://api.example.com/v3/feed",
				"https://telemetry.example.com/ingest",
			},
		},
	}
	hosts := si.addedHosts()
	if len(hosts) != 2 {
		t.Errorf("addedHosts returned %d, want 2: %v", len(hosts), hosts)
	}
}
