package embed

// DefaultVersion is the stackql release this module version was developed
// and conformance-tested against. cmd/stackql-mcp-fetch defaults to it.
//
// The server binary carries its own crypto/x509, so it needs the SPKI
// denylist for the compromised eMudhra intermediates (GO-2026-6809,
// CVE-2026-111943) compiled in: keep DefaultVersion on a release built
// with go1.26.10+ or go1.27.3+. 0.12.824 is built with go1.27.3.
const DefaultVersion = "0.12.824"

// BundlePins maps platform key to the published sha256 of the release
// .mcpb bundle for DefaultVersion, copied from the release's .sha256
// assets. The fetch tool verifies downloads against these before
// extracting the binary; for other versions it fetches the pin from the
// release at download time.
var BundlePins = map[string]string{
	PlatformLinuxX64:        "f842da3c2e1912acfdf99b04a8c88eae04842818504e1758678c1e7d77b33d37",
	PlatformLinuxARM64:      "65c7f98f88f505ab3c5408e47aff8c0337f3b55b0e41f9d97d75ef575320fe06",
	PlatformWindowsX64:      "7e09762b6c465705683907d4064d4c20f3c8fb7f340d14d9b9fe944dfa0f96d8",
	PlatformDarwinUniversal: "1e864f28b13f2c25be68128853f7804245e95bea7d0b7bd925e203c1ea0925cf",
}
