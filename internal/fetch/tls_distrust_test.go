package fetch

// Guards the TLS trust floor this module depends on.
//
// In October 2026 the private keys of eight eMudhra intermediate CAs were
// compromised. Go's mitigation (GO-2026-6809, CVE-2026-111943, Go issue
// 82345) is an SPKI denylist inside crypto/x509 that drops any chain
// containing one of the keys, on every platform including the Windows and
// macOS system-verify paths. It shipped in go1.26.10 and go1.27.3; Go 1.25
// is out of support and never received it. go.mod sets the floor, but a
// developer running with GOTOOLCHAIN=local on an older toolchain can still
// compile this module, so this test checks the behaviour directly.
//
// Without it a Go program accepts the intermediates' Sectigo
// cross-signatures: those chain to the AAA Certificate Services root,
// which every trust store carries, Go consults no CRLs, and Linux trust
// stores have no block list. testdata/emudhra-intermediates-aaa.pem holds the
// public certificates of the eight intermediates as cross-signed by that
// root; testdata/aaa-certificate-services-root.pem is the root. No private
// key material is involved: each intermediate is verified as a leaf
// against the root and must be rejected.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// distrustedSPKIs are the sha256 hashes of the compromised keys' subject
// public key info, as listed in Go's crypto/x509 (distrustedSPKIHashes in
// verify.go) and in Mozilla Bugzilla 2083449.
var distrustedSPKIs = map[string]string{
	"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": "EM DV TLS CA - G3B",
	"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": "EM OV TLS CA - G3B",
	"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": "EM EV TLS CA - G3B",
	"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": "EM DV TLS CA - G3C",
	"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": "EM OV TLS CA - G3C",
	"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": "EM EV TLS CA - G3C",
	"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": "EM OV CS CA - G3B",
	"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": "EM OV CS CA - G3C",
}

func loadCerts(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs = append(certs, c)
	}
	return certs
}

func TestToolchainDistrustsCompromisedEMudhraIntermediates(t *testing.T) {
	rootCerts := loadCerts(t, "aaa-certificate-services-root.pem")
	if len(rootCerts) != 1 {
		t.Fatalf("expected 1 root, got %d", len(rootCerts))
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCerts[0])
	opts := x509.VerifyOptions{
		Roots: roots,
		// Inside every intermediate's validity (2025-05-14 to 2028-12-31),
		// so the outcome does not change when they expire.
		CurrentTime: time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Control: the root verifies against itself, so a rejection below is
	// the denylist, not a broken pool.
	if _, err := rootCerts[0].Verify(opts); err != nil {
		t.Fatalf("control: AAA Certificate Services did not verify against itself: %v", err)
	}

	intermediates := loadCerts(t, "emudhra-intermediates-aaa.pem")
	if len(intermediates) != len(distrustedSPKIs) {
		t.Fatalf("expected %d intermediates, got %d", len(distrustedSPKIs), len(intermediates))
	}
	seen := map[string]bool{}
	for _, c := range intermediates {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		spki := hex.EncodeToString(sum[:])
		name, ok := distrustedSPKIs[spki]
		if !ok {
			t.Fatalf("testdata %q has SPKI %s, which is not in the published list", c.Subject.CommonName, spki)
		}
		seen[spki] = true
		chains, err := c.Verify(opts)
		if err == nil {
			t.Errorf("%s verified against AAA Certificate Services (%d chain(s)): %s lacks the GO-2026-6809 denylist; build with go1.26.10+ or go1.27.3+",
				name, len(chains), runtime.Version())
			continue
		}
		t.Logf("%s rejected by %s: %v", name, runtime.Version(), err)
	}
	if len(seen) != len(distrustedSPKIs) {
		t.Errorf("testdata covers %d of %d distrusted keys", len(seen), len(distrustedSPKIs))
	}
}
