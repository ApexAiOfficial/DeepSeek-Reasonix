package evidence

import "testing"

// Cryptographic manifest verification was rejected as "opaque" purely because
// the shared taxonomy had no entry for it. These lock the new family's shape
// and, just as importantly, its limits.

func TestIntegrityVerificationAccepted(t *testing.T) {
	for _, cmd := range []string{
		"sha256sum -c MANIFEST.sha256",
		"sha256sum --check MANIFEST.sha256",
		"sha512sum -c sums.txt",
		"md5sum -c MD5SUMS",
		"b2sum -c B2SUMS",
		"sha256sum --check --status MANIFEST.sha256",
		"sha256sum -c --ignore-missing MANIFEST.sha256",
		"sha256sum -cw MANIFEST.sha256",
		"cd dist && sha256sum -c MANIFEST.sha256",
	} {
		if !bashCommandIsVerification(cmd) {
			t.Errorf("expected verification: %q", cmd)
		}
	}
}

func TestIntegrityVerificationRejected(t *testing.T) {
	for _, cmd := range []string{
		"sha256sum some-file",          // computes digests, proves no expectation
		"sha256sum *.tar.gz",           // ditto
		"sha256sum --check",            // no manifest operand
		"sha256sum -c",                 // ditto
		"sha256sum --tag MANIFEST",     // BSD digest emission, not a check
		"sha256sum -c -",               // stdin: no auditable manifest
		"sha256sum -c MANIFEST > out",  // write-producing chain
		"sha256sum --frobnicate M",     // unknown flag must fail closed
		"echo OK",
		"true",
		"cat MANIFEST.sha256",
	} {
		if bashCommandIsVerification(cmd) {
			t.Errorf("expected rejection: %q", cmd)
		}
	}
}

// Requirement H: integrity is not behavioral verification. A delivery task that
// needs tests must not be satisfiable by a checksum.
func TestIntegrityIsNotFullProjectVerification(t *testing.T) {
	for _, cmd := range []string{
		"sha256sum -c MANIFEST.sha256",
		"sha512sum -c sums.txt",
	} {
		if !bashCommandIsVerification(cmd) {
			t.Fatalf("precondition: %q should be a recognized verifier", cmd)
		}
		if IsFullVerificationCommand(cmd) {
			t.Errorf("integrity check must NOT count as full project verification: %q", cmd)
		}
	}
	// Negative control: a real behavioral verifier still is one.
	if !IsFullVerificationCommand("go test ./...") {
		t.Error("go test ./... must remain full project verification")
	}
}

// The classifier is shared with the final-readiness gate; existing families
// must be untouched by this change.
func TestExistingVerifierFamiliesUnchanged(t *testing.T) {
	for _, cmd := range []string{
		"go test ./...", "go vet ./...", "pytest", "npm test", "cargo check",
		"golangci-lint run", "make test", "python3 -m pytest",
		"git diff --check", "dotnet test", "swift test",
	} {
		if !bashCommandIsVerification(cmd) {
			t.Errorf("regression: %q no longer recognized", cmd)
		}
	}
	for _, cmd := range []string{"go build ./...", "npm run build", "ls", "git status"} {
		if bashCommandIsVerification(cmd) {
			t.Errorf("regression: %q wrongly recognized", cmd)
		}
	}
}
