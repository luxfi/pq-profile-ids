package profile

import (
	"testing"

	"golang.org/x/crypto/sha3"
)

// kat re-derives keccak256 of the input string at runtime so a typo in
// one of the pinned hex constants cannot ship undetected. This is the
// Go side of the cross-language KAT in KAT.md.
func kat(t *testing.T, name string, want ID) {
	t.Helper()
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(name))
	var got ID
	copy(got[:], h.Sum(nil))
	if got != want {
		t.Fatalf("kat mismatch for %q\n got: %s\nwant: %s", name, got.Hex(), want.Hex())
	}
}

func TestProfileIDs_KAT(t *testing.T) {
	kat(t, "PROFILE_CLASSICAL_COMPAT", ProfileClassicalCompat)
	kat(t, "PROFILE_QUASAR_STRICT_PQ", ProfileQuasarStrictPQ)
	kat(t, "PROFILE_HYBRID", ProfileHybrid)
}

func TestPolicyIDs_KAT(t *testing.T) {
	kat(t, "ProofPolicyGroth16BN254", PolicyGroth16BN254)
	kat(t, "ProofPolicyPLONKBN254", PolicyPLONKBN254)
	kat(t, "ProofPolicyKZGBLS12381", PolicyKZGBLS12381)
	kat(t, "ProofPolicySTARKFRISHA3PQ", PolicySTARKFRISHA3)
	kat(t, "ProofPolicyMLDSA65FIPS204", PolicyMLDSA65FIPS204)
}

func TestRefuseUnderStrictPQ_ClassicalCompat_AllowsAll(t *testing.T) {
	for _, p := range []ID{
		PolicyGroth16BN254, PolicyPLONKBN254, PolicyKZGBLS12381,
		PolicySTARKFRISHA3, PolicyMLDSA65FIPS204,
	} {
		if err := RefuseUnderStrictPQ(ProfileClassicalCompat, p); err != nil {
			t.Fatalf("classical-compat must allow %s: %v", p.Hex(), err)
		}
	}
}

func TestRefuseUnderStrictPQ_StrictPQ_RefusesClassical(t *testing.T) {
	for _, p := range []ID{PolicyGroth16BN254, PolicyPLONKBN254, PolicyKZGBLS12381} {
		err := RefuseUnderStrictPQ(ProfileQuasarStrictPQ, p)
		if err == nil {
			t.Fatalf("strict-PQ must refuse %s", p.Hex())
		}
		if _, ok := err.(*VerifierRefusedError); !ok {
			t.Fatalf("want *VerifierRefusedError, got %T: %v", err, err)
		}
	}
}

func TestRefuseUnderStrictPQ_StrictPQ_AllowsPQ(t *testing.T) {
	for _, p := range []ID{PolicySTARKFRISHA3, PolicyMLDSA65FIPS204} {
		if err := RefuseUnderStrictPQ(ProfileQuasarStrictPQ, p); err != nil {
			t.Fatalf("strict-PQ must allow %s: %v", p.Hex(), err)
		}
	}
}

func TestRefuseUnderStrictPQ_UnknownProfile(t *testing.T) {
	var bogus ID
	bogus[0] = 0xde
	bogus[1] = 0xad
	err := RefuseUnderStrictPQ(bogus, PolicySTARKFRISHA3)
	if err == nil {
		t.Fatal("unknown profile must be rejected")
	}
	if _, ok := err.(*UnknownProfileError); !ok {
		t.Fatalf("want *UnknownProfileError, got %T: %v", err, err)
	}
	// Hybrid is reserved → also rejected today.
	if err := RefuseUnderStrictPQ(ProfileHybrid, PolicySTARKFRISHA3); err == nil {
		t.Fatal("hybrid profile is reserved and must reject for now")
	}
}

func TestIsPQScheme(t *testing.T) {
	for _, ok := range []string{SchemePulsarMLWE, SchemeCoronaRLWE, SchemeDoubleLattice} {
		if !IsPQScheme(ok) {
			t.Fatalf("IsPQScheme(%q) = false; want true", ok)
		}
	}
	for _, nope := range []string{SchemeECDSAGG18, SchemeECDSACGGMP21, SchemeFROSTRFC9591, "bogus"} {
		if IsPQScheme(nope) {
			t.Fatalf("IsPQScheme(%q) = true; want false", nope)
		}
	}
}
