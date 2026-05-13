// Package profile is the canonical source of truth for Lux PQ profile and
// proof-policy identifiers shared across Go, Solidity, and TypeScript.
//
// Every consumer (luxfi/node quasar contract, luxfi/teleport contracts,
// luxfi/teleport mpc, luxfi/teleport api) imports IDs from one place so
// drift between language ports becomes impossible.
//
// Decomplected: the strings here ARE the protocol. They are the keys the
// StrictPQ profile gate, the IVerifier ABI, and the MPC scheme bus all
// compare against. Anything that derives or compares an ID against
// something else is on the wrong side of the boundary.
//
// Wire format: keccak256 of the UTF-8 input string, as [32]byte. The
// strings themselves are stable and case-sensitive — they are checked
// into KAT.md and the test in profile_test.go re-derives every value
// from the input string, so a typo can never ship.
package profile

import (
	"encoding/hex"
)

// ID is the canonical 32-byte identifier (= keccak256 of an input string).
// Compatible with Solidity bytes32 and ethers.id() output.
type ID [32]byte

// Hex returns the 0x-prefixed lowercase hex encoding of the ID.
func (i ID) Hex() string {
	return "0x" + hex.EncodeToString(i[:])
}

// String returns the hex encoding for convenient logging.
func (i ID) String() string {
	return i.Hex()
}

// ─── Profile IDs ────────────────────────────────────────────────────────
//
// PROFILE_CLASSICAL_COMPAT is the default; the profile gate is a no-op.
// PROFILE_QUASAR_STRICT_PQ refuses BN254 / BLS12-381 verifiers and
// classical MPC schemes in any slot a verifier or signer is plugged into.
// PROFILE_HYBRID is reserved for future "classical and PQ in parallel"
// composition; today it is treated by the gate as an unknown profile
// and rejected, which keeps the binary classical-or-strict-PQ choice
// explicit at deploy time.

var (
	ProfileClassicalCompat = mustParseHex("0xff460dabe75e1748cc81f17230386222b67f53a1e8ce1f1176820292194fab7b") // keccak256("PROFILE_CLASSICAL_COMPAT")
	ProfileQuasarStrictPQ  = mustParseHex("0x648ae57d5359236a9608028b38c6dd3d567b40418e9513c146bb71df7d4d0e83") // keccak256("PROFILE_QUASAR_STRICT_PQ")
	ProfileHybrid          = mustParseHex("0x56e230b3af23076ccb38335583e550d2be4f7f33dea829713a2d12adff19774e") // keccak256("PROFILE_HYBRID")
)

// ─── ProofPolicy IDs (refused under strict-PQ in the BN254 / BLS family) ─
var (
	PolicyGroth16BN254  = mustParseHex("0x91cae9e6247c12e7efc5498813eb0339f035757faac42bf27d572c113f507838") // keccak256("ProofPolicyGroth16BN254")
	PolicyPLONKBN254    = mustParseHex("0x5ec6ac94122b75276930288364a62f5544dfbc691b4160344f9aa14d5768fe32") // keccak256("ProofPolicyPLONKBN254")
	PolicyKZGBLS12381   = mustParseHex("0x15d4efdbd8ca26cc89082cba15d73cd942394806fea4a72937ca50f22e6b1b38") // keccak256("ProofPolicyKZGBLS12381")
	PolicySTARKFRISHA3  = mustParseHex("0x36bff5354600cd569f66c4d1b7aaafd0193299577d2171e1e42c01cd9bc6709a") // keccak256("ProofPolicySTARKFRISHA3PQ")
	PolicyMLDSA65FIPS204 = mustParseHex("0x027f4d69dccaa8c1f50e842236389edbc4d5eac5722b4d7960b5373cfd586805") // keccak256("ProofPolicyMLDSA65FIPS204")
)

// ─── MPC scheme policy IDs (string form) ────────────────────────────────
//
// The MPC bus uses the literal string (not the hashed form) because the
// JSON-RPC wire surface between teleport/api ↔ teleport/mpc carries the
// scheme as a human-readable string. Strict-PQ enforcement still happens
// on-chain via the hashed bytes32 form above; this constant table just
// pins the strings.
const (
	SchemeECDSAGG18           = "ECDSA-SECP256K1-GG18"
	SchemeECDSACGGMP21        = "ECDSA-SECP256K1-CGGMP21"
	SchemeFROSTRFC9591        = "SCHNORR-SECP256K1-FROST-RFC9591"
	SchemePulsarMLWE          = "PULSAR-M-LWE-FIPS204T"
	SchemeCoronaRLWE          = "CORONA-R-LWE-RINGTAIL"
	SchemeDoubleLattice       = "DOUBLE-LATTICE-PULSAR+CORONA"
)

// IsPQScheme reports whether the named MPC scheme is acceptable in the
// strict-PQ profile (= the classical / BN254-family schemes are not).
//
// This is the ONE place that gates "is this scheme PQ?". Anything else
// is a leak.
func IsPQScheme(scheme string) bool {
	switch scheme {
	case SchemePulsarMLWE, SchemeCoronaRLWE, SchemeDoubleLattice:
		return true
	default:
		return false
	}
}

// RefuseUnderStrictPQ returns nil if `policy` is acceptable in the active
// `profile`, or an error describing the refusal.
//
// This is the canonical Go implementation of the policy gate. It mirrors
// `StrictPQProfileGate.refuseUnderStrictPQ` in
// `~/work/lux/teleport/contracts/contracts/StrictPQProfileGate.sol`
// 1:1: same set of refused policies, same allow-everything behaviour
// under classical-compat, same UnknownProfile sentinel for any other ID.
//
// Decomplected from "does this proof verify?". The verifier verifies;
// this function decides admissibility.
func RefuseUnderStrictPQ(profile, policy ID) error {
	switch profile {
	case ProfileClassicalCompat:
		return nil
	case ProfileQuasarStrictPQ:
		switch policy {
		case PolicyGroth16BN254, PolicyPLONKBN254, PolicyKZGBLS12381:
			return &VerifierRefusedError{Profile: profile, Policy: policy}
		}
		return nil
	default:
		return &UnknownProfileError{Profile: profile}
	}
}

// VerifierRefusedError is returned when the policy is in the strict-PQ
// refuse-set under PROFILE_QUASAR_STRICT_PQ.
type VerifierRefusedError struct {
	Profile ID
	Policy  ID
}

func (e *VerifierRefusedError) Error() string {
	return "pq-profile: verifier refused under strict-PQ: profile=" +
		e.Profile.Hex() + " policy=" + e.Policy.Hex()
}

// UnknownProfileError is returned when the supplied profile ID is
// neither classical-compat nor strict-PQ. Hybrid is intentionally
// rejected at the gate today.
type UnknownProfileError struct {
	Profile ID
}

func (e *UnknownProfileError) Error() string {
	return "pq-profile: unknown profile id: " + e.Profile.Hex()
}

func mustParseHex(s string) ID {
	if len(s) != 66 || s[0] != '0' || s[1] != 'x' {
		panic("pq-profile: bad pinned hex id: " + s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		panic("pq-profile: bad pinned hex id: " + s + ": " + err.Error())
	}
	var out ID
	copy(out[:], b)
	return out
}
