/**
 * @luxfi/pq-profile-ids — TypeScript surface of the canonical PQ profile
 * and proof-policy identifiers.
 *
 * Single source of truth shared with Go (`go/profile/profile.go`) and
 * Solidity (`solidity/src/PQProfileIDs.sol`). The string inputs are
 * stable and case-sensitive — they are the protocol. The bytes32 form
 * is `keccak256(<utf8 string>)`; pinned here as 0x-prefixed lowercase
 * 32-byte hex so consumers don't have to depend on a keccak lib at
 * import time, with a KAT test re-deriving each value.
 *
 * Decomplected: this module ONLY exposes IDs and the policy-gate
 * function. It does NOT verify proofs. The verifier verifies; the gate
 * decides admissibility. Two responsibilities, two surfaces.
 */

// ─── Profile IDs (UTF-8 input strings) ───────────────────────────────
export const PROFILE_CLASSICAL_COMPAT_STRING = 'PROFILE_CLASSICAL_COMPAT';
export const PROFILE_QUASAR_STRICT_PQ_STRING = 'PROFILE_QUASAR_STRICT_PQ';
export const PROFILE_HYBRID_STRING = 'PROFILE_HYBRID';

// ─── Profile IDs (keccak256, bytes32 hex) ────────────────────────────
export const PROFILE_CLASSICAL_COMPAT =
  '0xff460dabe75e1748cc81f17230386222b67f53a1e8ce1f1176820292194fab7b';
export const PROFILE_QUASAR_STRICT_PQ =
  '0x648ae57d5359236a9608028b38c6dd3d567b40418e9513c146bb71df7d4d0e83';
export const PROFILE_HYBRID =
  '0x56e230b3af23076ccb38335583e550d2be4f7f33dea829713a2d12adff19774e';

// ─── ProofPolicy IDs (UTF-8 input strings) ───────────────────────────
export const POLICY_GROTH16_BN254_STRING = 'ProofPolicyGroth16BN254';
export const POLICY_PLONK_BN254_STRING = 'ProofPolicyPLONKBN254';
export const POLICY_KZG_BLS12381_STRING = 'ProofPolicyKZGBLS12381';
export const POLICY_STARK_FRI_SHA3_PQ_STRING = 'ProofPolicySTARKFRISHA3PQ';
export const POLICY_MLDSA65_FIPS204_STRING = 'ProofPolicyMLDSA65FIPS204';

// ─── ProofPolicy IDs (keccak256, bytes32 hex) ────────────────────────
export const POLICY_GROTH16_BN254 =
  '0x91cae9e6247c12e7efc5498813eb0339f035757faac42bf27d572c113f507838';
export const POLICY_PLONK_BN254 =
  '0x5ec6ac94122b75276930288364a62f5544dfbc691b4160344f9aa14d5768fe32';
export const POLICY_KZG_BLS12381 =
  '0x15d4efdbd8ca26cc89082cba15d73cd942394806fea4a72937ca50f22e6b1b38';
export const POLICY_STARK_FRI_SHA3_PQ =
  '0x36bff5354600cd569f66c4d1b7aaafd0193299577d2171e1e42c01cd9bc6709a';
export const POLICY_MLDSA65_FIPS204 =
  '0x027f4d69dccaa8c1f50e842236389edbc4d5eac5722b4d7960b5373cfd586805';

// ─── MPC scheme strings (wire format) ────────────────────────────────
export const SCHEME_ECDSA_GG18 = 'ECDSA-SECP256K1-GG18';
export const SCHEME_ECDSA_CGGMP21 = 'ECDSA-SECP256K1-CGGMP21';
export const SCHEME_FROST_RFC9591 = 'SCHNORR-SECP256K1-FROST-RFC9591';
export const SCHEME_PULSAR_M_LWE = 'PULSAR-M-LWE-FIPS204T';
export const SCHEME_CORONA_R_LWE = 'CORONA-R-LWE-RINGTAIL';
export const SCHEME_DOUBLE_LATTICE = 'DOUBLE-LATTICE-PULSAR+CORONA';

/** All MPC scheme strings, in registry order. */
export const ALL_SCHEMES: ReadonlyArray<string> = [
  SCHEME_ECDSA_GG18,
  SCHEME_ECDSA_CGGMP21,
  SCHEME_FROST_RFC9591,
  SCHEME_PULSAR_M_LWE,
  SCHEME_CORONA_R_LWE,
  SCHEME_DOUBLE_LATTICE,
];

/** Subset of ALL_SCHEMES that is acceptable under strict-PQ. */
export const PQ_SCHEMES: ReadonlyArray<string> = [
  SCHEME_PULSAR_M_LWE,
  SCHEME_CORONA_R_LWE,
  SCHEME_DOUBLE_LATTICE,
];

/** Returns true iff `scheme` is acceptable in PROFILE_QUASAR_STRICT_PQ. */
export function isPQScheme(scheme: string): boolean {
  return (PQ_SCHEMES as readonly string[]).includes(scheme);
}

// ─── Refused policies under strict-PQ ────────────────────────────────
const REFUSED_UNDER_STRICT_PQ = new Set<string>([
  POLICY_GROTH16_BN254,
  POLICY_PLONK_BN254,
  POLICY_KZG_BLS12381,
]);

export class VerifierRefusedUnderStrictPQError extends Error {
  readonly profile: string;
  readonly policy: string;
  constructor(profile: string, policy: string) {
    super(`pq-profile: verifier refused under strict-PQ: profile=${profile} policy=${policy}`);
    this.name = 'VerifierRefusedUnderStrictPQError';
    this.profile = profile;
    this.policy = policy;
  }
}

export class UnknownProfileError extends Error {
  readonly profile: string;
  constructor(profile: string) {
    super(`pq-profile: unknown profile id: ${profile}`);
    this.name = 'UnknownProfileError';
    this.profile = profile;
  }
}

/**
 * refuseUnderStrictPQ — TS port of the Solidity / Go gate.
 *
 * Returns void on accept; throws on refuse. Same set of refused policies
 * as the on-chain library, same UnknownProfile semantics, same allow-
 * everything under classical-compat.
 */
export function refuseUnderStrictPQ(profile: string, policy: string): void {
  if (profile === PROFILE_CLASSICAL_COMPAT) return;
  if (profile !== PROFILE_QUASAR_STRICT_PQ) {
    throw new UnknownProfileError(profile);
  }
  if (REFUSED_UNDER_STRICT_PQ.has(policy)) {
    throw new VerifierRefusedUnderStrictPQError(profile, policy);
  }
}
