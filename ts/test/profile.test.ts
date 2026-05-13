/**
 * KAT + behavioural test for @luxfi/pq-profile-ids/ts.
 *
 * Re-derives every pinned bytes32 from its canonical UTF-8 input string
 * using @noble/hashes' keccak256 so a typo in the pinned hex can never
 * ship. Mirrors the Go test (`profile_test.go`) and the Solidity test
 * (`PQProfileIDs.t.sol`).
 */

import { keccak_256 } from '@noble/hashes/sha3';
import {
  POLICY_GROTH16_BN254,
  POLICY_GROTH16_BN254_STRING,
  POLICY_KZG_BLS12381,
  POLICY_KZG_BLS12381_STRING,
  POLICY_MLDSA65_FIPS204,
  POLICY_MLDSA65_FIPS204_STRING,
  POLICY_PLONK_BN254,
  POLICY_PLONK_BN254_STRING,
  POLICY_STARK_FRI_SHA3_PQ,
  POLICY_STARK_FRI_SHA3_PQ_STRING,
  PROFILE_CLASSICAL_COMPAT,
  PROFILE_CLASSICAL_COMPAT_STRING,
  PROFILE_HYBRID,
  PROFILE_HYBRID_STRING,
  PROFILE_QUASAR_STRICT_PQ,
  PROFILE_QUASAR_STRICT_PQ_STRING,
  SCHEME_CORONA_R_LWE,
  SCHEME_DOUBLE_LATTICE,
  SCHEME_ECDSA_GG18,
  SCHEME_PULSAR_M_LWE,
  UnknownProfileError,
  VerifierRefusedUnderStrictPQError,
  isPQScheme,
  refuseUnderStrictPQ,
} from '../src/profile';

function kat(s: string): string {
  return '0x' + Buffer.from(keccak_256(new TextEncoder().encode(s))).toString('hex');
}

describe('pq-profile-ids — KAT', () => {
  it('profile IDs match keccak256(<input string>)', () => {
    expect(kat(PROFILE_CLASSICAL_COMPAT_STRING)).toBe(PROFILE_CLASSICAL_COMPAT);
    expect(kat(PROFILE_QUASAR_STRICT_PQ_STRING)).toBe(PROFILE_QUASAR_STRICT_PQ);
    expect(kat(PROFILE_HYBRID_STRING)).toBe(PROFILE_HYBRID);
  });

  it('policy IDs match keccak256(<input string>)', () => {
    expect(kat(POLICY_GROTH16_BN254_STRING)).toBe(POLICY_GROTH16_BN254);
    expect(kat(POLICY_PLONK_BN254_STRING)).toBe(POLICY_PLONK_BN254);
    expect(kat(POLICY_KZG_BLS12381_STRING)).toBe(POLICY_KZG_BLS12381);
    expect(kat(POLICY_STARK_FRI_SHA3_PQ_STRING)).toBe(POLICY_STARK_FRI_SHA3_PQ);
    expect(kat(POLICY_MLDSA65_FIPS204_STRING)).toBe(POLICY_MLDSA65_FIPS204);
  });
});

describe('pq-profile-ids — refuseUnderStrictPQ', () => {
  it('classical-compat allows every policy', () => {
    for (const p of [
      POLICY_GROTH16_BN254,
      POLICY_PLONK_BN254,
      POLICY_KZG_BLS12381,
      POLICY_STARK_FRI_SHA3_PQ,
      POLICY_MLDSA65_FIPS204,
    ]) {
      expect(() => refuseUnderStrictPQ(PROFILE_CLASSICAL_COMPAT, p)).not.toThrow();
    }
  });

  it('strict-PQ refuses BN254 / BLS family', () => {
    for (const p of [POLICY_GROTH16_BN254, POLICY_PLONK_BN254, POLICY_KZG_BLS12381]) {
      expect(() => refuseUnderStrictPQ(PROFILE_QUASAR_STRICT_PQ, p)).toThrow(
        VerifierRefusedUnderStrictPQError,
      );
    }
  });

  it('strict-PQ allows STARK + ML-DSA', () => {
    for (const p of [POLICY_STARK_FRI_SHA3_PQ, POLICY_MLDSA65_FIPS204]) {
      expect(() => refuseUnderStrictPQ(PROFILE_QUASAR_STRICT_PQ, p)).not.toThrow();
    }
  });

  it('unknown profile (including hybrid) rejects', () => {
    expect(() => refuseUnderStrictPQ('0xdeadbeef', POLICY_STARK_FRI_SHA3_PQ)).toThrow(
      UnknownProfileError,
    );
    expect(() => refuseUnderStrictPQ(PROFILE_HYBRID, POLICY_STARK_FRI_SHA3_PQ)).toThrow(
      UnknownProfileError,
    );
  });
});

describe('pq-profile-ids — isPQScheme', () => {
  it('accepts pulsar / corona / double-lattice', () => {
    expect(isPQScheme(SCHEME_PULSAR_M_LWE)).toBe(true);
    expect(isPQScheme(SCHEME_CORONA_R_LWE)).toBe(true);
    expect(isPQScheme(SCHEME_DOUBLE_LATTICE)).toBe(true);
  });
  it('rejects classical schemes', () => {
    expect(isPQScheme(SCHEME_ECDSA_GG18)).toBe(false);
    expect(isPQScheme('bogus')).toBe(false);
  });
});
