// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/// @title PQProfileIDs
/// @notice Canonical bytes32 constants for Lux PQ profile and proof-policy
///         identifiers. Single source of truth shared with Go, TypeScript,
///         and the LP-stricte2epq specification.
/// @dev    Every value is `keccak256(<UTF-8 string>)`. The strings
///         themselves are the protocol: Go (`go/profile/profile.go`) and
///         TS (`ts/src/profile.ts`) re-derive the same bytes. Cross-
///         language KAT lives in `KAT.md`.
///
///         Decomplected from verification: this file ONLY pins IDs. The
///         gate that decides admissibility lives in `OnlyStrictPQ.sol`
///         (modifier) / `StrictPQProfileGate.sol` (library).
library PQProfileIDs {
    // ─── Profile IDs ──────────────────────────────────────────────
    bytes32 internal constant PROFILE_CLASSICAL_COMPAT =
        keccak256("PROFILE_CLASSICAL_COMPAT");
    bytes32 internal constant PROFILE_QUASAR_STRICT_PQ =
        keccak256("PROFILE_QUASAR_STRICT_PQ");
    /// @notice Reserved for future "classical + PQ in parallel"
    ///         composition. Gate treats this as UnknownProfile today
    ///         so the deploy-time choice stays binary.
    bytes32 internal constant PROFILE_HYBRID =
        keccak256("PROFILE_HYBRID");

    // ─── ProofPolicy IDs ──────────────────────────────────────────
    bytes32 internal constant POLICY_GROTH16_BN254 =
        keccak256("ProofPolicyGroth16BN254");
    bytes32 internal constant POLICY_PLONK_BN254 =
        keccak256("ProofPolicyPLONKBN254");
    bytes32 internal constant POLICY_KZG_BLS12381 =
        keccak256("ProofPolicyKZGBLS12381");
    bytes32 internal constant POLICY_STARK_FRI_SHA3_PQ =
        keccak256("ProofPolicySTARKFRISHA3PQ");
    bytes32 internal constant POLICY_MLDSA65_FIPS204 =
        keccak256("ProofPolicyMLDSA65FIPS204");
}
