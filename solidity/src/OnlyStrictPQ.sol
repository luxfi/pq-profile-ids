// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "./PQProfileIDs.sol";
import "./IPolicyId.sol";

/// @title OnlyStrictPQ
/// @notice Abstract contract exposing the `onlyStrictPQ` modifier — one
///         reusable place that refuses non-PQ verifiers under
///         `PROFILE_QUASAR_STRICT_PQ`.
/// @dev    Lifted 1:1 from the inline call site in `BridgeV2.claim`
///         (`~/work/lux/teleport/contracts/contracts/BridgeV2.sol`).
///         Same refusal semantics, same error selectors, same set of
///         refused policies. The braid of "what does this primitive do"
///         and "is this primitive allowed in this slot" is now cut:
///         the verifier verifies (anywhere), the modifier gates
///         admissibility (one place).
///
///         To use:
///
///             contract MyBridge is OnlyStrictPQ {
///                 IVerifier public activeVerifier;
///                 bytes32 public activeProfile;
///                 function claim(...) external onlyStrictPQ(activeProfile, activeVerifier) {
///                     ...
///                 }
///             }
abstract contract OnlyStrictPQ {
    /// @notice Refused when the active profile is strict-PQ and the
    ///         supplied policy is NOT in the PQ allow-list.
    /// @dev    Allow-list (not deny-list): under strict-PQ a verifier is
    ///         admitted iff its `policyId()` is in `{POLICY_STARK_FRI_SHA3_PQ,
    ///         POLICY_MLDSA65_FIPS204}`. Any other value — including a
    ///         spoofed bytes32 that is not in the BN254/BLS12-381 family
    ///         but is also not a recognised PQ policy — is refused. This
    ///         is the fail-closed counterpart to the original deny-list,
    ///         which let an unknown `policyId()` slip past the gate.
    error VerifierRefusedUnderStrictPQ(bytes32 profile, bytes32 policy);
    /// @notice Refused when the profile id is neither classical-compat
    ///         nor strict-PQ. `PROFILE_HYBRID` is reserved and rejected
    ///         here today so the deploy-time choice stays binary.
    error UnknownProfile(bytes32 profile);
    /// @notice Refused when the active profile is strict-PQ and the
    ///         verifier slot is the zero address. A zero verifier means
    ///         "no proof check at all" — silently accepting that under
    ///         strict-PQ would be a strict-PQ-no-op state. Refuse fast.
    error VerifierUnsetUnderStrictPQ(bytes32 profile);

    /// @notice Refuses the call if `verifier`'s policy is not allowed in
    ///         the active `profile`. No-op under classical-compat (the
    ///         slot is allowed to be unset or to hold any backend);
    ///         under strict-PQ, both `address(0)` and any non-PQ policy
    ///         are refused.
    modifier onlyStrictPQ(bytes32 profile, IPolicyId verifier) {
        _refuseUnderStrictPQ(profile, verifier);
        _;
    }

    /// @notice Free function form for sites that cannot use a modifier
    ///         (e.g. branching on `claimWithProof` vs `claim`). Same
    ///         semantics as the modifier.
    /// @dev    Allow-list under strict-PQ. The set of admissible policies
    ///         is the canonical PQ allow-list from
    ///         `PQProfileIDs.POLICY_STARK_FRI_SHA3_PQ` and
    ///         `PQProfileIDs.POLICY_MLDSA65_FIPS204`. Anything else is
    ///         refused, including:
    ///           - classical BN254 / BLS12-381 backends,
    ///           - spoofed verifiers returning an unrecognised bytes32,
    ///           - `address(0)` (refused with `VerifierUnsetUnderStrictPQ`).
    function _refuseUnderStrictPQ(bytes32 profile, IPolicyId verifier) internal view {
        if (profile == PQProfileIDs.PROFILE_CLASSICAL_COMPAT) {
            // Classical-compat: gate is a no-op. The classical L1 EVM
            // counterparty is itself classical, so any verifier (or no
            // verifier) is admissible by construction.
            return;
        }
        if (profile != PQProfileIDs.PROFILE_QUASAR_STRICT_PQ) {
            revert UnknownProfile(profile);
        }
        // Strict-PQ from here on. Fail-closed everywhere.
        if (address(verifier) == address(0)) {
            revert VerifierUnsetUnderStrictPQ(profile);
        }
        bytes32 policy = verifier.policyId();
        if (
            policy != PQProfileIDs.POLICY_STARK_FRI_SHA3_PQ &&
            policy != PQProfileIDs.POLICY_MLDSA65_FIPS204
        ) {
            revert VerifierRefusedUnderStrictPQ(profile, policy);
        }
    }
}
