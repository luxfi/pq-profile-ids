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
    ///         supplied policy is in the BN254 / BLS12-381 family.
    error VerifierRefusedUnderStrictPQ(bytes32 profile, bytes32 policy);
    /// @notice Refused when the profile id is neither classical-compat
    ///         nor strict-PQ. `PROFILE_HYBRID` is reserved and rejected
    ///         here today so the deploy-time choice stays binary.
    error UnknownProfile(bytes32 profile);

    /// @notice Refuses the call if `verifier`'s policy is not allowed in
    ///         the active `profile`. No-op under classical-compat; no-op
    ///         when `verifier == address(0)` (slot unconfigured).
    modifier onlyStrictPQ(bytes32 profile, IPolicyId verifier) {
        _refuseUnderStrictPQ(profile, verifier);
        _;
    }

    /// @notice Free function form for sites that cannot use a modifier
    ///         (e.g. branching on `claimWithProof` vs `claim`). Same
    ///         semantics as the modifier.
    function _refuseUnderStrictPQ(bytes32 profile, IPolicyId verifier) internal view {
        if (address(verifier) == address(0)) {
            return;
        }
        if (profile == PQProfileIDs.PROFILE_CLASSICAL_COMPAT) {
            return;
        }
        if (profile != PQProfileIDs.PROFILE_QUASAR_STRICT_PQ) {
            revert UnknownProfile(profile);
        }
        bytes32 policy = verifier.policyId();
        if (
            policy == PQProfileIDs.POLICY_GROTH16_BN254 ||
            policy == PQProfileIDs.POLICY_PLONK_BN254 ||
            policy == PQProfileIDs.POLICY_KZG_BLS12381
        ) {
            revert VerifierRefusedUnderStrictPQ(profile, policy);
        }
    }
}
