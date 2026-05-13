// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/// @title IPolicyId
/// @notice Minimal interface a verifier (or other gated primitive) must
///         expose so `OnlyStrictPQ` / `StrictPQProfileGate` can read its
///         policy ID and decide admissibility.
/// @dev    Deliberately decoupled from a particular `verify(...)` shape.
///         The Teleport `IVerifier` and `IP3QVerifier` both satisfy this
///         interface — they extend it with their domain-specific verify
///         method, but the gate only needs `policyId()`.
interface IPolicyId {
    /// @notice Returns the ProofPolicy ID this primitive implements.
    ///         Compared against `PQProfileIDs.POLICY_*` constants.
    function policyId() external view returns (bytes32);
}
