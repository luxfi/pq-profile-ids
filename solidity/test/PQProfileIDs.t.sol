// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/PQProfileIDs.sol";
import "../src/OnlyStrictPQ.sol";
import "../src/IPolicyId.sol";

contract MockPolicy is IPolicyId {
    bytes32 private immutable _id;
    constructor(bytes32 id) { _id = id; }
    function policyId() external view returns (bytes32) { return _id; }
}

contract Harness is OnlyStrictPQ {
    function check(bytes32 profile, IPolicyId v) external view {
        _refuseUnderStrictPQ(profile, v);
    }

    function gated(bytes32 profile, IPolicyId v) external view onlyStrictPQ(profile, v) returns (uint256) {
        return 42;
    }
}

contract PQProfileIDsTest is Test {
    Harness h;
    MockPolicy groth16;
    MockPolicy plonk;
    MockPolicy kzg;
    MockPolicy stark;
    MockPolicy mldsa;

    function setUp() public {
        h = new Harness();
        groth16 = new MockPolicy(PQProfileIDs.POLICY_GROTH16_BN254);
        plonk   = new MockPolicy(PQProfileIDs.POLICY_PLONK_BN254);
        kzg     = new MockPolicy(PQProfileIDs.POLICY_KZG_BLS12381);
        stark   = new MockPolicy(PQProfileIDs.POLICY_STARK_FRI_SHA3_PQ);
        mldsa   = new MockPolicy(PQProfileIDs.POLICY_MLDSA65_FIPS204);
    }

    // KAT: re-derive each constant from the canonical UTF-8 input.
    function testKAT_Profiles() public pure {
        assertEq(PQProfileIDs.PROFILE_CLASSICAL_COMPAT, keccak256("PROFILE_CLASSICAL_COMPAT"));
        assertEq(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, keccak256("PROFILE_QUASAR_STRICT_PQ"));
        assertEq(PQProfileIDs.PROFILE_HYBRID,           keccak256("PROFILE_HYBRID"));
    }

    function testKAT_Policies() public pure {
        assertEq(PQProfileIDs.POLICY_GROTH16_BN254,     keccak256("ProofPolicyGroth16BN254"));
        assertEq(PQProfileIDs.POLICY_PLONK_BN254,       keccak256("ProofPolicyPLONKBN254"));
        assertEq(PQProfileIDs.POLICY_KZG_BLS12381,      keccak256("ProofPolicyKZGBLS12381"));
        assertEq(PQProfileIDs.POLICY_STARK_FRI_SHA3_PQ, keccak256("ProofPolicySTARKFRISHA3PQ"));
        assertEq(PQProfileIDs.POLICY_MLDSA65_FIPS204,   keccak256("ProofPolicyMLDSA65FIPS204"));
    }

    function testClassicalCompat_AllowsEverything() public view {
        bytes32 p = PQProfileIDs.PROFILE_CLASSICAL_COMPAT;
        h.check(p, groth16);
        h.check(p, plonk);
        h.check(p, kzg);
        h.check(p, stark);
        h.check(p, mldsa);
    }

    function testStrictPQ_RefusesGroth16() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OnlyStrictPQ.VerifierRefusedUnderStrictPQ.selector,
                PQProfileIDs.PROFILE_QUASAR_STRICT_PQ,
                PQProfileIDs.POLICY_GROTH16_BN254
            )
        );
        h.check(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, groth16);
    }

    function testStrictPQ_RefusesPLONK() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OnlyStrictPQ.VerifierRefusedUnderStrictPQ.selector,
                PQProfileIDs.PROFILE_QUASAR_STRICT_PQ,
                PQProfileIDs.POLICY_PLONK_BN254
            )
        );
        h.check(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, plonk);
    }

    function testStrictPQ_RefusesKZG() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OnlyStrictPQ.VerifierRefusedUnderStrictPQ.selector,
                PQProfileIDs.PROFILE_QUASAR_STRICT_PQ,
                PQProfileIDs.POLICY_KZG_BLS12381
            )
        );
        h.check(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, kzg);
    }

    function testStrictPQ_AllowsSTARK() public view {
        h.check(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, stark);
    }

    function testStrictPQ_AllowsMLDSA() public view {
        h.check(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, mldsa);
    }

    function testUnknownProfile_Reverts() public {
        bytes32 bogus = keccak256("PROFILE_BOGUS");
        vm.expectRevert(abi.encodeWithSelector(OnlyStrictPQ.UnknownProfile.selector, bogus));
        h.check(bogus, stark);
    }

    function testHybridProfile_IsRejectedToday() public {
        vm.expectRevert(
            abi.encodeWithSelector(OnlyStrictPQ.UnknownProfile.selector, PQProfileIDs.PROFILE_HYBRID)
        );
        h.check(PQProfileIDs.PROFILE_HYBRID, stark);
    }

    function testUnconfiguredSlot_IsNoOp() public view {
        // address(0) ⇒ no policyId fetch ⇒ allow.
        h.check(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, IPolicyId(address(0)));
    }

    function testModifierForm_AllowsAndRefuses() public {
        // Allow under classical-compat.
        assertEq(h.gated(PQProfileIDs.PROFILE_CLASSICAL_COMPAT, groth16), 42);
        // Refuse under strict-PQ.
        vm.expectRevert(
            abi.encodeWithSelector(
                OnlyStrictPQ.VerifierRefusedUnderStrictPQ.selector,
                PQProfileIDs.PROFILE_QUASAR_STRICT_PQ,
                PQProfileIDs.POLICY_GROTH16_BN254
            )
        );
        h.gated(PQProfileIDs.PROFILE_QUASAR_STRICT_PQ, groth16);
    }
}
