# @luxfi/pq-profile-ids

Canonical source of truth for Lux PQ profile and proof-policy identifiers.

Three subpackages, one set of strings:

| Subpackage              | Path              | Surface                                     |
|-------------------------|-------------------|---------------------------------------------|
| `github.com/luxfi/pq-profile-ids/go` | `go/`        | Go consts (`profile.ID` + `RefuseUnderStrictPQ`) |
| `@luxfi/pq-profile-ids` | `solidity/`       | Solidity library + `OnlyStrictPQ` modifier   |
| `@luxfi/pq-profile-ids-ts` | `ts/`          | TypeScript exports + `refuseUnderStrictPQ`   |

## Why this exists

Three independent ports of the same constants used to drift:

- `papers/pq/pq.tex` §profile-table used `STARK_FRI_SHA3_PQ` while
  Solidity (and on-chain state) used `ProofPolicySTARKFRISHA3PQ`.
- `luxfi/node` quasar contract carried a Go duplicate that was prone to
  typo-without-detection.
- `teleport/contracts` had two places (library + MockVerifier) inlining
  the strings.
- `teleport/mpc` carried a separate `POLICY_ID` map keyed by scheme name.

This repo collapses all of that to ONE set of strings. Every consumer
imports IDs from here. Tests in all three subpackages re-derive each
constant from its UTF-8 input via the canonical KAT in `KAT.md`, so a
typo in any pinned hex constant cannot ship undetected.

## What's pinned

### Profiles

| String                       | Meaning                                              |
|------------------------------|------------------------------------------------------|
| `PROFILE_CLASSICAL_COMPAT`   | Default. Gate is a no-op; every verifier allowed.     |
| `PROFILE_QUASAR_STRICT_PQ`   | BN254 / BLS12-381 verifiers refused at gate.          |
| `PROFILE_HYBRID`             | Reserved. Today the gate treats it as UnknownProfile. |

### Proof policies

| String                          | Refused under strict-PQ? |
|---------------------------------|--------------------------|
| `ProofPolicyGroth16BN254`       | YES                      |
| `ProofPolicyPLONKBN254`         | YES                      |
| `ProofPolicyKZGBLS12381`        | YES                      |
| `ProofPolicySTARKFRISHA3PQ`     | no                       |
| `ProofPolicyMLDSA65FIPS204`     | no                       |

### MPC scheme strings (wire format, not hashed)

`ECDSA-SECP256K1-GG18`, `ECDSA-SECP256K1-CGGMP21`,
`SCHNORR-SECP256K1-FROST-RFC9591`, `PULSAR-M-LWE-FIPS204T`,
`CORONA-R-LWE-RINGTAIL`, `DOUBLE-LATTICE-PULSAR+CORONA`.

The first three are classical; the last three pass `isPQScheme(...)`.

## Decomplected

This package ONLY pins IDs and exposes the policy-gate function.

It does NOT verify proofs.

The verifier verifies (anywhere). This package decides admissibility
(one place). Two responsibilities, two surfaces.

## License

Dual: MIT OR Apache-2.0.
