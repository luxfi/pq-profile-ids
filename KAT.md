# Known-Answer Test (KAT) for pinned IDs

Every consumer language (Go, Solidity, TypeScript) re-derives the
constants below at test time and compares against the pinned hex.
A typo in either the input string or the pinned hex blows up the test.

Hash: `keccak256` (NIST FIPS 202 Keccak with legacy 0x01 padding —
the EVM dialect, i.e. `ethers.id(s)` / Solidity `keccak256(bytes(s))` /
Go `golang.org/x/crypto/sha3.NewLegacyKeccak256()`).

Encoding of input: UTF-8 bytes of the string, no trailing NUL.

| Input string (UTF-8)                | keccak256 (bytes32, hex) |
|-------------------------------------|---------------------------|
| `PROFILE_CLASSICAL_COMPAT`          | `0xff460dabe75e1748cc81f17230386222b67f53a1e8ce1f1176820292194fab7b` |
| `PROFILE_QUASAR_STRICT_PQ`          | `0x648ae57d5359236a9608028b38c6dd3d567b40418e9513c146bb71df7d4d0e83` |
| `PROFILE_HYBRID`                    | `0x56e230b3af23076ccb38335583e550d2be4f7f33dea829713a2d12adff19774e` |
| `ProofPolicyGroth16BN254`           | `0x91cae9e6247c12e7efc5498813eb0339f035757faac42bf27d572c113f507838` |
| `ProofPolicyPLONKBN254`             | `0x5ec6ac94122b75276930288364a62f5544dfbc691b4160344f9aa14d5768fe32` |
| `ProofPolicyKZGBLS12381`            | `0x15d4efdbd8ca26cc89082cba15d73cd942394806fea4a72937ca50f22e6b1b38` |
| `ProofPolicySTARKFRISHA3PQ`         | `0x36bff5354600cd569f66c4d1b7aaafd0193299577d2171e1e42c01cd9bc6709a` |
| `ProofPolicyMLDSA65FIPS204`         | `0x027f4d69dccaa8c1f50e842236389edbc4d5eac5722b4d7960b5373cfd586805` |

### MPC scheme strings (NOT hashed; carried as strings on wire)

| Scheme key       | Wire string                       |
|------------------|-----------------------------------|
| `ecdsa`          | `ECDSA-SECP256K1-GG18`            |
| `cggmp21`        | `ECDSA-SECP256K1-CGGMP21`         |
| `frost`          | `SCHNORR-SECP256K1-FROST-RFC9591` |
| `pulsar`         | `PULSAR-M-LWE-FIPS204T`           |
| `corona`         | `CORONA-R-LWE-RINGTAIL`           |
| `double-lattice` | `DOUBLE-LATTICE-PULSAR+CORONA`    |

A scheme passes `isPQScheme(...)` iff it is one of
{`pulsar`, `corona`, `double-lattice`}.
