# Domain Separators

## BLAKE2b-256

### Transaction identifiers

Digests used to commit to Tachyon bundle contents for sighash and auth digest.

<!-- see 
    https://github.com/zcash/orchard/blob/main/src/bundle/commitments.rs 
    https://zips.z.cash/zip-0244
-->

| Purpose | Value |
| ------- | ----- |
| Bundle commitment | `ZTxIdTachyonHash` |
| Bundle auth digest | `ZTxAuthTachyHash` |

### Bundle contents

Digests over bundle contents, feeding the two above. These are Tachyon-specific and so take Tachyon personalizations.

| Purpose | Value |
| ------- | ----- |
| Action descriptors | `Tachyon-Actions` |
| Memo payload | `Tachyon-Memo` |
| Stamp proof | `Tachyon-Proof` |
| Stamp data | `Tachyon-Stamp` |

## BLAKE2b-512

### Action alpha

Deterministic action randomizer for Tachyon, privately handled by transaction author and custody device.

<!-- todo: consider poseidon or other curve-native derivation? -->

| Purpose | Value |
| ------- | ----- |
| Spend alpha | `Tachyon-Spend` |
| Output alpha | `Tachyon-Output` |

### PRF expansion

Domain string and personalization bytes for `sk` expansion.

<!-- see
    https://github.com/zcash/zcash_spec/blob/main/src/prf_expand.rs
-->

| Purpose | Value |
| ------- | ----- |
| PRF expand | `Zcash_ExpandSeed` |
| `ask` derivation | `0x21` byte |
| `nk` derivation | `0x22` byte |

## Poseidon

These are all Tachyon-specific digests, performed in-circuit.

| Purpose | Value |
| ------- | ----- |
| Nullifier master key | `Tachyon-NfMaster` |
| Nullifier derivation | `Tachyon-NfDerive` |
| Note commitment | `Tachyon-CmDerive` |
| Output padding tachygram | `Tachyon-CmOutPad` |
| Action digest | `Tachyon-ActionDg` |
| Payment key derivation | `Tachyon-PkDerive` |
| Anchor stamp step | `Tachyon-AnchorSt` |
| Anchor epoch step | `Tachyon-AnchorEp` |
| QR bucket tree leaf | `Tachyon-QrBucket` |

A QR bucket tree node takes no domain constant.
Its four children fill the sponge rate exactly, and a leaf absorbs nine elements against a node's four, so no node value can stand where a leaf digest is expected.
A tree short of a full level therefore pads by repeating a child and never by omitting one.

## Hash-to-curve

Value commitments presently use the same generator as Orchard.

| Purpose | Value |
| ------- | ----- |
| Value commitment | `z.cash:Orchard-cv` |
