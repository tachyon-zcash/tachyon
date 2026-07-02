# Domain Separators

## BLAKE2b-512

### Action alpha

Deterministic action randomizer for Tachyon, privately handled by transaction author and custody device.

<!-- todo: consider poseidon or other curve-native derivation? -->

| Purpose | Value |
| ------- | ----- |
| Spend alpha | `Tachyon-Spend` |
| Output alpha | `Tachyon-Output` |

### Transaction identifiers

Digests used to commit to Tachyon bundle contents for sighash and and auth digest.

<!-- see 
    https://github.com/zcash/orchard/blob/main/src/bundle/commitments.rs 
    https://zips.z.cash/zip-0244
-->

| Purpose | Value |
| ------- | ----- |
| Bundle commitment | `ZTxIdTachyonHash` |
| Bundle auth digest | `ZTxAuthTachyHash` |

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
| Nullifier master key part | `Tachyon-NfMaster` |
| Nullifier query salts | `Tachyon-NfSalt__` |
| Nullifier query weights | `Tachyon-NfWeight` |
| Nullifier lift challenge | `Tachyon-NfLiftCh` |
| Note commitment | `Tachyon-CmDerive` |
| Action digest | `Tachyon-ActionDg` |
| Payment key derivation | `Tachyon-PkDerive` |
| Anchor stamp step | `Tachyon-StampFld` |
| Anchor empty step | `Tachyon-EmptyBlk` |
| Anchor epoch step | `Tachyon-EpochStp` |

## Hash-to-curve

Value commitments presently use the same generator as Orchard.

| Purpose | Value |
| ------- | ----- |
| Value commitment | `z.cash:Orchard-cv` |
