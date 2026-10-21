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
| A stamp's fee descriptors | `Tachyon-Fees` |
| A stamp's coverage | `Tachyon-Coverage` |
| Memo payload | `Tachyon-Memo` |
| Stamp proof | `Tachyon-Proof` |
| Stamp data | `Tachyon-Stamp` |

## BLAKE2b-512

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
| Spend alpha | `Tachyon-Spend` |
| Output alpha | `Tachyon-Output` |
| Anchor stamp step | `Tachyon-AnchorSt` |
| Anchor epoch step | `Tachyon-AnchorEp` |
| evidence tree leaf | `Tachyon-QrBucket` |
| evidence tree node | `Tachyon-EvidNode` |
| Max fee note blind | `Tachyon-FeeBlind` |
| Fee digest | `Tachyon-FeeDg` |

Each domain sits in the sponge capacity.
A hash starts with its rate at zero and its capacity element at $\mathsf{tag}$, the sixteen-byte domain read as a little-endian integer.
The sponge then absorbs only the hash's data.

The two alpha domains and the fee digest domain are zero-padded to sixteen bytes.

## Hash-to-curve

Value commitments presently use the same generator as Orchard.

| Purpose | Value |
| ------- | ----- |
| Value commitment | `z.cash:Orchard-cv` |
