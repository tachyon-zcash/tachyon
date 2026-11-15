# Parameters

The protocol's fixed parameters, with the code that defines each.
Paths are relative to `crates/tachyon/src`.
Values from outside the crate come from Ragu at the pinned revision and from `zakura-udon` 0.1.0.

## Curves and fields

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| Value commitments, verification keys and RedPallas signatures | Pallas | `value.rs`, `keys/` |
| Tachygram-set bridge hash | Pallas | `stamp/proof.rs` |
| Set commitments | Vesta | `primitives/sets.rs` |
| Notes, tachygrams, anchors and Poseidon | $\F_p$, the Pallas base field | `note.rs`, `primitives/` |
| Value trapdoors and signing keys | $\F_q$, the Pallas scalar field | `value.rs`, `keys/private.rs` |
| Value commitment generators $\mathcal{V}$, $\mathcal{R}$ and action-auth generator $\mathcal{G}$ | Orchard's, see [Domain Separators](./domain-separators.md) | `constants.rs` |

## Values

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `MAX_MONEY` | $2.1 \times 10^{15}$ zatoshi | `constants.rs` |
| Note value | $0 \leq v \leq \mathsf{MAX\_MONEY}$ | `value.rs` |
| Fee | $0 \leq \fee \leq \feemax \leq \mathsf{MAX\_MONEY}$ | `fee.rs`, `stamp/proof/stamp.rs` |
| Value balance | $-\mathsf{MAX\_MONEY} \leq v^{bal} \leq \mathsf{MAX\_MONEY}$ | `value.rs` |

## Chain and epochs

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `BLOCK_MAX` | $2^{32} - 1$ | `constants.rs` |
| `EPOCH_SIZE` | 4,096 blocks | `constants.rs` |
| `EPOCH_MAX` | $2^{20} - 1$, `BLOCK_MAX / EPOCH_SIZE` rounded down | `constants.rs` |

`EPOCH_SIZE` is 64 under the `test-epoch-size` feature, which tests use.
It must be a power of two.
The last epoch is partial.

## Nullifiers and sets

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `NF_DERIVATION_WIDTH`, the derivation window | 16 epochs, four groups of the Poseidon rate | `nullifier.rs` |
| Cubic non-residue $c$ of the indexed multiset | 2 | `collections/indexed_multiset.rs` |
| Quadratic non-residue $n$ of the QR classes | 5 | `collections/qr.rs` |
| `QrProfile::MAX_DEPTH` | 32 | `primitives/qr.rs` |
| `EVIDENCE_TREE_ARITY` | 4 | `constants.rs` |
| Evidence-tree levels per descent step | 4 | `stamp/proof/evidence.rs` |

## Poseidon

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| Field | $\F_p$ | Udon `PALLAS_BASE` (Ragu `PoseidonFp`) |
| Width | 5 | Udon `PALLAS_BASE` |
| Rate | 4 | Udon `PALLAS_BASE` |
| S-box exponent | 5 | Udon `PALLAS_BASE` |
| Rounds | 8 full, 56 partial | Udon `PALLAS_BASE` |

Each hash is domain-separated as described in [Domain Separators](./domain-separators.md).

## Proof system

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `ProductionRank` | rank 13, $2^{13}$ coefficients | Ragu `ProductionRank` |
| Tachygrams per stamp | at most $2^{13} - 1$ | `stamp.rs` |
| Header size | 9 field elements, 8 of payload and a suffix | `stamp/proof.rs` |

The tachygram cap follows from the rank: a set polynomial with $n$ roots has $n + 1$ coefficients.
With two tachygrams per action and one per covered bundle, $2N + B \leq 2^{13} - 1$ with $B \geq 1$, so a stamp covers at most 4,095 actions.
