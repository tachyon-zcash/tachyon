# Parameters

The protocol's fixed parameters, with the code that defines each.
Paths are relative to `crates/tachyon/src`.
Values defined outside the crate come from Ragu at the pinned revision and from `zakura-udon` 0.3.0 (Udon).

## Curves and fields

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| Value commitments, verification keys and RedPallas signatures | Pallas | `value.rs`, `keys/`, `reddsa.rs` |
| Tachygram-set bridge hash | Pallas | `primitives/sets.rs`, `bridge_hash.rs` |
| Set commitments | Vesta | `primitives/sets.rs` |
| Notes, tachygrams, anchors and Poseidon | $\F_p$, the Pallas base field | `note.rs`, `primitives/`, `digest/poseidon.rs` |
| Value trapdoors and signing keys | $\F_q$, the Pallas scalar field | `value.rs`, `keys/private.rs` |
| Value commitment generators $\mathcal{V}$, $\mathcal{R}$ and action authorization basepoint $\mathcal{G}$ | Orchard's, see [Domain Separators](./domain-separators.md) | `constants.rs` |

## Values

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `MAX_MONEY` | $2.1 \times 10^{15}$ zatoshi | `constants.rs` |
| Note value | $0 \leq v \leq \mathsf{MAX\_MONEY}$ | `value.rs` |
| Fee | $0 \leq \fee \leq \feemax \leq \mathsf{MAX\_MONEY}$ | `fee.rs`, `stamp/proof/stamp.rs` |
| Value balance | $-\mathsf{MAX\_MONEY} \leq v^{\mathsf{bal}} \leq \mathsf{MAX\_MONEY}$ | `value.rs` |
| Note commitment trapdoor $\rcm$ | $\neq 0$ | `note.rs`, `gadgets/note.rs` |
| Action randomizer $\alpha$ | $< 2^{254}$; $\neq 0$ for outputs, at most five unassigned values per $\ak$ for spends | `stamp/proof/stamp.rs`, `gadgets/fixed_base.rs`, Ragu `FixedBase` |
| Action value trapdoor $\rcv$ and max-fee blind $r$ | $0 < x < 2^{254}$ | Ragu `FixedBase`, `gadgets/fixed_base.rs`, `stamp/proof/spend.rs`, `stamp/proof/output.rs`, `stamp/proof/stamp.rs`, `gadgets/note.rs` |

## Chain and epochs

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `BLOCK_MAX` | $2^{32} - 1$ | `constants.rs` |
| `EPOCH_SIZE` | 4,096 blocks | `constants.rs` |
| `EPOCH_MAX` | $2^{20} - 1$, `BLOCK_MAX / EPOCH_SIZE` rounded down | `constants.rs` |
| Duplicate-tachygram window | 2 epochs, the present and immediately previous | [Tachygrams](./tachygrams.md) |

`EPOCH_SIZE` must be a power of two.
It is 64 under the `test-epoch-size` feature, which tests use, and `EPOCH_MAX` is then $2^{26} - 1$.
Because `EPOCH_SIZE` divides $2^{32}$, the last epoch is full and ends at `BLOCK_MAX`.

## Nullifiers and sets

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `NF_DERIVATION_WIDTH`, the derivation window | 16 epochs, four groups of the Poseidon rate | `nullifier.rs` |
| Published tachygrams | $\neq 0$ | `stamp/proof/spend.rs`, `stamp/proof/output.rs`, `stamp/proof/stamp.rs` |
| Cubic non-residue of the indexed multiset | 2 | `collections/indexed_multiset.rs` |
| Quadratic non-residue of the QR classes | 5 | `collections/qr.rs` |
| `QrProfile::MAX_DEPTH` | 32 | `primitives/qr.rs` |
| `EVIDENCE_TREE_ARITY` | 4 | `constants.rs` |
| Evidence-tree levels per descent step | 4 | `stamp/proof/evidence.rs` |

## Poseidon

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| Field | $\F_p$ | Udon `PALLAS_BASE`, `PoseidonFp` |
| Width | 5 | Udon `PALLAS_BASE` |
| Rate | 4 | Udon `PALLAS_BASE` |
| Capacity | 1 | Udon `PALLAS_BASE` |
| S-box exponent | 5 | Udon `PALLAS_BASE` |
| Rounds | 8 full, 56 partial | Udon `PALLAS_BASE` |

Each hash is domain-separated as described in [Domain Separators](./domain-separators.md).

## Proof system

| Parameter | Value | Defined in |
| --------- | ----- | ---------- |
| `WalletRank` | rank 13, $2^{13}$ coefficients, $2^{11}$ gates | Ragu `WalletRank` |
| Tachygrams per stamp | at most $2^{13} - 1$ | `bundle.rs` |
| Header size | 9 field elements, 8 of payload and 1 suffix | `stamp/proof.rs` |

The tachygram cap follows from the rank, as the [stamp trailer](./bundle.md#stamp-trailer) explains: a set polynomial with $n$ roots has $n + 1$ coefficients.
A stamp covering $N$ actions across $B \geq 1$ bundles publishes two tachygrams per action and one per bundle fee, so $2N + B \leq 2^{13} - 1$ and it covers at most 4,095 actions.
