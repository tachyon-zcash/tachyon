# Transaction Identifiers

A Tachyon bundle's authorization form changes as it moves through aggregation: stamping, merging into a covering aggregate, and stripping all produce bit-different authorizations of the same effecting data. [`wtxid`](https://zips.z.cash/zip-0239) — `txid || auth_digest` — is defined to uniquely fingerprint the physical on-wire transaction, so these forms must produce distinct `wtxid`s.

Tachyon routes the mutable parts through `auth_digest`, leaving `txid` stable:

- `txid` commits to [effecting data](./authorization.md#bundle-commitment) only: the actions, the value balance, the max fee note's value commitment, and the memo. Stripping, merging, re-stamping, and applying or changing the fee leave `txid` unchanged.
- `auth_digest` commits to sigs and the stamp trailer, which carries the fee. Each physical auth form yields a distinct `auth_digest` and therefore a distinct `wtxid`.

## `auth_digest` contribution

Zcash's transaction-level `auth_digest` commits to authorization data — the half of `wtxid = txid || auth_digest` that changes when an authorization form changes ([ZIP-239](https://zips.z.cash/zip-0239), [ZIP-244](https://zips.z.cash/zip-0244)).

Tachyon's bundle contributes on both sides:

- **Effecting data → `txid`.** Tachyon's contribution is the bundle commitment over $\mathsf{hActionsTachyon} \,\|\, \mathsf{valueBalanceTachyon} \,\|\, \mathsf{cvFeeMaxTachyon} \,\|\, \mathsf{hMemoTachyon}$.
- **Authorization data → `auth_digest`.** Tachyon's contribution hashes the bundle state byte, the action signatures, the binding signature, and a fixed-width summary of whichever stamp the bundle carries, led by its fee:

$$
\mathsf{auth\_digest\_contribution} =
\text{BLAKE2b-256}_{\text{``ZTxAuthTachyHash''}}\bigl(
    \mathsf{tachyonBundleState} \,\|\, \mathsf{vActionSigs} \,\|\, \mathsf{bindingSigTachyon}
    \,\|\, \mathsf{tachyonStampState}
\bigr)
$$

$\mathsf{tachyonStampState}$ is 72 bytes in both states, so the two are the same width and are told apart by the state byte:

$$
\mathsf{tachyonStampState} = \begin{cases}
    \mathsf{LE64}(\mathsf{vFeeTachyon}) \,\|\, \mathsf{hStampCoverageTachyon} \,\|\, \mathsf{hStampDataTachyon} & \text{if stamped}\\
    \mathsf{LE64}(\mathsf{vFeeTachyon}) \,\|\, \mathsf{tachyonAggregateId} & \text{if stripped}
\end{cases}
$$

A stamped bundle summarizes its stamp as the fee and two digests. $\mathsf{hStampCoverageTachyon}$ is the [action set indicator](./aggregation.md#action-set-indicator), which combines $\mathsf{hStampActionsTachyon}$ over the covered actions with $\mathsf{hStampFeesTachyon}$ over the covered fee descriptors. It strips away with the rest of the stamp when a bundle becomes an adjunct. $\mathsf{hStampDataTachyon}$ covers everything else the stamp carries:

$$
\mathsf{hStampDataTachyon} =
\text{BLAKE2b-256}_\text{Tachyon-Stamp}\bigl(
    \mathsf{hStampProofTachyon} \,\|\, \mathsf{anchorTachyon} \,\|\, \mathsf{cTachygrams}
    \,\|\, \mathsf{vTachygrams}
\bigr)
$$

with $\mathsf{hStampProofTachyon} = \text{BLAKE2b-256}_\text{Tachyon-Proof}(\mathsf{proofTachyon})$. Hashing the proof separately keeps the tachygram vector as the only variable-length input.

A stripped bundle's summary is the fee and the 64-byte `wtxid` of the covering aggregate. The personalization `"ZTxAuthTachyHash"` is a placeholder until a Tachyon-ZIP amendment to ZIP-244 fixes it.

## Covering-aggregate references

An adjunct's reference to the aggregate that covers it is a `wtxid`, not a `txid` — the 64-byte `wtxid` pins a specific physical aggregate, whereas a `txid` only pins the effecting data.

Miners assign the reference during block assembly. The covering aggregate must itself be top-level in the block — never stripped, never further aggregated — so the `wtxid` pointed to is stable. See [Aggregation → Block Layout](./aggregation.md#block-layout) for how references are resolved in a block.
