# Transaction Identifiers

A Tachyon bundle's authorization form changes as it moves through aggregation: stamping, merging into a covering aggregate, and stripping all produce bit-different authorizations of the same effecting data. [`wtxid`](https://zips.z.cash/zip-0239) — `txid || auth_digest` — is defined to uniquely fingerprint the physical on-wire transaction, so these forms must produce distinct `wtxid`s.

Tachyon routes the mutable parts through `auth_digest`, leaving `txid` stable:

- `txid` commits to [effecting data](./authorization.md#bundle-commitment) only: the action descriptors `(cv, rk)`, the value balance, the max fee note's value commitment, and the memo. Stripping, merging, re-stamping, and applying or changing the fee leave `txid` unchanged.
- `auth_digest` commits to action signatures and pairs, the fee and fee change, the binding signature, and the stamp digest, including an aggregate's adjunct `txid`s. Each physical auth form yields a distinct `auth_digest` and therefore a distinct `wtxid`.

## `auth_digest` contribution

Zcash's transaction-level `auth_digest` commits to authorization data — the half of `wtxid = txid || auth_digest` that changes when an authorization form changes ([ZIP-239](https://zips.z.cash/zip-0239), [ZIP-244](https://zips.z.cash/zip-0244)).

Tachyon's bundle contributes on both sides:

- **Effecting data → `txid`.** Tachyon's contribution is the bundle commitment over $\mathsf{hActionsTachyon} \,\|\, \mathsf{valueBalanceTachyon} \,\|\, \mathsf{cvFeeMaxTachyon} \,\|\, \mathsf{hMemoTachyon}$.
- **Authorization data → `auth_digest`.** Tachyon's contribution hashes the bundle state byte, one signature-and-pair record per action, the fee, the fee change, the binding signature, and the stamp digest:

$$
\mathsf{tachyon\_auth\_digest} =
\text{BLAKE2b-256}_{\text{``ZTxAuthTachyHash''}}\bigl(
    \mathsf{tachyonBundleState} \,\|\, \mathop{\|}_{i=0}^{n-1}(\mathsf{sig}_i \,\|\, \mathsf{tg}_{i,0} \,\|\, \mathsf{tg}_{i,1})
    \,\|\, \mathsf{LE64}(\mathsf{vFeeTachyon}) \,\|\, \mathsf{cmChangeTachyon}
    \,\|\, \mathsf{bindingSigTachyon} \,\|\, \mathsf{hStampTachyon}
\bigr)
$$

Record $i$ combines `vActionSigsTachyon[i]` with `vActionTachygramsTachyon[i]`, hashing the pair as written. Each record is 128 bytes. The preimage is $137 + 128n$ bytes, with the record sequence its only variable-length input; no count is hashed. This is a digest projection, not the phase-ordered [wire layout](./bundle.md#bundle-body).

For a proof stamp, $\mathsf{hStampTachyon}$ hashes the adjunct txids in list order, followed by the proof digest:

$$
\mathsf{hStampTachyon} =
\text{BLAKE2b-256}_\text{Tachyon-Stamp}\bigl(
    \mathsf{vAdjunctsTachyon} \,\|\, \mathsf{hStampProofTachyon}
\bigr)
$$

$\mathsf{vAdjunctsTachyon}$ is its only variable-length input; no count is hashed. The preimage is $32k + 32$ bytes for $k$ adjuncts. An autonome has an empty adjunct list but still includes the proof digest.

$$
\mathsf{hStampProofTachyon} =
    \text{BLAKE2b-256}_\text{Tachyon-Proof}\bigl(
        \mathsf{anchorTachyon} \,\|\, \mathsf{cTachygrams} \,\|\, \mathsf{proofTachyon}
    \bigr)
$$

covers the stamp proof, the anchor and the tachygram set commitment. A verifier rebuilds the stamp proof's header from the last two. $\mathsf{proofTachyon}$ is its only variable-length input: the Ragu-encoded proof bytes including their envelope. These bytes determine [`sizeProofTachyon`](./bundle.md#stamp-trailer).

A stripped bundle has an empty trailer and no proof digest. Its $\mathsf{hStampTachyon}$ is `STAMP_DIGEST_EMPTY`, the `Tachyon-Stamp` personalized hash of the empty input, written $\text{BLAKE2b-256}_\text{Tachyon-Stamp}(\texttt{""})$. A proof stamp always hashes at least its 32-byte proof digest, so even an autonome has a different stamp-digest preimage. The personalization `"ZTxAuthTachyHash"` is a placeholder until a Tachyon-ZIP amendment to ZIP-244 fixes it.

## Adjunct references

An aggregate refers to each other transaction whose bundle it covers by `txid`, in its [`vAdjunctsTachyon`](./bundle.md#stamp-trailer). Those transactions are still stamped in the mempool and stripped in a block. A stripped bundle holds no reference.

A `txid` is enough to name an adjunct. The stamp proof binds each covered bundle's fee, fee change and unordered action pairs, which are authorization data in the body that a `txid` leaves out. An adjunct with a different fee, fee change or unordered action pair from what the stamp proof covers fails verification; signatures and pair encoding order are not bound by the proof.

A stripped bundle's `wtxid` is a function of that bundle alone. Stripping takes nothing and writes nothing. The miner strips each listed transaction for its block, and a mempool node that strips a copy to verify an aggregate gets the same adjunct and `wtxid`. Lifting, merging or rerandomizing the aggregate's stamp changes the aggregate's `wtxid` and breaks no reference.

A `txid` names a transaction and not one of its authorization forms. Several forms of one `txid` can sit in a mempool, differing in fee, fee change or pairs. A node strips the form it holds and verifies. A form with a different fee, fee change or unordered action pair from what the covering proof binds fails verification.

See [Aggregation → Adjunct list](./aggregation.md#adjunct-list) for who writes the list and the block rules that use it.
