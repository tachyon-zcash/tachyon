# Transaction Identifiers

A Tachyon bundle's authorization form changes as it moves through aggregation: stamping, merging into a covering aggregate, and stripping all produce bit-different authorizations of the same effecting data. [`wtxid`](https://zips.z.cash/zip-0239) — `txid || auth_digest` — is defined to uniquely fingerprint the physical on-wire transaction, so these forms must produce distinct `wtxid`s.

Tachyon routes the mutable parts through `auth_digest`, leaving `txid` stable:

- `txid` commits to [effecting data](./authorization.md#bundle-commitment) only: the action descriptors `(cv, rk)`, the value balance, the max fee note's value commitment, and the memo. Stripping, merging, re-stamping, and applying or changing the fee leave `txid` unchanged.
- `auth_digest` commits to action sigs and the stamp trailer, which carries the action pairs, the fee and the fee change, and on an aggregate the `txid`s of its adjuncts. Each physical auth form yields a distinct `auth_digest` and therefore a distinct `wtxid`.

## `auth_digest` contribution

Zcash's transaction-level `auth_digest` commits to authorization data — the half of `wtxid = txid || auth_digest` that changes when an authorization form changes ([ZIP-239](https://zips.z.cash/zip-0239), [ZIP-244](https://zips.z.cash/zip-0244)).

Tachyon's bundle contributes on both sides:

- **Effecting data → `txid`.** Tachyon's contribution is the bundle commitment over $\mathsf{hActionsTachyon} \,\|\, \mathsf{valueBalanceTachyon} \,\|\, \mathsf{cvFeeMaxTachyon} \,\|\, \mathsf{hMemoTachyon}$.
- **Authorization data → `auth_digest`.** Tachyon's contribution hashes the bundle state byte, the action signatures, the binding signature, and one digest of whichever stamp the bundle carries:

$$
\mathsf{tachyon\_auth\_digest} =
\text{BLAKE2b-256}_{\text{``ZTxAuthTachyHash''}}\bigl(
    \mathsf{tachyonBundleState} \,\|\, \mathsf{vActionSigsTachyon} \,\|\, \mathsf{bindingSigTachyon}
    \,\|\, \mathsf{hStampTachyon}
\bigr)
$$

$\mathsf{hStampTachyon}$ covers every field applied after signing, with one layout for both stamp forms: the bundle's action pairs as written, 64 bytes per pair, and its fee change, then the fee, then a digest of the adjunct list and a digest of the stamp proof:

$$
\mathsf{hStampTachyon} =
\text{BLAKE2b-256}_\text{Tachyon-Stamp}\bigl(
    \mathsf{vTachygrams} \,\|\, \mathsf{LE64}(\mathsf{vFeeTachyon}) \,\|\, \mathsf{hStampAdjunctsTachyon} \,\|\, \mathsf{hStampProofTachyon}
\bigr)
$$

$\mathsf{vTachygrams}$ is its only variable-length input.

$$
\mathsf{hStampAdjunctsTachyon} =
\text{BLAKE2b-256}_\text{Tachyon-Adjuncts}\bigl(\mathsf{vAdjunctsTachyon}\bigr)
$$

covers the adjunct txids in list order. The list is empty for an autonome and for a stripped stamp.

$$
\mathsf{hStampProofTachyon} = \begin{cases}
    \text{BLAKE2b-256}_\text{Tachyon-Proof}\bigl(
        \mathsf{anchorTachyon} \,\|\, \mathsf{cTachygrams} \,\|\, \mathsf{proofTachyon}
    \bigr) & \text{if stamped}\\
    \text{BLAKE2b-256}_\text{Tachyon-Proof}() & \text{if stripped}
\end{cases}
$$

covers the stamp proof, the anchor and the tachygram set commitment. A verifier rebuilds the stamp proof's header from the last two. $\mathsf{proofTachyon}$ is its only variable-length input: the Ragu-encoded proof bytes including their envelope. These bytes determine [`sizeProofTachyon`](./bundle.md#stamp-trailer).

A stripped bundle has no adjunct list and no stamp proof. Both digests take ZIP 244's value for an absent component, the personalized hash of the empty input. A stamped preimage of $\mathsf{hStampProofTachyon}$ is at least 64 bytes, so the two forms differ inside $\mathsf{hStampTachyon}$ itself. A stripped bundle's $\mathsf{hStampTachyon}$ depends on that bundle alone. The personalization `"ZTxAuthTachyHash"` is a placeholder until a Tachyon-ZIP amendment to ZIP-244 fixes it.

## Adjunct references

An aggregate refers to each other transaction whose bundle it covers by `txid`, in its [`vAdjunctsTachyon`](./bundle.md#stamp-trailer). Those transactions are still stamped in the mempool and stripped in a block. A stripped bundle holds no reference.

A `txid` is enough to name an adjunct. The stamp proof binds each covered bundle's fee, fee change and pairs, which are the stamp fields a `txid` leaves out. An adjunct whose stamp fields differ from what the stamp proof covers fails verification.

A stripped bundle's `wtxid` is a function of that bundle alone. Stripping takes nothing and writes nothing. The miner strips each listed transaction for its block, and a mempool node that strips a copy to verify an aggregate gets the same adjunct and `wtxid`. Lifting, merging or rerandomizing the aggregate's stamp changes the aggregate's `wtxid` and breaks no reference.

A `txid` names a transaction and not one of its authorization forms. Several forms of one `txid` can sit in a mempool, differing in fee, fee change or pairs. A node strips the form it holds and verifies. A wrong form fails verification.

See [Aggregation → Adjunct list](./aggregation.md#adjunct-list) for who writes the list and the block rules that use it.
