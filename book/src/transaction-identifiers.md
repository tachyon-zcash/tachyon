# Transaction Identifiers

A Tachyon bundle's authorization form changes as it moves through aggregation: stamping, merging into a covering aggregate, and stripping all produce bit-different authorizations of the same effecting data. [`wtxid`](https://zips.z.cash/zip-0239) — `txid || auth_digest` — is defined to uniquely fingerprint the physical on-wire transaction, so these forms must produce distinct `wtxid`s.

Tachyon routes the mutable parts through `auth_digest`, leaving `txid` stable:

- `txid` commits to [effecting data](./authorization.md#bundle-commitment) only: `action_acc || value_balance`. Stripping, merging, and re-stamping leave `txid` unchanged.
- `auth_digest` commits to sigs plus the stamp trailer. Each physical auth form yields a distinct `auth_digest` and therefore a distinct `wtxid`.

## `auth_digest` contribution

Zcash's transaction-level `auth_digest` commits to authorization data — the half of `wtxid = txid || auth_digest` that changes when an authorization form changes ([ZIP-239](https://zips.z.cash/zip-0239), [ZIP-244](https://zips.z.cash/zip-0244)).

Tachyon's bundle contributes on both sides:

- **Effecting data → `txid`.** Tachyon's contribution is the bundle commitment `action_acc || value_balance`.
- **Authorization data → `auth_digest`.** Tachyon's contribution hashes action signatures, the binding signature, and the bundle's stamp trailer:

$$
\mathsf{auth\_digest\_contribution} =
\text{BLAKE2b-256}_{\text{``ZTxAuthTachyHash''}}\bigl(\\
\quad \mathsf{vActionSigs} \,\|\, \mathsf{bindingSig} \\
\quad\|\,\begin{cases}
    \text{anchor}_h \,\|\, \text{anchor}_{\text{pc}} \,\|\, \text{nTachygrams} \,\|\, \text{vTachygrams} \,\|\, \text{proof} & \text{if stamped}\\
    \text{stampWtxid}_{64} & \text{if stripped}
\end{cases}\bigr)
$$

A stamped bundle's trailer is its stamp (anchor + tachygrams + proof); a stripped bundle's trailer is the 64-byte `wtxid` of the covering aggregate. The personalization `"ZTxAuthTachyHash"` is a placeholder until a Tachyon-ZIP amendment to ZIP-244 fixes it.

## Covering-aggregate references

An adjunct's reference to the aggregate that covers it is a `wtxid`, not a `txid` — the 64-byte `wtxid` pins a specific physical aggregate, whereas a `txid` only pins the effecting data.

Miners assign the reference during block assembly. The covering aggregate must itself be top-level in the block — never stripped, never further aggregated — so the `wtxid` pointed to is stable. See [Aggregation → Block Layout](./aggregation.md#block-layout) for how references are resolved in a block.
