# Tachyon Aggregator Protocol

**Tracking:** [#106](https://github.com/tachyon-zcash/tachyon/issues/106)

**('Additive' ZIP, Category 'Network')**

## I. Dependencies

- [Tachyon Shielded Protocol (#103)](https://github.com/tachyon-zcash/tachyon/issues/103)
  defines the Tachyon pool, Tachyon actions, tachygrams, and the per-action authorization
  layer that aggregation preserves.
- [Tachyon Bundle / Aggregate Transaction Format (#104)](https://github.com/tachyon-zcash/tachyon/issues/104)
  defines the stamped and stripped bundle wire encodings, the `tachyonBundleState` byte,
  the `tachyonAggregateId` trailer, and the stamp trailer fields (including the
  `cActionsTachyon` action-set indicator).
- [Tachyon Accumulator / Hash Chain (#105)](https://github.com/tachyon-zcash/tachyon/issues/105)
  defines the anchor (Poseidon hash-chain state), the per-block anchor sequence, and the
  consensus anchor-membership rule that aggregation depends on for spend validity.
- [ZIP 239](https://zips.z.cash/zip-0239) defines `MSG_WTX`-based transaction relay by
  `wtxid = txid || auth_digest`. This ZIP extends its rationale to Tachyon's
  authorization-form malleability.
- [ZIP 244](https://zips.z.cash/zip-0244) defines the `txid_digest` and `auth_digest`
  trees. A Tachyon amendment to ZIP 244 (tracked separately) fixes the
  `"ZTxAuthTachyHash"` personalization and the Tachyon digest branches; this ZIP does
  not re-specify that algorithm.

## II. Design Considerations

**Aggregation**[^aggregation] is the act of recursively merging per-transaction Ragu PCD stamps into a single aggregate proof, and **aggregators**[^network-roles] are the nodes that perform it.
Miners are likely to vertically integrate aggregation, but a protocol is established for dedicated aggregator nodes to contribute aggregates to the mempool.

[^aggregation]: See [Aggregation](../aggregation.md) for how stamps merge their tachygram and action sets.

[^network-roles]: See [Network Roles](../network_roles/overview.md) for the aggregator and miner roles.

## III. ZIP Draft

--------------------------------------------------------------------------------

```
ZIP: <to be assigned by ZIP Editors>
Title: Tachyon Aggregator Protocol
Owners: <Tachyon team>
Status: Draft
Category: Network
Created: 2026-06-26
License: MIT
Discussions-To: <https://github.com/tachyon-zcash/tachyon/issues/106>
```

## Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", and "RECOMMENDED" in
this document are to be interpreted as described in BCP 14 when, and only when, they
appear in all capitals.

The term "network upgrade" is to be interpreted as described in
[ZIP 200](https://zips.z.cash/zip-0200). The terms "Testnet" and "Mainnet" are to be
interpreted as described in section 3.12 of the Zcash Protocol Specification.

- **Tachygram.** A `byte[32]` field element ($\mathbb{F}_p$) representing either a note
  nullifier or a note commitment. Consensus treats nullifiers and commitments
  identically.
- **Stamp.** A bundle trailer which may replaced with a reference to another
  transaction. Contains a Ragu proof and some associated data necessary for
  verification, including tachygrams.The proof establishes that the actions follow
  the correct rules.
- **Autonome.** A stand-alone transaction with a stamped bundle, containing a
  proof covering only its own actions. The standard form of a user-originated
  Tachyon transaction. An autonome may appear in a block or in the mempool.
- **Aggregate.** A transaction with a stamped bundle, containing a merged stamp
  that covers other transactions. More specifically, an *innocent aggregate*
  contains no Tachyon actions of its own; and a *based aggregate* contains Tachyon
  actions. An aggregate may appear in a block or in the mempool.
- **Adjunct.** A transaction with a stripped bundle. Its proof has been removed
  and replaced by a `wtxid` reference to a covering aggregate. Adjuncts retain
  action data, action signatures, the binding signature, and `value_balance`. An
  adjunct should only appear in a block.

## Abstract

Tachyon shielded transactions use a recursive proof system. To reduce proof
verification costs, recursion is used to combine many per-transaction proofs
into a single proof covering all contributing transactions.

This recursion provides an opportunity to introduce a new participant role
without creating a new trust assumption.

This ZIP specifies: the aggregator protocol, a block-layout discipline under
which miners strip redundant proofs, the semantics about effecting data and
authorizing data that make stripping safe, and P2P rules that extend ZIP 239 to
Tachyon's authorization-form malleability.

Aggregation involves an 8-step lifecycle from transaction authorization, through
the mempool, to block layout, and final validation. All effecting data (actions,
value balances, action signatures, and binding signatures) remains present and
valid when a proof is stripped.

## Motivation

Every proof must be verified to reach consensus. Without aggregation, every
Tachyon bundle would carry a stamp, and consensus costs would be dominated by
stamp data and verification. By specifying an aggregation protocol, consensus
avoids this complexity.

A block in which a large number of Tachyon stamps are aggregated into a smaller
number of Tachyon stamps is completely verified by that smaller number of
stamps, while still allowing every action, signature, and balance to remain
independently valid. In the ideal case, a single proof MAY verify all Tachyon
transactions in a block.

Aggregation is RECOMMENDED, not required. A miner MAY choose to include
completely independent non-aggregated transactions.

## Requirements

(Goals, stated without conformance keywords; the normative rules that meet them live in
the Specification.)

- Reduce per-block stamp-verification cost by allowing multiple transactions' stamps to
  be merged into one aggregate stamp.
- Preserve independent verifiability of every transaction's effecting data: action
  digests, value balances, action signatures, and binding signatures remain checkable
  without trusting the aggregator.
- Preserve transaction-identifier stability: a transaction's `txid` is invariant across
  stamping, merging, and stripping.
- Allow any participant to act as aggregator; no protocol-level exclusivity.
- Enable a validator or miner to confirm they hold all necessary data before
  attempting proof verification.
- Introduce no new trust assumption: every invariant is enforced either by proof
  or by consensus rules.

## Specification

The specification is organised around the 8-step aggregation lifecycle. Each step is a
subsection with conformance language. Two cross-cutting concerns are specified in their own
subsections after the lifecycle and referenced from the steps that invoke them:
[Transaction identifiers and P2P relay](#transaction-identifiers-and-p2p-relay), and
[Covered-transaction identification](#covered-transaction-identification).

### Step 1: Publication of autonomes

Transaction authors produce complete and independently verifiable transactions
with stamped bundles (**autonomes**) and broadcast them to the mempool via the
existing wallet RPC or P2P path.

### Step 2: Aggregator observation and selection

Aggregators observe transactions in mempool gossip (see
[Transaction identifiers and P2P relay](#transaction-identifiers-and-p2p-relay)).

An aggregator selects two transactions (autonomes or existing aggregates) for
merging into a new aggregate. Selected transactions SHOULD bear disjoint
tachygram sets.

### Step 3: Prepare witnesses and PCD

Aggregators reconstruct two stamp PCD from proofs and data available directly on
the input transactions.

If selected transactions bear unequal anchors, aggregators MUST align stamp anchors by
fusing with an anchor PCD that represents the difference. Aggregators are
RECOMMENDED to maintain recent consensus data and cache anchor PCD likely to be
relevant to anchor adjustment.

If selected transactions are autonomes, all necessary witness data is directly
available.

Any selected transaction that is already an aggregate will require additional
action digests from all contributing transactions. Aggregators are RECOMMENDED
to maintain an index of recent mempool transactions likely to be relevant to
witness preparation. Recovering those contributors is
[covered-transaction identification](#covered-transaction-identification): a correct and
complete collection of relevant action digests reproduces the action set commitment on the
selected stamp.

### Step 4: Aggregate construction

Holding two stamp PCD and an appropriate witness, the aggregator may execute a
fuse step to prove a new stamp PCD that covers the selected transactions and all
transactions contributing to the selected transactions.

The aggregator may construct a new transaction bearing the merged stamp, or
simply update one or both of the contributing transactions.

### Step 5: Aggregate publication

Aggregators publish the aggregate transaction to the mempool. A freshly constructed
transaction has a distinct `txid` and `wtxid`; an updated transaction keeps the same `txid`
and produces a new `wtxid` distinct from the input it replaced. Relay follows
[Transaction identifiers and P2P relay](#transaction-identifiers-and-p2p-relay).

### Step 6: Miner observation and selection

Miners observe both autonomes and aggregates in the mempool (see
[Transaction identifiers and P2P relay](#transaction-identifiers-and-p2p-relay)) and select
the aggregates and the transactions they cover to include in a block. Determining which
transactions a candidate aggregate covers is
[covered-transaction identification](#covered-transaction-identification). A miner MAY also
vertically integrate aggregation, producing its own aggregates privately (Step 7) rather
than sourcing them from the mempool.

### Step 7: Block assembly

Use of aggregates within a block is RECOMMENDED, not required.

Miners MAY perform additional aggregation during block assembly, without
publishing the aggregate to the mempool. The resulting aggregate is included
directly in the miner's proposed block. The same `MergeStamp` and
anchor-alignment rules apply.

A block MAY contain, in any combination:

- zero or more non-Tachyon transactions
- zero or more Tachyon autonomes
- zero or more Tachyon aggregates

A block MUST contain a complete set of adjuncts for all included aggregates.
For each covered adjunct the miner includes, the miner MUST strip the adjunct's
stamp and identify the covering aggregate in the `tachyonAggregateId` field.

A stripped innocent (a former innocent aggregate) SHOULD carry a
`tachyonAggregateId` referring to the aggregate which ultimately absorbed its
stamp.

### Step 8: Block validation

All tachygrams in a block MUST be distinct.

All stripped Tachyon transactions MUST bear a `tachyonAggregateId` referring to
the stamped transaction in the same block covering its actions.

All stamped Tachyon transactions MUST bear a `cActionsTachyon` opening to the
complete set of actions for all of its covered transactions in the same block.

All proofs in a block MUST verify.

These are the aggregation-specific rules; other Tachyon consensus rules (action and binding
signatures, value balance, and anchor membership) are base-protocol consensus, specified by
the [Tachyon Shielded Protocol](tachyon-shielded-protocol.md) and
[Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) ZIPs, and apply unchanged. A validator
confirms the rules above as follows, deferring the costly proof verification until the
cheaper checks pass:

1. **Tachygram uniqueness.** The validator MUST reject the block if any
tachygram appears more than once. Reuse within the wider epoch window is
governed by the duplicate-tachygram consensus rule of the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md).
2. **Adjunct association.** Every Tachyon transaction with a stripped bundle
contains a `tachyonAggregateId` that MUST identify a stamped transaction in the
same block. If no transaction is located, or the located transaction bears no
stamp, the validator MUST reject the block.
3. **Action set commitment per stamp.** Every stamp contains a `cActionsTachyon`
which MUST be confirmed by reconstruction. Collect the action digests of the stamped
bundle's own actions together with those of every stripped bundle that names it by
`tachyonAggregateId`, form the polynomial $\prod_i (X - d_i)$ over that combined set, and
take a single Pedersen commitment of it. If the commitment is not equal to the carried
`cActionsTachyon`, the validator MUST reject the block.
4. **Stamp proof verification.** Every Tachyon transaction with a stamped bundle
contains a proof which MUST verify. Reassemble the stamp PCD from the stamp
proof, the stamp's `anchorTachyon`, a Pedersen commitment to the stamp's
`vTachygrams` list of tachygrams, and the confirmed `cActionsTachyon`. If a
proof does not verify, the validator MUST reject the block.

### Transaction identifiers and P2P relay

These semantics underpin publication (Step 5), observation (Steps 2 and 6), and stripping
(Step 7).

**Identifiers.** A Tachyon transaction is identified by `wtxid = txid || auth_digest`
([ZIP 239](https://zips.z.cash/zip-0239), [ZIP 244](https://zips.z.cash/zip-0244)):

- `txid` commits only to effecting data (`action_acc || value_balance`). It is stable across
  stamping, merging, stripping, and re-stamping, so a transaction's logical identity is
  invariant across the aggregation lifecycle.
- `auth_digest` commits to action signatures, the binding signature, and the stamp trailer.
  A stamped bundle's trailer is the full stamp (`cActionsTachyon`, anchor, tachygrams,
  proof); a stripped bundle's trailer is the `byte[64]` covering `wtxid` (the `stampWtxid`
  of the digest contribution). The `"ZTxAuthTachyHash"` personalization is a placeholder
  pending a Tachyon amendment to ZIP 244, which specifies the normative digest algorithm.
- A transaction's effecting data fixes its `txid`, but it can be authorized in several
  physical forms that share that `txid` and differ only in `auth_digest`, hence in `wtxid`:
  a wallet's autonome, an anchor-lifted or proof-rerandomized restamp, and the stripped
  adjunct a miner produces. The covering-aggregate reference an adjunct carries is a
  `wtxid`, not a `txid`, because it must pin a specific physical aggregate.
- The wire byte `tachyonBundleState` (`uint8`) distinguishes forms: `0x00` no Tachyon
  bundle, `0x01` stamped, `0x02` stripped.

**Relay.** Tachyon bundles are announced and fetched by `wtxid` using the
`MSG_WTX` inv type, and nodes MUST treat distinct `wtxid`s as distinct inventory
objects. `MSG_WTX` relay is mandatory: restamping changes a transaction's
`wtxid` while leaving `txid` unchanged, so announcement by `txid` alone could
not distinguish the stamped forms a node may be offered.

**Stripped bundles are forbidden from the mempool.** A bundle in the stripped state
(`tachyonBundleState == 0x02`) MUST NOT be accepted into the mempool, relayed, or published
by an aggregator; it is valid only inside a block. The P2P network carries stamped bundles
(autonomes and aggregates) only, and an aggregator publishes its merged stamp as a new
stamped aggregate rather than a stripped form. This relay policy and `MSG_WTX` operate at
different layers: `MSG_WTX` fixes the identifier and inventory semantics, while the policy
admits only the stamped forms. A stripped form's `wtxid` is still meaningful at the block
layer, where a block commits to each included transaction by `wtxid`
([ZIP 244](https://zips.z.cash/zip-0244)); that is what lets a block name an adjunct
unambiguously even though relay only ever carried the stamped form.

### Covered-transaction identification

Identifying which transactions a stamp covers is a single primitive, used by aggregators
preparing a merge witness (Step 3) and by miners observing and composing a block (Steps 6
and 7).

Tachygrams give a first pass: an aggregate's stamp publishes the tachygrams of every action
it covers, so transactions whose tachygrams appear there are candidates. But tachygram
matching only narrows the candidate set; it cannot confirm the set is complete. A based
aggregate's own tachygrams are not labelled, and tachygrams do not distinguish nullifiers
from commitments, so a near-complete collection is indistinguishable from the complete one.
Absent a faster check, the only way to discover whether a candidate set is exactly the cover
would be to attempt the aggregate's full proof verification, which fails only after that
costly attempt when a transaction is missing.

`cActionsTachyon` is that faster check. The aggregate's stamp publishes it as a commitment
to the action-digest set of every action the aggregate covers. A candidate set is tested by
reconstructing the commitment from the candidate actions and matching: each action digest
$d_i = \text{Poseidon}_\texttt{Tachyon-ActionDg}(\mathsf{cv}_i \,\|\, \mathsf{rk}_i)$ is
computable from public action data, so the check costs $O(n)$ polynomial arithmetic plus one
Pedersen commitment and attempts no proof verification. A match confirms the candidate set is
exactly the cover; a mismatch is fail-fast.

## Reference implementation

A reference implementation of the Tachyon aggregator protocol (the bundle state machine,
stamp merging, stripping, and the `cActionsTachyon` coverage check) is in the
`zcash_tachyon` crate under [`crates/tachyon/src/`](../../crates/tachyon/src/).

## Rationale

**Lifecycle-structured specification.** Organising the Specification around the lifecycle
mirrors how participants actually move through the protocol. The two concerns that several
steps share, transaction-identifier and relay semantics and covered-transaction
identification, are factored into their own subsections and referenced from the steps, so no
step restates another's rules and the lifecycle reads as a sequence of actions.

**Cheap coverage confirmation.** Matching previously-seen tachygrams associates an
aggregate with the autonomes it covers, but cannot confirm the association is complete: a
based aggregate's own tachygrams are indistinguishable from its covered autonomes'. The
`cActionsTachyon` indicator gives observers a fail-fast completeness check over the
action-digest set, reusing the commitment the proof already attests to rather than adding
a signed coverage manifest or a tachygram-origin query protocol.

**Aggregate limits.** Two hard limits bound an aggregate. Its tachygram vector is committed
as a ragu polynomial, so it cannot exceed the maximum ragu polynomial size; and the
aggregate transaction, like any transaction, is bounded by block size. Construction is also
shaped by parallelism: a single merge is sequential, since each `MergeStamp` consumes the
previous result, but independent aggregates can be built in parallel.

**`wtxid`, not `txid`, for adjunct references.** A `txid` would be ambiguous across
the autonome/aggregate forms (they share effecting data). The `wtxid` pins a specific
physical aggregate including its stamp state, which is what the adjunct needs to
reference. This is why the `tachyonAggregateId` holds a `wtxid` rather than a `txid`.

**Stripping is miner-side, not relay-time.** Stripping at relay time would force every
relay node to understand aggregate coverage and would mix block-assembly policy with
gossip. Keeping the P2P network carrying stamped bundles only, and forbidding stripped
bundles from the mempool, simplifies relay and matches the implementation (a stripped
bundle is not serializable until its covering `wtxid` is assigned, which happens at block
assembly).

**`MSG_WTX` relay is mandatory.** Tachyon's authorization-form malleability is the direct
analogue of the v5 witness malleability that motivated ZIP 239: restamping and proof
rerandomization yield distinct `wtxid`s over one stable `txid`, all relayable. Announcing
by `txid` alone would let one such form shadow another in relay. Requiring `MSG_WTX`
for Tachyon bundles closes this exactly as ZIP 239 closed it for v5.

## Security and Privacy Implications

**No new trust assumption.** The aggregator is not trusted. Every invariant is
enforced either inside the Ragu PCD (circuit logic) or by consensus checks on public
data (consensus logic). A malicious aggregator can publish an invalid aggregate, but
validators will reject it at Step 8. A malicious miner can mis-assign adjuncts or
omit covered transactions, but the block will fail validation.

**Data availability.** Aggregation removes redundant proof bytes only. Every adjunct
retains its action data, action signatures, binding signature, and `value_balance`;
validators reconstruct the aggregate header from this public data. An aggregate proof
alone is insufficient: the covered effecting data is present in the block as adjuncts,
and Step 8 rejects any block where it is not.

**`cActionsTachyon` is confirmed, not trusted.** The action set is bound by the proof. Block
validation confirms the carried `cActionsTachyon` by reconstructing the action-set commitment
from the actions actually present in the block, rejects on any mismatch, and only then uses
the confirmed value as the proof header. That confirmation is what ties the proof to the
adjuncts the block carries, not to a value the prover supplies, so a wrong `cActionsTachyon`
cannot pass and only harms its author. The carried value lets observers identify coverage
cheaply (see [Covered-transaction identification](#covered-transaction-identification)); it
is reconstructable from visible actions, so it reveals nothing the actions do not, and for a
based aggregate it does not expose which actions are the aggregator's own.

**Privacy of aggregation relationships.** An observer who sees an aggregate in the
mempool can identify covered autonomes by the `cActionsTachyon` check (see
[Covered-transaction identification](#covered-transaction-identification)). This
is inherent to the scheme: the aggregate must carry enough information for validators
to reconstruct its header. The tachygram-set and action-digest-set commitments do not
reveal the private contents of any covered note.

**Circuit/consensus boundary.** Several security properties are enforced by consensus
rather than fully proven inside the stamp. Double-spend prevention rests on the block-scoped
tachygram-uniqueness check (Step 8) together with the epoch-scoped tachygram-uniqueness,
anchor membership, and spendable-lineage rules owned by the
[Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) and
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIPs. Those base-protocol rules are depended upon, not re-specified
here, so implementers and auditors should not assume the proof alone establishes these
properties.

## References

- [ZIP 0: ZIP Process](https://zips.z.cash/zip-0000)
- [ZIP 200: Network Upgrade Mechanism](https://zips.z.cash/zip-0200)
- [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)
- [ZIP 239: Relay of Version 5 Transactions](https://zips.z.cash/zip-0239)
- [ZIP 244: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-0244)
- [ZIP 252: Deployment of the NU5 Network Upgrade](https://zips.z.cash/zip-0252)
- [ZIP 317: Proportional Transfer Fee Mechanism](https://zips.z.cash/zip-0317)
- [BIP 339: WTXID-based transaction relay](https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki)
- [Tachyon Shielded Protocol](tachyon-shielded-protocol.md)
- [Tachyon Accumulator / Hash Chain](tachyon-accumulator.md)
