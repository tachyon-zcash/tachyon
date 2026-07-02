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

The terms "tachygram" and "stamp" are defined by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) and
[Tachyon Bundle / Aggregate Transaction Format](tachyon-bundle.md) ZIPs respectively, and
are summarized here non-normatively. The remaining terms are defined by this ZIP.

- **Tachygram.** The `byte[32]` encoding of a field element ($\mathbb{F}_p$)
  representing either a note nullifier or a note commitment. Consensus treats
  nullifiers and commitments identically.
- **Stamp.** A bundle trailer carrying a Ragu proof and the data necessary to
  verify it, including tachygrams. The proof attests that every covered action
  satisfies the Tachyon action rules. A bundle's stamp may be replaced by a
  reference to a covering transaction (see Adjunct).
- **Autonome.** A stand-alone transaction with a stamped bundle, whose proof
  covers only its own actions. The standard form of a user-originated Tachyon
  transaction. An autonome may appear in a block or in the mempool.
- **Aggregate.** A transaction with a stamped bundle, whose merged stamp covers
  other transactions. An *innocent aggregate* contains no Tachyon actions of its
  own; a *based aggregate* contains Tachyon actions. An aggregate may appear in
  a block or in the mempool.
- **Adjunct.** A transaction with a stripped bundle: its stamp has been removed
  and replaced by a `wtxid` reference to a covering aggregate. Adjuncts retain
  action data, action signatures, the binding signature, and `value_balance`.
  An adjunct is valid only within a block.

## Abstract

Tachyon shielded transactions use a recursive proof system. Recursion allows
many per-transaction proofs to be combined into a single proof covering all
contributing transactions, reducing proof verification costs. This recursion
admits a new participant role, the aggregator, without creating a new trust
assumption.

This ZIP specifies the aggregator protocol: an 8-step lifecycle from
transaction authorization, through the mempool, to block layout and final
validation. It comprises a block-layout discipline under which miners strip
redundant proofs, the effecting-data and authorizing-data semantics that make
stripping safe, and P2P rules extending ZIP 239 to Tachyon's
authorization-form malleability. All effecting data (actions, value balances,
action signatures, and binding signatures) remains present and valid when a
proof is stripped.

## Motivation

Consensus requires every proof in a block to be verified. Without aggregation,
every Tachyon bundle would carry a stamp, and consensus costs would be
dominated by stamp data and stamp verification. Aggregation bounds that cost.

A block in which a large number of Tachyon stamps have been aggregated into a
smaller number of stamps is completely verified by that smaller number of
stamps, while every action, signature, and balance remains independently
verifiable. In the ideal case, a single proof verifies all Tachyon
transactions in a block.

Aggregation is optional. Miners remain free to include non-aggregated Tachyon
transactions; any aggregate a block does contain must be fully backed by
adjuncts in the same block.

## Requirements

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

The specification is organized around the 8-step aggregation lifecycle. Each step is a
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
tachygram sets: merging combines tachygram sets, and a block containing a
duplicate tachygram is invalid (Step 8), so an aggregate built from
overlapping sets can never be included in a valid block.

### Step 3: Witness and PCD preparation

The aggregator reconstructs each selected transaction's stamp PCD from the
proof and data carried on that transaction.

Merging is defined only over stamps bearing identical anchors. If the selected
transactions bear unequal anchors, the aggregator MUST first align them by
fusing with an anchor PCD that proves the sequence from one anchor to the
other. Aggregators SHOULD maintain recent consensus data and cache anchor PCD
likely to be relevant to anchor alignment.

If both selected transactions are autonomes, all necessary witness data is
directly available on the transactions themselves.

A selected transaction that is already an aggregate additionally requires the
action digests of every transaction contributing to it. Recovering those
contributors is
[covered-transaction identification](#covered-transaction-identification): a correct and
complete collection of action digests reproduces the action set commitment on the
selected stamp. Aggregators SHOULD maintain an index of recent mempool
transactions likely to be relevant to witness preparation.

### Step 4: Aggregate construction

Holding two stamp PCD with identical anchors and the prepared witness, the
aggregator executes a merge, proving a new stamp PCD that covers the selected
transactions and every transaction contributing to them.

The aggregator MAY construct a new transaction bearing the merged stamp, or
MAY update either contributing transaction in place, replacing its stamp with
the merged stamp.

### Step 5: Aggregate publication

The aggregator publishes the aggregate transaction to the mempool. A newly
constructed transaction bears a new `txid` and `wtxid`; an updated transaction
retains its `txid` and bears a new `wtxid`, distinct from the form it replaced.
Relay follows
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
directly in the miner's proposed block. The merge and anchor-alignment rules
of Steps 3 and 4 apply unchanged.

A block MAY contain, in any combination:

- zero or more non-Tachyon transactions
- zero or more Tachyon autonomes
- zero or more Tachyon aggregates

A block containing an aggregate MUST also contain, as adjuncts, every
transaction that aggregate covers. For each such adjunct, the miner MUST strip
the bundle's stamp and set the `tachyonAggregateId` field to the covering
aggregate's `wtxid`.

A stripped innocent (a former innocent aggregate) contributes no actions, but
the stripped form still names a covering transaction. Its `tachyonAggregateId`
MUST identify a stamped transaction in the same block, and SHOULD refer to the
aggregate that ultimately absorbed its stamp. The latter is unverifiable: a
bundle with no actions contributes no action digests to any reconstruction, so
a validator cannot distinguish the absorbing aggregate from any other stamped
transaction (Step 8).

### Step 8: Block validation

All tachygrams in a block MUST be distinct.

Every stripped Tachyon transaction MUST bear a `tachyonAggregateId` referring
to the stamped transaction in the same block covering its actions.

Every stamped Tachyon transaction MUST bear a `cActionsTachyon` opening to the
complete set of actions of its covered transactions in the same block.

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
2. **Adjunct association.** The `tachyonAggregateId` of every stripped bundle
MUST identify a stamped transaction in the same block. If the referenced
transaction is absent from the block, or bears no stamp, the validator MUST
reject the block. A stripped bundle with no actions satisfies this check
against any stamped transaction in the block: it contributes no action digests
to the reconstruction in item 3, so consensus attaches no further meaning to
its reference.
3. **Action set commitment per stamp.** The validator MUST confirm each stamp's
`cActionsTachyon` by reconstruction: collect the action digests of the stamped
bundle's own actions together with those of every stripped bundle that names it
by `tachyonAggregateId`, form the polynomial $\prod_i (X - d_i)$ over that
combined set, and take a single Pedersen commitment of it. If the reconstructed
commitment does not equal the carried `cActionsTachyon`, the validator MUST
reject the block.
4. **Stamp proof verification.** Every stamped bundle's proof MUST verify. The
validator reassembles the stamp PCD from the stamp proof, the stamp's
`anchorTachyon`, a Pedersen commitment to the stamp's `vTachygrams` list of
tachygrams, and the confirmed `cActionsTachyon`. If any proof does not verify,
the validator MUST reject the block.

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
- A transaction's effecting data fixes its `txid`, but the transaction can be authorized
  in several physical forms that share that `txid` and differ only in `auth_digest`, hence
  in `wtxid`:
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
aggregate's own tachygrams are not labeled, and tachygrams do not distinguish nullifiers
from commitments, so a near-complete collection is indistinguishable from the complete one.
Absent a faster check, the only way to discover whether a candidate set is exactly the cover
would be to attempt the aggregate's full proof verification, which fails only after that
costly attempt when a transaction is missing or extra.

`cActionsTachyon` is that faster check. The aggregate's stamp publishes it as a commitment
to the action-digest set of every action the aggregate covers. A candidate set is tested by
reconstructing the commitment from the candidate actions and matching: each action digest is
computable from the action's public data, as specified by the
[Tachyon Bundle / Aggregate Transaction Format](tachyon-bundle.md) ZIP, so the check costs
$O(n)$ polynomial arithmetic plus one Pedersen commitment and attempts no proof
verification. A match confirms the candidate set is exactly the cover; a mismatch is
fail-fast.

## Reference implementation

A reference implementation of the Tachyon aggregator protocol (the bundle state machine,
stamp merging, stripping, and the `cActionsTachyon` coverage check) is in the
`zcash_tachyon` crate under [`crates/tachyon/src/`](../../crates/tachyon/src/).

## Rationale

**Lifecycle-structured specification.** Organizing the Specification around the lifecycle
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
as a Ragu polynomial, so it cannot exceed the maximum Ragu polynomial size; and the
aggregate transaction, like any transaction, is bounded by block size. Construction is also
shaped by parallelism: a chain of merges is sequential, since each merge consumes the
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
block validation (Step 8) rejects it. A malicious miner can mis-assign adjuncts or
omit covered transactions, but the block fails validation.

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
reveal the private contents of any covered note. The `tachyonAggregateId` of a stripped
innocent is not consensus-validated beyond naming a stamped transaction (Step 8, item 2),
so an observer reconstructing aggregation relationships cannot rely on an actionless
bundle's reference.

**Circuit/consensus boundary.** Several security properties are enforced by consensus
rather than fully proven inside the stamp. Double-spend prevention rests on the block-scoped
tachygram-uniqueness check (Step 8) together with the epoch-scoped tachygram-uniqueness,
anchor membership, and spendable-lineage rules owned by the
[Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) and
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIPs. Those base-protocol rules are depended upon, not re-specified
here, so implementers and auditors should not assume the proof alone establishes these
properties.

## References

- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [ZIP 200: Network Upgrade Mechanism](https://zips.z.cash/zip-0200)
- [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)
- [ZIP 239: Relay of Version 5 Transactions](https://zips.z.cash/zip-0239)
- [ZIP 244: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-0244)
- [BIP 339: WTXID-based transaction relay](https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki)
- [Tachyon Shielded Protocol](tachyon-shielded-protocol.md)
- [Tachyon Bundle / Aggregate Transaction Format](tachyon-bundle.md)
- [Tachyon Accumulator / Hash Chain](tachyon-accumulator.md)
