# Tachyon Aggregator Protocol

**Tracking:** [#106](https://github.com/tachyon-zcash/tachyon/issues/106)

**('Additive' ZIP, Category 'Network')**

## I. Dependencies

- [Tachyon Shielded Protocol (#103)](https://github.com/tachyon-zcash/tachyon/issues/103)
  defines the Tachyon pool, tachyactions, tachygrams, and the per-action authorization
  layer that aggregation preserves.
- [Tachyon Bundle / Aggregate Transaction Format (#104)](https://github.com/tachyon-zcash/tachyon/issues/104)
  defines the stamped and stripped bundle wire encodings, the `tachyonBundleState` byte,
  the `tachyonAggregateId` trailer, and the serialization of the `ActionSetCommit` field
  on the stamp that this ZIP relies on for covered-transaction identification.
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
- [ZIP 248](https://zips.z.cash/zip-0248) (extensible transaction format) is required
  for registering the Tachyon bundle type on the v5 transaction format.

## II. Design Considerations

### Aggregation as a network role

Tachyon seeks to reduce chain costs by recursively merging per-transaction Ragu PCD
stamps into a single aggregate proof that covers many transactions. The act of merging
proofs is **aggregation**, and **aggregators** are the nodes that perform it. Miners
are likely to vertically integrate aggregation, but the protocol must also work for
third-party aggregators that publish aggregates to the mempool. See
[Network Roles](../network_roles/overview.md) and [Aggregation](../aggregation.md).

### The 10-step lifecycle

The Specification is organised around the following lifecycle, distilled in
[Aggregation](../aggregation.md):

1. Autonome transactions are published to the mempool.
2. Aggregators observe transactions in the mempool.
3. Aggregators produce their own transactions with merged stamps.
4. Aggregators publish their own transactions to the mempool, and do not re-publish the
   autonomes they covered.
5. Miners see transactions in the mempool.
6. Miners identify the aggregate/autonome relationship by action-set commitment
   (`ActionSetCommit`) match.
7. Miners may perform their own aggregation privately, without publishing to the
   mempool.
8. Miners compose their block at will, stripping stamps and assigning the covering
   aggregate `wtxid` to each adjunct.
9. The miner proposes a block.
10. Block validation only passes if the appropriate adjuncts are included and properly
    assigned aggregate ids, enabling header reconstruction and verification.

### Based-aggregate tachygram attribution

A **based aggregate** carries its own tachyactions in addition to a merged stamp
covering other transactions. Its stamp tachygram set is the union of the covered
autonomes' tachygrams and the based aggregate's own tachygrams, with no in-protocol
label distinguishing the two ([Bundles](../bundle.md)). An observer with an incomplete
mempool view therefore cannot partition the published tachygram set, and cannot confirm
by tachygram overlap alone that it holds every autonome that must become an adjunct.

The protocol resolves this with the `ActionSetCommit` field carried on the stamp header:
an observer reconstructs the action-digest-set commitment from visible actions and
matches it against the aggregate's published `ActionSetCommit`, a cheap fail-fast check
that needs no proof verification. The normative mechanism is specified in Step 6
below; the design trade-offs and soundness/privacy arguments are folded into the
Rationale and the Security and Privacy Implications sections. The encoding of
`ActionSetCommit` on the stamp wire format is specified by the Tachyon Bundle / Aggregate
Transaction Format ZIP (#104).

### Open questions

The following remain unresolved at Draft and are not normatively specified below:

- **Aggregate limits.** Fan-in, recursion depth, proof size, tachygram vector size,
  action count, and per-block aggregate count. Aggregate size is commitment-size-limited
  before block-size-limited (on the order of thousands of actions); exact limits TBD.
- **Anchor publication and membership.** Specified by the accumulator/anchor ZIP (#105);
  this draft states the dependency.
- **Fee accounting (ZIP 317).** `contribution_Tachyon` must account for logical work
  split between adjuncts (actions) and aggregates (proofs); under discussion.
- **Value-pool balance (ZIP 209).** `valueBalanceTachyon` turnstile integration; under
  discussion.
- **Block commitments (ZIP 221).** How Tachyon's end-of-block anchor enters the MMR
  leaf; under discussion.
- **Bundle serialization registration (ZIP 248).** Pending ZIP-248 editor consensus.
- **P2P aggregation gossip.** Secondary objective; selection criteria (covered-
  transaction set, size, anchor alignment) remain an open policy question. Single-
  aggregate merge is not parallelizable, but multiple aggregates can be built in
  parallel.
- **`mock_ragu` vs real Ragu.** The normative text below describes the intended real
  Ragu PCD semantics. The current Tachyon implementation uses a permissive mock; a green
  test suite against the mock is not soundness.

## III. ZIP Draft

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
  identically; one accumulator handles both. See [Tachygrams](../tachygrams.md).
- **Tachyaction.** An indistinguishable representation of either the creation or
  destruction of a note. Contains `cv`, `rk`, and `sig`; each tachyaction is
  cryptographically bound to one tachygram but does not contain it. A spend additionally
  publishes a next-epoch nullifier, so a stamp's tachygram set is not in 1:1
  correspondence with its actions. See [Bundles](../bundle.md).
- **Stamp.** The recursive Ragu PCD proof data carried by a stamped bundle: `anchor`,
  `tachygrams`, `proof`, and `ActionSetCommit`. The proof establishes that the
  tachyactions follow the correct rules and that the published tachygrams and action
  digests correspond to those actions.
- **Autonome.** A stamped bundle produced by a wallet, carrying a complete proof with
  all inputs. The standard form of a user-originated Tachyon transaction.
- **Aggregate.** A stamped bundle produced by an aggregator, carrying a merged stamp
  that covers multiple bundles. An *innocent* aggregate contains no Tachyon actions of
  its own; a *based* aggregate carries its own Tachyon actions in addition to the merged
  stamp.
- **Adjunct.** A stripped bundle whose stamp has been removed and replaced by a
  `tachyonAggregateId` reference to the covering aggregate. Adjuncts retain action data,
  action signatures, the binding signature, and `value_balance`.
- **`ActionSetCommit`.** A Pedersen commitment to the action-digest-set polynomial, with
  exactly one root per action:
  $\mathsf{ActionSetCommit} = \mathsf{Commit}\bigl(\prod_i (X - d_i)\bigr)$, where each
  action digest $d_i = \text{Poseidon}_\texttt{Tachyon-ActionDg}(\mathsf{cv}_i \,\|\, \mathsf{rk}_i)$
  is defined in [Authorization](../authorization.md). This is the same commitment the book
  calls `action_acc`. It is a PCD header field (`StampHeader::Data` carries it), and its
  on-wire encoding is specified by the bundle-format ZIP (#104).
- **`tachyonAggregateId`.** The wire field on a stripped bundle that replaces its stamp:
  the `byte[64]` `wtxid` of the covering aggregate (the implementation type is
  `AggregateId`). It is a `wtxid`, not a `txid`, so it pins a specific physical aggregate
  including its stamp state. The `auth_digest` contribution refers to this same value as
  `stampWtxid` (see [Transaction Identifiers](../transaction-identifiers.md)).
- **`txid`.** The transaction identifier, committing only to effecting data. For a
  Tachyon bundle, the `txid` contribution is `action_acc || value_balance`. Stable
  across stamping, merging, and stripping.
- **`auth_digest`.** The authorizing-data commitment. For a Tachyon bundle, commits to
  action signatures, the binding signature, and the stamp trailer. Each physical
  authorization form yields a distinct `auth_digest`.
- **`wtxid`.** The `byte[64]` witnessed transaction identifier `txid || auth_digest`. The
  unit of physical relay per [ZIP 239](https://zips.z.cash/zip-0239).

## Abstract

Tachyon shielded transactions carry recursive Ragu PCD stamps whose verification cost
is substantial. Verifying each transaction's stamp independently at consensus would
dominate block-validation cost. This ZIP specifies the Tachyon aggregator protocol: a
network role that merges stamps from multiple stamped transactions into a single
aggregate stamp, and a block-layout discipline under which miners strip the now-
redundant per-transaction stamps and replace them with a reference to the covering
aggregate. The same effecting data — tachyactions, value balances, action signatures,
and binding signatures — remains independently verifiable; only the proof bytes are
deduplicated. The ZIP defines the 10-step aggregation lifecycle from autonome
publication through block validation, the transaction-identifier semantics that make
stripping safe, the P2P relay rules that extend ZIP 239 to Tachyon's authorization-form
malleability, and a fail-fast covered-transaction identification mechanism based on the
`ActionSetCommit` field carried on the stamp. Aggregation introduces a new network
participant but no new trust assumption: every invariant is enforced either inside the
Ragu PCD or by consensus checks on public data.

## Motivation

Without aggregation, every Tachyon transaction in a block carries its own Ragu PCD
stamp, and validators must verify each stamp independently. Stamp verification is the
dominant per-transaction cost; at scale this limits throughput and raises the barrier
to running a validating node.

Ragu PCD stamps are recursively composable: two stamps at a common anchor can be merged
into a single stamp that attests to the union of the two action-digest and tachygram
sets. This composition is what aggregation exploits. An aggregator merges stamps off-
chain and publishes a single aggregate transaction carrying the merged stamp; miners
strip the redundant per-transaction stamps at block-assembly time, leaving each covered
transaction as an adjunct that carries its effecting data plus a reference to the
covering aggregate.

The result is that a block containing $N$ Tachyon transactions need only verify a small
number of aggregate stamps rather than $N$ independent proofs, while still allowing every
action, signature, and value balance to be independently checked. This ZIP specifies
the network behaviour, the block-layout rules, and the identification mechanism that
makes the scheme work without a trusted aggregator.

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
- Allow any participant (miner or third-party) to act as aggregator; no protocol-level
  exclusivity or claim on autonomes.
- Enable a validating observer or miner to confirm, cheaply and fail-fast, that they
  hold every autonome covered by an aggregate before assembling or validating a block.
- Introduce no new trust assumption: every invariant is enforced either inside the Ragu
  PCD or by consensus checks on public data.

## Specification

The specification is organised around the 10-step aggregation lifecycle. Each step is
a subsection with conformance language. Transaction-identifier semantics and P2P relay
rules are folded into the relevant steps rather than specified as parallel sections.

This specification applies identically to Mainnet and Testnet.

### Step 1: Publication of autonomes

Wallets construct stamped bundles — **autonomes** — and broadcast them to the mempool
via the existing wallet RPC or P2P path. An autonome is a standard stamped transaction
with a complete Ragu PCD proof, a serialized `ActionSetCommit`, and a distinct `wtxid`.
Autonomes are announced and relayed by `wtxid` per Step 5.

### Step 2: Aggregator mempool observation

Aggregators observe stamped transactions in mempool gossip. An aggregator MAY select
any subset of autonomes (and existing aggregates) for merging. There is no protocol-
level exclusivity or claim on autonomes: multiple aggregators MAY attempt to cover the
same autonome, and a miner MAY prefer one aggregate over another at block-assembly
time.

### Step 3: Aggregate construction

Aggregators merge stamps as follows:

1. Deserialize and validate each input stamp, including its `ActionSetCommit` against
   the input's visible actions.
2. Align anchors: each input stamp is lifted to a common later anchor using `StampLift`
   over an `AnchorChain` segment whose `start` equals the stamp's current anchor. The
   merged stamp's anchor is the segment `end`.
3. Merge the stamps with `MergeStamp`, which constrains `left.anchor == right.anchor`,
   binds the witnessed input action-digest and tachygram polynomials to the input
   header commitments, and proves the merged polynomials are the products of the input
   polynomials (multiset union by polynomial product).
4. Serialize and compress the merged stamp. The merged stamp carries the merged
   commitment $\mathsf{ActionSetCommit} = \mathsf{Commit}(P_{\mathsf{left}} \cdot P_{\mathsf{right}})$.

The aggregator constructs a new stamped transaction carrying the merged stamp. For a
**based** aggregate the transaction also carries the aggregator's own tachyactions; for
an **innocent** aggregate it carries no Tachyon actions.

### Step 4: Aggregate publication

Aggregators publish the aggregate transaction to the mempool. Aggregators MUST NOT
re-publish the covered autonomes; the autonome remains in the mempool independently and
the aggregate is published alongside it. The aggregate is a new `wtxid` distinct from
each covered autonome's `wtxid`, because its `auth_digest` commits to a different
stamp trailer (the merged stamp) even though the covered effecting data is recoverable
from the aggregate's action-digest and tachygram sets.

### Step 5: Miner mempool observation and P2P relay

Miners see both autonomes and aggregates in the mempool. A miner MAY also vertically
integrate aggregation and produce its own aggregates privately without publishing them
to the mempool (Step 7).

P2P relay for Tachyon bundles follows [ZIP 239](https://zips.z.cash/zip-0239):
transactions are announced and fetched by `wtxid` using the `MSG_WTX` inv type. An
autonome, an aggregate, and an adjunct carrying the same effecting data are three
distinct `wtxid`s and MUST be treated as distinct inventory objects.

`MSG_WTX`-style relay is mandatory for Tachyon bundles. Announcing by `txid` alone
would let a third party broadcast a covered autonome with the same `txid` as an
aggregate and interfere with relay of the aggregate form — exactly the failure mode
ZIP 239 was written to prevent for v5 witness malleability, extended here to Tachyon's
authorization-form malleability (stamping, merging, and stripping all change `wtxid`
while leaving `txid` unchanged).

Because `txid` is stable across the aggregation lifecycle (it commits only to
`action_acc || value_balance`), a wallet's submitted transaction remains identifiable
in the mempool even after an aggregator republishes a covering aggregate. Relay policy
MAY de-duplicate on `txid` to avoid redundant propagation of covered autonomes once a
covering aggregate is present.

Adjuncts are block-local. A standalone adjunct whose `tachyonAggregateId` is not present
in the mempool or block MUST NOT be relayed as an independent transaction; adjuncts only
appear inside blocks alongside their covering aggregate. Stripping is a miner-side
block-assembly action (Step 8), not a relay-time transformation: the P2P network
carries stamped bundles (autonomes and aggregates) only.

### Step 6: Covered-transaction identification by `ActionSetCommit`

Miners (and validating observers) identify the aggregate/autonome relationship using the
`ActionSetCommit` field serialized on each stamp. Coverage is determined over the
**action-digest set** — exactly one digest $d_i$ per action — not over tachygrams, whose
count need not equal the action count (a spend publishes two tachygrams).

The aggregate's stamp publishes
$\mathsf{ActionSetCommit} = \mathsf{Commit}(P_{\mathsf{aggregate}})$, where
$P_{\mathsf{aggregate}} = \prod_i (X - d_i)$ ranges over the action digests of every
action covered by the aggregate (both the based aggregate's own actions and all covered
autonomes' actions). Each
$d_i = \text{Poseidon}_\texttt{Tachyon-ActionDg}(\mathsf{cv}_i \,\|\, \mathsf{rk}_i)$ is
computable from public action data.

An observer who has seen a candidate set of autonomes confirms coverage as follows:

1. For a based aggregate, compute $P_{\mathsf{own}} = \prod_j (X - d_j)$ from the
   aggregate's own visible actions. For an innocent aggregate, $P_{\mathsf{own}}$ is the
   empty product $1$.
2. For each candidate autonome $k$, compute
   $P_{\mathsf{autonome},k} = \prod_l (X - d_l)$ from its visible actions.
3. Compute
   $P_{\mathsf{observed}} = P_{\mathsf{own}} \cdot \prod_k P_{\mathsf{autonome},k}$.
4. Compute $\mathsf{Commit}(P_{\mathsf{observed}})$ and compare to the aggregate's
   published `ActionSetCommit`.

Match confirms the observer holds the complete covered set. Mismatch is fail-fast: the
observer is missing a covered autonome, has an extra one, or is matching against the
wrong aggregate. The check is $O(n)$ polynomial arithmetic plus one Pedersen commitment;
it does not require Ragu proof verification.

This resolves the based-aggregate attribution problem without a comprehensive mempool
index or a tachygram-origin query protocol: each action contributes exactly one root to
the product, so the published commitment fixes the covered action multiset directly.

### Step 7: Private miner aggregation (optional)

Miners MAY perform their own aggregation privately during block assembly, without
publishing the aggregate to the mempool. The resulting aggregate is included directly
in the miner's proposed block. The same `MergeStamp` and anchor-alignment rules apply;
the only difference is that the aggregate is never gossiped.

### Step 8: Block composition and adjunct assignment

Miners compose the block at will. For each covered transaction the miner includes, the
miner strips the stamp and assigns the covering aggregate's `wtxid` as the adjunct's
`byte[64]` `tachyonAggregateId`. The covering aggregate MUST be included top-level in the
same block, never stripped and never further aggregated in that block, so the `wtxid`
referenced by adjuncts is stable and resolvable by validators in a single pass.

A stripped innocent (an aggregate with no Tachyon actions) MAY carry an all-zero
`tachyonAggregateId` if no absorbing aggregate was recorded; this is the only case where
a zero `tachyonAggregateId` is valid. Nodes MUST reject a stripped bundle having
non-empty actions and an all-zero `tachyonAggregateId`.

Transaction-identifier semantics under stripping:

- `txid` commits only to effecting data (`action_acc || value_balance`) and is stable
  across stamping, merging, stripping, and re-stamping. A transaction's logical
  identity is invariant across the aggregation lifecycle.
- `auth_digest` commits to action signatures, the binding signature, and the bundle's
  stamp trailer. A stamped bundle's trailer is the full stamp (anchor,
  `ActionSetCommit`, tachygrams, proof); a stripped bundle's trailer is the `byte[64]`
  covering `wtxid` (referred to as `stampWtxid` in the digest contribution). Each
  physical authorization form yields a distinct `auth_digest` and therefore a distinct
  `wtxid = txid || auth_digest`.
- The covering-aggregate reference carried by an adjunct is a `wtxid`, not a `txid`,
  because the `wtxid` pins a specific physical aggregate (authorization + stamp state).
  A `txid` would be ambiguous across the autonome/aggregate forms.
- The wire byte `tachyonBundleState` (`uint8`) distinguishes forms: `0x00` no Tachyon
  bundle, `0x01` stamped, `0x02` stripped. Innocents and adjuncts share the stripped
  layout; both end in a `byte[64]` `tachyonAggregateId`.

The `"ZTxAuthTachyHash"` personalization used in the Tachyon `auth_digest` contribution
is a placeholder pending a Tachyon amendment to ZIP 244; the normative digest
algorithm is specified there, not in this ZIP.

### Step 9: Block proposal

The miner proposes the block containing:

- one or more top-level unstripped aggregates;
- for each transaction covered by an aggregate, an adjunct carrying the action data,
  action signatures, binding signature, `value_balance`, and the covering `wtxid`;
- any non-Tachyon transactions; and
- the coinbase transaction, which MAY itself be a based aggregate.

### Step 10: Block validation

Nodes MUST reject a block containing Tachyon bundles unless, for every covering aggregate
in the block, all of the following hold:

1. **Adjunct resolution.** Every adjunct whose `tachyonAggregateId` refers to that
   aggregate is present in the same block, and the aggregate is top-level, unstripped,
   and not further aggregated in that block.
2. **Action-set reconstruction.** The multiset union of the action-digest sets of all
   adjuncts covered by the aggregate, combined with the based aggregate's own
   action-digest set (empty for an innocent aggregate), matches the aggregate stamp's
   `ActionSetCommit`. Consensus reconstructs $\mathsf{action\_acc}$ from these visible
   actions; the serialized `ActionSetCommit` on the stamp is advisory for this check, and
   any mismatch between the serialized commitment and the reconstructed one is itself a
   consensus error.
3. **Tachygram-set binding.** The aggregate stamp publishes the merged tachygram set
   (`vTachygrams`); adjuncts carry no tachygrams of their own. The Ragu PCD proof binds
   the tachygram-set commitment to the action-set commitment reconstructed in item 2, so
   consensus takes the tachygram set from the aggregate's stamp rather than
   reconstructing it from the adjuncts.
4. **Stamp proof verification.** The header
   $(\mathsf{action\_acc}, \mathsf{tachygram\_acc}, \mathsf{anchor})$ — with
   $\mathsf{action\_acc}$ reconstructed in item 2, $\mathsf{tachygram\_acc}$ committed
   from the stamp's published tachygrams, and $\mathsf{anchor}$ taken from the stamp —
   verifies against the Ragu PCD proof.
5. **Signatures and value balance.** Action signatures and the binding signature verify
   against the transaction sighash, and the bundle's value commitments are consistent
   with the declared `value_balance`.
6. **Anchor membership.** The aggregate's anchor is a member of the published per-block
   anchor sequence, as specified by the accumulator/anchor ZIP (#105).
7. **Tachygram uniqueness.** No tachygram published in this block — in any stamp the
   block contains — duplicates a tachygram published in the current epoch or the
   immediately preceding epoch, as specified by the tachygram-uniqueness consensus rule
   ([Tachygrams](../tachygrams.md)).

The above checks split into two layers:

- **Circuit-enforced (Ragu PCD):** spend/output validity, stamp header binding, anchor
  equality after lifting, and the multiset-product merge relations. The proof attests
  that the header was produced by a valid execution; the proof will only verify with
  the correct header.
- **Consensus-enforced:** canonical anchor membership and end-of-block anchor
  progression; two-epoch tachygram non-reuse; action and binding signatures; value-
  balance rules; and adjunct-to-aggregate resolution.

Several security properties (notably spendable-lineage epoch pinning and double-spend
prevention) are intentionally not fully proven inside the stamp and depend on the
consensus checks above. This split is by design.

## Reference implementation

A reference implementation of the Tachyon aggregator protocol, including the bundle
state machine, stamp merging, stripping, and `ActionSetCommit`-based coverage
identification, is in the `zcash_tachyon` crate under
[`crates/tachyon/src/`](../../crates/tachyon/src/). The implementation currently uses
`mock_ragu`, a permissive stand-in for real Ragu; the protocol semantics specified
above describe the intended real-Ragu behaviour.

## Rationale

**Lifecycle-structured specification.** Organising the Specification around the 10-step
lifecycle — rather than as parallel sections for P2P, identifiers, block layout, and
consensus rules — mirrors how participants actually move through the protocol and keeps
each rule anchored to the step where it applies. This avoids the reader having to
cross-reference unrelated sections to understand a single participant's obligations.

**`ActionSetCommit` solves based-aggregate attribution.** Tachygram-set overlap alone
is insufficient for coverage identification when a based aggregate's own tachygrams are
indistinguishable from covered autonomes' tachygrams. The `ActionSetCommit` field, a PCD
header field bound by the proof, provides a cheap fail-fast check that does not require
proof verification, a comprehensive mempool index, or a separate tachygram-origin query
protocol. A based aggregate could alternatively declare
which tachygrams are its own, but this would not help: the based portion's count is
already inferable from the visible actions, and the remaining attribution problem is
unchanged. It would also leak structure about the aggregator's own vs covered activity
that the actions alone do not reveal.

**No separate coverage manifest.** A coverage manifest (an explicit list of covered
`wtxid`s signed by the aggregator) was considered and rejected. It would add a new
authenticated data structure, require a new signature path, and still need to be
checked against the stamp's action-digest set for soundness. The `ActionSetCommit`
check reuses an existing PCD header field and an existing reconstruction path.

**`wtxid`, not `txid`, for adjunct references.** A `txid` would be ambiguous across
the autonome/aggregate forms (they share effecting data). The `wtxid` pins a specific
physical aggregate including its stamp state, which is what the adjunct needs to
reference. This is why the `tachyonAggregateId` holds a `wtxid` rather than a `txid`.

**Stripping is miner-side, not relay-time.** Stripping at relay time would force every
relay node to understand aggregate coverage and would mix block-assembly policy with
gossip. Keeping the P2P network carrying stamped bundles only, and restricting
adjuncts to blocks, simplifies relay and matches the implementation (a stripped bundle
is not serializable until its covering `wtxid` is assigned, which happens at block
assembly).

**`MSG_WTX` relay is mandatory.** Tachyon's authorization-form malleability is the
direct analogue of v5 witness malleability that motivated ZIP 239. Announcing by
`txid` would let a third party broadcast a covered autonome with the same `txid` as
an aggregate and interfere with relay of the aggregate form. Requiring `MSG_WTX` for
Tachyon bundles closes this exactly as ZIP 239 closed it for v5.

## Security and Privacy Implications

**No new trust assumption.** The aggregator is not trusted. Every invariant is
enforced either inside the Ragu PCD (circuit logic) or by consensus checks on public
data (consensus logic). A malicious aggregator can publish an invalid aggregate, but
validators will reject it at Step 10. A malicious miner can mis-assign adjuncts or
omit covered transactions, but the block will fail validation.

**Data availability.** Aggregation removes redundant proof bytes only. Every adjunct
retains its action data, action signatures, binding signature, and `value_balance`;
validators reconstruct the aggregate header from this public data. An aggregate proof
alone is insufficient: the covered effecting data is present in the block as adjuncts,
and Step 10 rejects any block where it is not.

**No new leakage from `ActionSetCommit`.** The commitment is reconstructable from visible
actions for any self-contained bundle, so its serialized value reveals nothing the
actions do not. For a based aggregate, the factored
polynomial (which roots are the aggregator's own vs covered) is not recoverable from the
commitment alone, so publishing it does not reveal which actions are the aggregator's
own. The coverage check is also sound against the rank-from-above caveat of
commit-equality: each $\prod_i (X - d_i)$ is monic of degree equal to the action count,
so its top coefficient is fixed at $1$ and the commitment pins the exact action multiset
(no shorter polynomial can share the commitment). Identity `cv`/`rk` is separately
rejected by `ActionDigest::new`, which is a well-formedness guard ensuring every action
has a computable digest, not part of the rank argument.

**Privacy of aggregation relationships.** An observer who sees an aggregate in the
mempool can identify covered autonomes by the `ActionSetCommit` check (Step 6). This
is inherent to the scheme: the aggregate must carry enough information for validators
to reconstruct its header. The tachygram-set and action-digest-set commitments do not
reveal the private contents of any covered note.

**Circuit/consensus boundary.** Several security properties — notably spendable-
lineage epoch pinning and double-spend prevention — depend on consensus checks
(items 6 and 7 of Step 10) rather than being fully proven inside the stamp. This is
by design and is documented explicitly so that implementers and auditors do not assume
the proof alone establishes these properties.

## References

- [ZIP 0: ZIP Process](https://zips.z.cash/zip-0000)
- [ZIP 200: Network Upgrade Mechanism](https://zips.z.cash/zip-0200)
- [ZIP 221: FlyClient - Consensus Layer Changes](https://zips.z.cash/zip-0221)
- [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)
- [ZIP 239: Relay of Version 5 Transactions](https://zips.z.cash/zip-0239)
- [ZIP 244: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-0244)
- [ZIP 248: Extensible Transaction Format](https://zips.z.cash/zip-0248)
- [ZIP 252: Deployment of the NU5 Network Upgrade](https://zips.z.cash/zip-0252)
- [ZIP 317: Proportional Transfer Fee Mechanism](https://zips.z.cash/zip-0317)
- [BIP 339: WTXID-based transaction relay](https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki)
- [Tachyon book: Aggregation](../aggregation.md)
- [Tachyon book: Bundles](../bundle.md)
- [Tachyon book: Proof Tree](../proof-tree.md)
- [Tachyon book: Tachygrams](../tachygrams.md)
- [Tachyon book: Anchor](../anchor.md)
- [Tachyon book: Authorization](../authorization.md)
- [Tachyon book: Transaction Identifiers](../transaction-identifiers.md)
- [Tachyon book: Network Roles](../network_roles/overview.md)
