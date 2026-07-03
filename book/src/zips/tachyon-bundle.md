# Tachyon Bundle / Aggregate Transaction Format

**Tracking:** [#104](https://github.com/tachyon-zcash/tachyon/issues/104)

**('Additive / Update' ZIP, Category 'Consensus')**

## I. Dependencies

- [Tachyon Shielded Protocol (#103)](https://github.com/tachyon-zcash/tachyon/issues/103)
  defines the Tachyon pool, action semantics, tachygrams, keys, the statement the
  stamp proof attests to, and the epoch-level tachygram rules.
- [Tachyon Accumulator / Hash Chain (#105)](https://github.com/tachyon-zcash/tachyon/issues/105)
  defines the anchor (Poseidon hash-chain state) that `anchorTachyon` references, and the
  consensus anchor-membership rule.
- [Tachyon Aggregator Protocol (#106)](https://github.com/tachyon-zcash/tachyon/issues/106)
  defines the aggregation lifecycle, mempool and relay policy, and block validation. It
  cites this ZIP for the wire encodings; this ZIP cites it for lifecycle and block rules.
- [ZIP 225](https://zips.z.cash/zip-0225) is the v5 transaction-format precedent this
  format follows; the withdrawn [ZIP 230](https://zips.z.cash/zip-0230) is the v6
  precedent.
- [ZIP 239](https://zips.z.cash/zip-0239) defines `wtxid = txid || auth_digest`, the
  identifier format carried by `tachyonAggregateId`.
- [ZIP 244](https://zips.z.cash/zip-0244) defines the `txid_digest` and `auth_digest`
  trees. A Tachyon amendment to ZIP 244 (tracked separately) specifies the normative
  placement of this bundle's digest contributions; this ZIP specifies only their inputs,
  as ZIP 225 defers its digest algorithms to ZIP 244.

## II. Design Considerations

This ZIP is the Tachyon analogue of [ZIP 225](https://zips.z.cash/zip-0225): the wire
format of the bundle that goes on-chain.[^bundle] Its organizing principle is the
effecting/authorizing split, carried down to the wire layout: the bundle body holds the
bundle's contribution to the transaction's logical identity (actions and value balance)
together with the signatures over it, and a state-dependent trailer holds the part that
aggregation replaces (the stamp, or the reference to a covering aggregate).[^txid]

This draft adds the bundle to the existing transaction format as a new section, in the
manner of ZIP 225's shielded fields. It does not build on the extensible
transaction-format proposal
([ZIP-248](https://github.com/zcash/zips/pull/1156)); see the open questions.

[^bundle]: See [Bundle](../bundle.md) for the bundle lifecycle and state machine.

[^txid]: See [Transaction Identifiers](../transaction-identifiers.md) for how the split
    keeps `txid` stable while `auth_digest` tracks the authorization form.

Open questions:

- **ZIP-248 migration.** If the extensible transaction format
  ([ZIP-248](https://github.com/zcash/zips/pull/1156)) lands, the bundle re-registers as
  a `(bundleType, bundleVariant)` TLV entry (see [the ZIP-248 entry](zip-248.md) and the
  registration draft in
  [tachyon-zcash/zips#4](https://github.com/tachyon-zcash/zips/pull/4)). Under TLV
  framing, absence of the entry encodes "no bundle", making the `0x00` state byte
  redundant there.
- **Transaction-digest amendment.** The `"ZTxIdTachyonHash"` and `"ZTxAuthTachyHash"`
  personalizations and the placement of the Tachyon branches in the ZIP 244 digest trees
  await an amendment to ZIP 244, which may be a separate update ZIP or may fold into one
  of the general Tachyon ZIPs.
- **Proof-size constant.** `proofTachyon` is a fixed-size field whose length is a
  constant of the Ragu proof system. The constant is not yet numerically frozen, so this
  draft names it symbolically as `PROOF_SIZE`.
- **Zero-action bundles.** Stamped bundles with no actions (innocent aggregates) and
  stripped bundles with no actions (stripped innocents) are wire-valid. With no
  actions, producing a valid binding signature for a nonzero `valueBalanceTachyon` is
  computationally infeasible, but no rule requires the zero balance directly.
- **Duplicate-tachygram rule ownership.** This draft owns the per-transaction rule that
  a stamped bundle's tachygrams are distinct, with the
  [Aggregator Protocol ZIP (#106)](https://github.com/tachyon-zcash/tachyon/issues/106)
  citing it (matching that draft's open question on rule ownership). The rule is stated
  here but not yet enforced in the reference implementation's parse or verify paths.
- **Block-validation ownership.** This draft cites proof verification and block-level
  validity to the
  [Aggregator Protocol ZIP (#106)](https://github.com/tachyon-zcash/tachyon/issues/106),
  their current home. That draft's own open questions contemplate relocating its
  consensus rules (possibly here) or splitting into network and consensus ZIPs; the
  citations follow wherever those rules land.
- **Value-balance range.** No `MAX_MONEY` bound on `valueBalanceTachyon` is specified or
  implemented. ZIP 225 bounds `valueBalanceOrchard`; an analogous rule needs an owner,
  here or at the transaction layer.
- **Count caps.** Only the compactSize maximum `0x02000000` bounds `nActionsTachyon` and
  `nTachygrams`. Whether a tighter per-field cap is wanted is undecided.

## III. ZIP Draft

--------------------------------------------------------------------------------

```
ZIP: <to be assigned by ZIP Editors>
Title: Tachyon Bundle / Aggregate Transaction Format
Owners: <Tachyon team>
Status: Draft
Category: Consensus
Created: 2026-07-02
License: MIT
Discussions-To: <https://github.com/tachyon-zcash/tachyon/issues/104>
```

## Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", and "RECOMMENDED" in
this document are to be interpreted as described in BCP 14 when, and only when, they
appear in all capitals.

The term "network upgrade" is to be interpreted as described in
[ZIP 200](https://zips.z.cash/zip-0200). The terms "Testnet" and "Mainnet" are to be
interpreted as described in section 3.12 of the Zcash Protocol Specification. The
character § is used when referring to sections of the Zcash Protocol Specification.

`txid`, `auth_digest`, and the SIGHASH transaction hash are defined by
[ZIP 244](https://zips.z.cash/zip-0244); `wtxid = txid || auth_digest`, the 64-byte
identifier used for transaction announcement and relay, by
[ZIP 239](https://zips.z.cash/zip-0239). Value commitments, spend authorization
signatures, and binding signatures are existing constructions (§5.4.8.3, §4.15, and
§4.14 respectively, in their Orchard instantiations); this ZIP applies them to
Tachyon as specified below rather than redefining them.

The following terms are defined by other Tachyon ZIPs and summarized here
non-normatively:

- **Tachygram.** The `byte[32]` encoding of a field element ($\mathbb{F}_p$)
  representing either a note nullifier or a note commitment. Consensus treats
  nullifiers and commitments identically.
  ([Tachyon Shielded Protocol](tachyon-shielded-protocol.md))
- **Anchor.** A Poseidon hash-chain state referencing the Tachyon pool at a
  specific block.
  ([Tachyon Accumulator / Hash Chain](tachyon-accumulator.md))
- **Autonome / aggregate / adjunct.** A stand-alone stamped transaction; a stamped
  transaction whose merged stamp covers other transactions; a transaction whose stamp
  has been stripped in favor of a reference to a covering aggregate.
  ([Tachyon Aggregator Protocol](tachyon-aggregator.md))

The remaining terms are defined by this ZIP:

- **Bundle.** The Tachyon section of a transaction: actions, a value balance, action
  signatures, a binding signature, and a state-dependent trailer.
- **Bundle state.** The three-valued wire discriminator `tachyonBundleState`
  selecting no bundle, a stamped bundle, or a stripped bundle.
- **Action.** The triple $(\mathsf{cv}, \mathsf{rk}, \mathsf{sig})$: a value
  commitment, a randomized verification key, and a signature over the transaction
  sighash. An action effects a spend or an output; both forms share this encoding,
  and consensus applies the same rules to each.
- **Action digest.** The Poseidon digest of an action's $(\mathsf{cv}, \mathsf{rk})$
  pair.
- **Action-set commitment.** The deterministic polynomial commitment to a multiset of
  action digests.
- **Stamp.** The trailer of a stamped bundle: an action-set commitment over the
  covered actions, an anchor, a tachygram list, and a Ragu proof. The proof attests
  that every covered action satisfies the Tachyon action rules.
- **Stripped bundle.** A bundle whose stamp is replaced by `tachyonAggregateId`, the
  `wtxid` of a covering aggregate.

## Abstract

This ZIP specifies the consensus wire format of the Tachyon bundle: a three-state
discriminator byte, a bundle body carrying actions, a value balance, and signatures,
and a trailer carrying either a stamp (the proof and the public data needed to verify
it) or a reference to a covering aggregate. It defines the canonical field
encodings, the action digest and set commitments cited by the other Tachyon ZIPs,
the bundle's transaction-digest inputs, and the consensus rules scoped to a single
bundle. It plays the role for the Tachyon pool that
[ZIP 225](https://zips.z.cash/zip-0225) plays for the v5 transaction.

## Motivation

Tachyon proofs aggregate: the stamps of many transactions merge into one covering
stamp, and covered transactions appear in a block without their own (see the
[Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP). The transaction format must
therefore allow a stamp to be removed without changing the transaction's identity and
without invalidating any signature. This forces the effecting/authorizing split down
into the wire layout: the bundle's contribution to the signed data is confined to the
body and is identical across bundle states, while the strippable part is isolated in
the trailer.

A single format serves all three transaction roles. An autonome and an aggregate are
the same stamped form; an adjunct is the same body under a stripped trailer. Every
consensus check on a stripped bundle operates on data the stripped form still
carries.

## Requirements

- A transaction's `txid` contribution is invariant across stamping, merging,
  stripping, and re-stamping.
- Stamped and stripped forms carry identical effecting data; only the trailer
  differs.
- Every field a validator needs for signature and balance verification is present in
  both states.
- Encodings are canonical: each parsed bundle has exactly one serialization.
- The proof field has a fixed size, so parsing requires no untrusted length.
- Bundles with no actions are representable (innocent aggregates and their stripped
  forms).

## Non-requirements

This ZIP does not specify:

- proof verification or block-level validity, which are specified by the
  [Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP;
- anchor semantics or the anchor-membership rule, which are specified by the
  [Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) ZIP;
- the proof statement or the epoch-level tachygram rules, which are specified by the
  [Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP;
- the transaction digest trees or the sighash algorithm, which are specified by
  [ZIP 244](https://zips.z.cash/zip-0244) as amended for Tachyon;
- the position of the bundle section within the transaction encoding, which is
  specified by the transaction format of the activating network upgrade.

## Specification

The specification proceeds from the wire layout of the bundle body to the rules over
its fields, the digest and commitment constructions those rules use, the two
trailers, the canonical encodings of every field, the bundle's transaction-digest
inputs, and a consolidated summary of the bundle-scoped consensus rules.

### Placement and bundle states

The Tachyon bundle is a contiguous section of the transaction encoding, added by a
Tachyon network upgrade. The first byte of the section, `tachyonBundleState`,
selects the bundle state:

| value         | state       | bundle contents                       |
| ------------- | ----------- | ------------------------------------- |
| `0b0000_0000` | non-tachyon | no bundle                             |
| `0b0000_0001` | stamped     | bundle with anchor, tachygrams, proof |
| `0b0000_0010` | stripped    | bundle with aggregate's wtxid         |
| `...`         | *reserved*  | *n/a*                                 |

A parser MUST reject any other value of `tachyonBundleState`.

When `tachyonBundleState` is `0x00`, the section contains no further fields:

| Bytes | Name                 | Data Type | Description |
| ----- | -------------------- | --------- | ----------- |
| 1     | `tachyonBundleState` | `uint8`   | `0x00`      |

The bundle lifecycle also passes through states with no wire representation: a bundle
awaiting its proof, and a stripped bundle whose covering aggregate is not yet
assigned. Only the stamped and stripped states serialize; the lifecycle itself is
specified by the [Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP.

### Bundle body

When `tachyonBundleState` is not `0x00`, the body follows immediately:

| Bytes                | Name                  | Data Type                        | Description                             |
| -------------------- | --------------------- | -------------------------------- | --------------------------------------- |
| 1                    | `tachyonBundleState`  | `uint8`                          | `0x01` (stamped) or `0x02` (stripped)   |
| 8                    | `valueBalanceTachyon` | `int64`                          | The net value of Tachyon spends minus outputs |
| varies               | `nActionsTachyon`     | `compactSize`                    | The number of Tachyon actions           |
| 64 * nActionsTachyon | `vActionsTachyon`     | `TachyonAction[nActionsTachyon]` | A sequence of action descriptors, each (`cv`: 32 bytes, `rk`: 32 bytes) |
| 64 * nActionsTachyon | `vActionSigsTachyon`  | `byte[64][nActionsTachyon]`      | An authorizing signature for each action |
| 64                   | `bindingSigTachyon`   | `byte[64]`                       | A binding signature for the bundle      |

`valueBalanceTachyon` is a two's-complement signed 64-bit integer in little-endian
byte order. `vActionsTachyon` is a sequence of `nActionsTachyon` action descriptors,
each the 32-byte encoding of $\mathsf{cv}$ followed by the 32-byte encoding of
$\mathsf{rk}$. `vActionSigsTachyon` is a sequence of `nActionsTachyon` 64-byte
signatures; the $i$-th signature authorizes the $i$-th descriptor. Both sequences
share the single count `nActionsTachyon`, so a count mismatch between descriptors and
signatures is unrepresentable. The semantics of the actions themselves (what a spend
or an output effects in the pool) are specified by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP.

### Value balance and the binding signature

`valueBalanceTachyon` asserts the net value of the bundle's actions, spends minus
outputs. A positive balance releases value from the Tachyon pool to the rest of the
transaction; a negative balance absorbs value into it. The balance is not required
to be zero: a transaction MAY balance across pools, and a coinbase transaction MAY
absorb newly created value. Value accounting across a whole transaction is a
transaction-layer rule, not specified here.

Value commitments and balance enforcement are Orchard's constructions, unchanged.
Each action's $\mathsf{cv}$ is a homomorphic Pedersen commitment (§5.4.8.3) to the
action's value, $+v$ for a spend and $-v$ for an output, using Orchard's
value-commitment generators (the `z.cash:Orchard-cv` hash-to-curve domain). The
binding validating key $\mathsf{bvk}$ is derived from the actions' $\mathsf{cv}$
values and `valueBalanceTachyon` exactly as in §4.14, and is not encoded in the
transaction. `bindingSigTachyon` MUST be a valid binding signature over the
transaction sighash under the derived $\mathsf{bvk}$; a valid signature enforces
consistency between the asserted balance and the hidden action values.

### Action signatures

Each action signature in `vActionSigsTachyon` MUST be a valid spend authorization
signature (§4.15; RedPallas with the SpendAuth basepoint of §5.4.7.1, for spends and
outputs alike) over the transaction sighash under the corresponding action's
$\mathsf{rk}$. The sighash is a transaction-level digest, computed as specified by
[ZIP 244](https://zips.z.cash/zip-0244) as amended for Tachyon; all of a bundle's
signatures sign the same sighash.

### Action digests

Each action has an action digest, a Poseidon hash of its
$(\mathsf{cv}, \mathsf{rk})$ pair. Let $(\mathsf{cv}_x, \mathsf{cv}_y)$ and
$(\mathsf{rk}_x, \mathsf{rk}_y)$ be the affine Pallas coordinates of the action's
decompressed $\mathsf{cv}$ and $\mathsf{rk}$. Then

$$ d = \mathrm{Poseidon}\bigl(\mathsf{dom},\ \mathsf{cv}_x,\ \mathsf{cv}_y,\
\mathsf{rk}_x,\ \mathsf{rk}_y\bigr) $$

where $\mathsf{dom}$ is the Pallas base field element whose integer value is the
little-endian interpretation of the 16-byte ASCII string `Tachyon-ActionDg`.

If an action's $\mathsf{cv}$ or $\mathsf{rk}$ is the identity point, it has no
affine coordinates, the digest is undefined, and the transaction is invalid.

### Set commitments

Multisets of field elements are committed as polynomials with the members as roots.
For action digests $d_i$ and tachygrams $t_j$:

$$ A(X) = \prod_i \bigl(X - d_i\bigr) \qquad T(X) = \prod_j \bigl(X - t_j\bigr) $$

The commitment to a set polynomial is the deterministic, untrapdoored Pedersen
commitment to its coefficient vector over the Vesta group, using the
polynomial-commitment generators fixed by the Ragu proof system. A polynomial is
invariant under permutation of its roots, so the commitment depends only on the
multiset, not on any ordering.

The action-set commitment over a set of actions is the commitment of $A$ formed from
their digests; the tachygram-set commitment of $T$ is formed likewise. Both are
deterministic functions of the public actions and tachygrams they commit to, and
carry no information beyond them.

### Stamp trailer

When `tachyonBundleState` is `0x01`, the stamp trailer follows the body:

| Bytes            | Name              | Data Type               | Description                                    |
| ---------------- | ----------------- | ----------------------- | ---------------------------------------------- |
| 32               | `cActionsTachyon` | `byte[32]`              | Action-set commitment over the covered actions |
| 32               | `anchorTachyon`   | `byte[32]`              | Anchor referencing the pool state              |
| varies           | `nTachygrams`     | `compactSize`           | The number of tachygrams                       |
| 32 * nTachygrams | `vTachygrams`     | `byte[32][nTachygrams]` | The stamp's tachygrams                         |
| PROOF_SIZE       | `proofTachyon`    | `byte[PROOF_SIZE]`      | Ragu proof                                     |

`cActionsTachyon` is the action-set commitment
([Set commitments](#set-commitments)) over every action the stamp covers: the
bundle's own actions together with the actions of every covered transaction. How a
block's actions are checked against it is specified by the
[Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP.

`anchorTachyon` references the pool state the proof is valid against; its semantics
and the anchor-membership rule are specified by the
[Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) ZIP.

`vTachygrams` publishes the stamp's tachygram multiset for data availability. Which
tachygrams an action contributes is specified by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP; this ZIP imposes no
relation between `nTachygrams` and `nActionsTachyon`, and an aggregate's stamp
carries tachygrams for actions that are not its own. The tachygrams within one
stamped bundle MUST be distinct; a transaction violating this rule is invalid.
Block-level and epoch-level distinctness rules are specified by the
[Tachyon Aggregator Protocol](tachyon-aggregator.md) and
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIPs respectively.

`proofTachyon` is the Ragu proof. The statement it attests to is specified by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP; when and how it is
verified is specified by the [Tachyon Aggregator Protocol](tachyon-aggregator.md)
ZIP.

### Stripped trailer

When `tachyonBundleState` is `0x02`, the stripped trailer follows the body:

| Bytes | Name                 | Data Type  | Description                     |
| ----- | -------------------- | ---------- | ------------------------------- |
| 64    | `tachyonAggregateId` | `byte[64]` | wtxid of a covering aggregate |

`tachyonAggregateId` is the `wtxid` ([ZIP 239](https://zips.z.cash/zip-0239)) of a
covering aggregate. It MUST NOT be all zero; the rule applies to every stripped
bundle, with or without actions. Which transaction it must identify within a block
is specified by the [Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP.

### Canonical encodings

- Every compactSize field MUST use the minimal encoding for its value (§7.1) and
  MUST NOT encode a value exceeding `0x02000000`. A parser MUST reject any other
  encoding.
- `cv` and `rk` are 32-byte compressed encodings of Pallas points. A parser MUST
  reject an encoding that does not decode to a point. `rk` MUST decode as a
  RedPallas validating key (§5.4.7). The identity point decodes successfully; it is
  excluded by the rule in [Action digests](#action-digests), not by the parser.
- `anchorTachyon` and each tachygram are canonical little-endian encodings of Pallas
  base field elements; a parser MUST reject an encoding whose value is not less than
  the field modulus.
- `cActionsTachyon` is a 32-byte compressed Vesta point (the set-commitment group is
  Vesta, since polynomial coefficients are Pallas base field elements, which are
  Vesta scalars). A parser MUST reject an invalid point encoding.
- Signatures (`vActionSigsTachyon`, `bindingSigTachyon`) are opaque 64-byte strings
  at parse time; their validity is a verification-time property.
- `proofTachyon` is exactly `PROOF_SIZE` bytes and MUST decode as a Ragu proof. The
  proof encoding is defined by the Ragu proof system.

### Transaction digest contributions

The bundle contributes one leaf to each of the transaction's two digest trees
([ZIP 244](https://zips.z.cash/zip-0244)). Both leaves are BLAKE2b-256 hashes with
16-byte personalizations.

The effecting contribution (to `txid` and the sighash) commits to the bundle's own
actions and balance:

$$ \text{BLAKE2b-256}_{\text{"ZTxIdTachyonHash"}}\bigl(
\mathsf{encoding}(\mathsf{action\_acc}) \,\|\, \mathsf{le64}(\mathsf{valueBalanceTachyon})
\bigr) $$

where $\mathsf{action\_acc}$ is the action-set commitment
([Set commitments](#set-commitments)) over the bundle's own actions, digested as its
32-byte point encoding. This is distinct from `cActionsTachyon`, which for an
aggregate covers more actions than its own. The stamp is excluded, so the
contribution is invariant across stamping, merging, stripping, and re-stamping.

The authorizing contribution (to `auth_digest`) commits to the signatures and the
trailer's field encodings:

$$ \text{BLAKE2b-256}_{\text{"ZTxAuthTachyHash"}}\bigl(
\mathsf{vActionSigsTachyon} \,\|\, \mathsf{bindingSigTachyon} \,\|\,
\begin{cases}
\mathsf{cActionsTachyon} \,\|\, \mathsf{anchorTachyon} \,\|\, \mathsf{vTachygrams}
\,\|\, \mathsf{proofTachyon} & \text{if stamped}\\[2pt]
\mathsf{tachyonAggregateId} & \text{if stripped}
\end{cases}
\bigr) $$

Vector counts are not part of either preimage, matching the ZIP 244 auth-digest
leaves.

A transaction with no Tachyon bundle contributes the hash of the empty string under
each personalization. No bundle produces the empty preimage: a stripped bundle's
preimage contains at least its binding signature and trailer, and a bundle with no
actions and zero balance contributes its encoded empty-set commitment and balance.

The normative specification of the transaction digest trees, including these
leaves, belongs to the Tachyon amendment to ZIP 244 (with ZIP 239 defining
`wtxid`); this section records the inputs the bundle supplies. The
`"ZTxIdTachyonHash"` and `"ZTxAuthTachyHash"` personalizations are placeholders
pending that amendment.

### Bundle validity

The rules owned by this ZIP, applying to a single transaction's bundle:

1. `tachyonBundleState` MUST be `0x00`, `0x01`, or `0x02`.
2. Every compactSize MUST be minimally encoded and MUST NOT exceed `0x02000000`.
3. Every point and field-element encoding MUST be canonical, as specified in
   [Canonical encodings](#canonical-encodings).
4. An action's $\mathsf{cv}$ and $\mathsf{rk}$ MUST NOT be the identity point.
5. Every action signature MUST verify over the transaction sighash under its
   action's $\mathsf{rk}$.
6. `bindingSigTachyon` MUST verify over the transaction sighash under the derived
   $\mathsf{bvk}$.
7. A stamped bundle's `proofTachyon` MUST be exactly `PROOF_SIZE` bytes and a valid
   proof encoding, and its tachygrams MUST be distinct.
8. A stripped bundle's `tachyonAggregateId` MUST NOT be all zero.

Rules outside the scope of this ZIP are enumerated in
[Non-requirements](#non-requirements).

## Rationale

**The stamp is excluded from the txid contribution.** The effecting contribution
commits only to actions and balance, so stamping, merging, stripping, and
re-stamping preserve a transaction's logical identity. This is the property the
aggregation lifecycle rests on: an adjunct in a block is the same transaction its
author signed.

**Two vectors, one count.** Descriptors (effecting) are separated from signatures
(authorizing), matching the digest split and ZIP 225's layout, while the shared
`nActionsTachyon` makes a count mismatch unrepresentable rather than checkable.

**compactSize counts, minimally encoded.** Consistency with the existing transaction
encoding (§7.1, ZIP 225 precedent). The minimal-encoding rule gives each bundle
exactly one serialization. The `0x02000000` bound matches the maximum accepted by
existing transaction parsers (Bitcoin's `MAX_SIZE`, retained by Zcash); the protocol
specification does not state it explicitly.

**Plaintext `valueBalanceTachyon`.** The net pool flow is public, as with
`valueBalanceSapling` and `valueBalanceOrchard`, supporting pool turnstile
accounting at the consensus layer.

**Identity points are invalid.** The action digest hashes affine coordinates, which
the identity point lacks. Excluding it also rejects a degenerate verification key
and a degenerate value commitment.

**Order-independent action commitment.** The txid side commits to the action-digest
multiset through the root polynomial, which is invariant under permutation. Sequence
position in `vActionsTachyon` carries no meaning, and stamp merging acts on the
underlying multisets by union, which the root-polynomial representation expresses
as polynomial multiplication, likewise ordering-free.

**Deterministic set commitments.** The committed sets are public data, so a hiding
commitment is unnecessary; determinism is what lets any party recompute and confirm
a commitment from the data it covers.

**Fixed-size proof.** Recursion yields one proof size whether a stamp covers one
action or a block's worth. A constant-size field needs no untrusted length prefix,
and a stamp size independent of coverage underlies aggregation's space savings.

**`wtxid`, not `txid`, in `tachyonAggregateId`.** A `txid` is ambiguous across the
authorization forms that share it; the `wtxid` pins the physical covering aggregate,
stamp included. The [Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP gives
the full rationale.

**Nonzero `tachyonAggregateId`.** Every stripped bundle names a covering
transaction, and the unassigned stripped state has no wire form, so no sentinel
value is needed and the all-zero `wtxid` (which names no transaction) is invalid.

**Flat digest preimages.** The digest contributions hash field encodings directly,
in the style of the ZIP 244 leaves, rather than hashing a length-delimited
serialization. Omitting the counts does not make the authorizing preimage
ambiguous: the signature count equals `nActionsTachyon`, to which the effecting
contribution commits, and every other section of the preimage has a fixed size
except the tachygram list, which occupies the remainder.

## Security and Privacy Implications

**Canonical encodings.** Each accepted serialization decodes to a distinct bundle,
and each bundle has exactly one accepted serialization, so a bundle cannot be
re-encoded into a second accepted serialization. Authorization-form changes
(re-stamping, stripping) produce distinct bundles by design and are reflected in
`auth_digest` and `wtxid` ([ZIP 239](https://zips.z.cash/zip-0239); see the
[Tachyon Aggregator Protocol](tachyon-aggregator.md) ZIP).

**Balance consistency is enforced by the binding property.** A valid binding
signature establishes that `valueBalanceTachyon` equals the net value committed by
the actions' $\mathsf{cv}$, by the same binding argument as Orchard (§4.14). It
establishes nothing about the transaction's overall balance, which is a
transaction-layer rule.

**`bvk` is derived, not carried.** The binding verification key is recomputed from
`vActionsTachyon` and `valueBalanceTachyon`; a prover cannot supply a key
inconsistent with the public data.

**Signatures survive stripping.** All signatures cover the transaction sighash,
which incorporates only effecting data. A miner stripping a stamp changes no signed
data, so aggregation does not invalidate signatures. A signature authorizes only
the sighash it signs; using an action in a transaction with different effecting
data requires a new signature over that transaction's sighash.

**Absent bundles are distinct from empty bundles.** A transaction with no Tachyon
section and a transaction with a zero-action, zero-balance bundle produce distinct
digest preimages, so their identifier contributions differ (see
[Transaction digest contributions](#transaction-digest-contributions)).

**Public data.** $\mathsf{cv}$ is a hiding commitment to the action's value. The
unlinkability properties of $\mathsf{rk}$, and of tachygrams (which do not
distinguish nullifiers from note commitments), are established by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP, not by this format.
The action count, the value balance, and, on a stamped bundle, the tachygram count
are public, as is anything derivable from them.

**Parse validity is not spend validity.** A bundle that parses and whose signatures
verify is not thereby valid to spend; the rules enumerated in
[Non-requirements](#non-requirements) also apply. Implementers and auditors should
not assume the rules in this ZIP alone establish those properties.

## Deployment

This ZIP is deployed with a Tachyon network upgrade. Activation parameters are
specified by the corresponding deployment ZIP
([Network Upgrade Deployment](network-upgrade-deployment.md)).

## Reference implementation

A reference implementation of the bundle wire codec, the action digest and set
commitments, the value balance, the digest contributions, and signature verification
is developed in the `zcash_tachyon` crate of the Tachyon repository:
<https://github.com/tachyon-zcash/tachyon>.

## References

- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [ZIP 200: Network Upgrade Mechanism](https://zips.z.cash/zip-0200)
- [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)
- [ZIP 230: Version 6 Transaction Format (withdrawn)](https://zips.z.cash/zip-0230)
- [ZIP 239: Relay of Version 5 Transactions](https://zips.z.cash/zip-0239)
- [ZIP 244: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-0244)
- [ZIP 248: Extensible Transaction Format (proposal)](https://github.com/zcash/zips/pull/1156)
- [Tachyon Shielded Protocol](tachyon-shielded-protocol.md)
- [Tachyon Accumulator / Hash Chain](tachyon-accumulator.md)
- [Tachyon Aggregator Protocol](tachyon-aggregator.md)
- [Network Upgrade Deployment](network-upgrade-deployment.md)
