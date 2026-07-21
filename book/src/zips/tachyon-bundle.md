# Tachyon Bundle / Aggregate Transaction Format

**Tracking:** [#104](https://github.com/tachyon-zcash/tachyon/issues/104)

**('Additive / Update' ZIP, Category 'Consensus')**

## I. Dependencies

- [Tachyon Shielded Protocol (#103)](https://github.com/tachyon-zcash/tachyon/issues/103)
  defines the Tachyon pool, action semantics, tachygrams, keys, and the statement the
  stamp proof attests to.
- [Tachyon Accumulator / Hash Chain (#105)](https://github.com/tachyon-zcash/tachyon/issues/105)
  defines the anchor (Poseidon hash-chain state) that `anchorTachyon` references, the
  consensus anchor-membership rule, and the epoch window with its duplicate-tachygram
  rule.
- [ZIP 225](https://zips.z.cash/zip-0225) is the v5 transaction-format precedent this
  format follows; the withdrawn [ZIP 230](https://zips.z.cash/zip-0230) is the v6
  precedent.
- [ZIP 239](https://zips.z.cash/zip-0239) defines `wtxid = txid || auth_digest`, the
  identifier format carried by `tachyonAggregateId`.
- [ZIP 244](https://zips.z.cash/zip-0244) defines the `txid_digest` and `auth_digest`
  trees. ZIP 244 as extended for Tachyon
  ([Transaction digest contributions](zip-244.md#transaction-digest-contributions))
  specifies the leaf algorithms and personalizations for this bundle's digest
  contributions; this ZIP specifies only their inputs, as ZIP 225 defers its digest
  algorithms to ZIP 244.

## II. Design Considerations

This ZIP is the Tachyon analogue of [ZIP 225](https://zips.z.cash/zip-0225): the wire
format of the bundle that goes on-chain.[^bundle] Its organizing principle is the
effecting/authorizing split, carried down to the wire layout: the bundle body holds the
bundle's contribution to the transaction's logical identity (actions and value balance)
together with the signatures over it, and a state-dependent stamp holds the part that
aggregation replaces (a proof, or a pointer to a covering aggregate).[^txid]

This draft adds the bundle to the existing transaction format as a new section, in the
manner of ZIP 225's shielded fields. It does not build on the extensible
transaction-format proposal
([ZIP-248](https://github.com/zcash/zips/pull/1156)); see the open questions.

The [Tachyon Aggregator Protocol (#106)](https://github.com/tachyon-zcash/tachyon/issues/106)
builds on this ZIP: it defines the aggregation lifecycle, the mempool and relay policy,
and the autonome, aggregate, and adjunct transaction roles. This ZIP defines the
proof and pointer stamp forms and the adjunct bundle those roles build on; the draft
body below otherwise speaks of the covering transaction without naming the roles.

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
- **Proof-size constant.** A fixed-size `proofTachyon` is the working assumption: its
  length is a constant of the Ragu proof system, not yet numerically frozen, so this
  draft names it symbolically as `PROOF_SIZE`. A variable-size final compression
  (bulletproof-style) would replace the constant-length field with a dynamic one; whether
  the proof system settles on a fixed size is unresolved.
- **Zero-action coverage confirmation.** Block validity confirms an adjunct
  bundle's reference through its actions, so an adjunct bundle with no actions
  names a covering aggregate that consensus does not confirm. Two candidate rules:
  
  1. Validators holding mempool data locate a proof-stamped form matching the adjunct
  bundle's `txid`, identify its tachygram set, and confirm that set folded into
  the referenced aggregate. Multiple proof-stamped candidates may exist. Requires no
  changes to bundle format. Significantly, this check depends on ephemeral
  mempool state.
  2. A field is added to the bundle identifying the bundle's tachygram set at
  creation. The field contributes to `txid` and the sighash. A validator must
  confirm that an adjunct bundle's tachygram set MUST be a complete subset of
  the referenced aggregate's stamp. The body field survives stripping and does
  not depend on mempool state. Significantly, this extends the definition of
  effecting data beyond actions and balance.

- **Tachygram arity.** A spend emits two tachygrams and an output emits one, so a
  stamp's tachygram count bears no fixed relation to the actions it covers. Fixing the
  arity at two per action, and consequently removing `hStampActionsTachyon` in favor of
  total reconstruction, is deferred to
  [#164](https://github.com/tachyon-zcash/tachyon/issues/164).
- **In-band memo data.** An optional in-band path for memo data, committed by a
  `da_digest` contribution to the transaction digests, is deferred to
  [#163](https://github.com/tachyon-zcash/tachyon/issues/163).
- **Count caps.** Only the compactSize maximum `0x02000000` bounds `nActionsTachyon` and
  `nTachygrams`. A tighter per-field cap may be wanted.

The digest leaf algorithms and personalizations live in
[ZIP 244 as extended for Tachyon](zip-244.md#transaction-digest-contributions); see that
page for their normative form.

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
signatures, and binding signatures are existing constructions (§5.4.8.3
‘Homomorphic Pedersen commitments (Sapling and Orchard)’, §4.15 ‘Spend
Authorization Signature (Sapling and Orchard)’, and §4.14 ‘Balance and Binding
Signature (Orchard)’, respectively, in their Orchard instantiations); this ZIP
applies them to Tachyon as specified below rather than redefining them.

The following terms are defined by other Tachyon ZIPs and summarized here
non-normatively:

- **Tachygram.** The `byte[32]` encoding of a field element ($\mathbb{F}_p$)
  representing either a note nullifier or a note commitment. Consensus treats
  nullifiers and commitments identically.
  ([Tachyon Shielded Protocol](tachyon-shielded-protocol.md))
- **Anchor.** A Poseidon hash-chain state referencing the Tachyon
  pool at a specific block. Sub-block states may be valid but should not be
  acknowledged. ([Tachyon Accumulator / Hash Chain](tachyon-accumulator.md#anchor-semantics))

The remaining terms are defined by this ZIP:

- **Bundle.** The Tachyon section of a transaction: actions, a value balance, action
  signatures, a binding signature, and a state-dependent stamp.
- **Covering transaction.** The proof-stamped transaction whose stamp covers a
  pointer-stamped transaction's actions, named by the pointer-stamped bundle's
  `tachyonAggregateId`.
- **Bundle state.** The three-valued wire discriminator `tachyonBundleState`
  selecting no bundle, a proof stamp, or a pointer stamp.
- **Action.** The triple $(\mathsf{cv}, \mathsf{rk}, \mathsf{sig})$: a value
  commitment, a randomized verification key, and a signature over the transaction
  sighash. An action effects a spend or an output; both forms share this encoding,
  and consensus applies the same rules to each.
- **Action digest.** The Poseidon digest of an action's $(\mathsf{cv}, \mathsf{rk})$
  pair.
- **Descriptor digest.** The BLAKE2b-256 digest of a sequence of action
  descriptors ([Action descriptor digests](#action-descriptor-digests)).
- **Action-set commitment.** The deterministic polynomial commitment to a multiset of
  action digests.
- **Stamp.** The final section of a bundle, following the body: either a proof stamp
  or a pointer stamp.
- **Proof stamp.** A stamp carrying a Ragu proof and supporting verification
  data: a digest of the covered actions, an anchor, and the stamp's
  tachygrams. The proof attests that every covered action satisfies the Tachyon
  action rules.
- **Pointer stamp.** A stamp carrying `tachyonAggregateId`, the `wtxid` of a covering
  transaction, in place of a proof.

## Abstract

This ZIP specifies the consensus wire format of the Tachyon bundle: a three-state
discriminator byte, a bundle body carrying actions, a value balance, and signatures,
and a stamp carrying either a proof (with the public data needed to verify it) or a
pointer to a covering transaction. It defines the canonical field
encodings and sequence orders, the action digests, descriptor digests, and set
commitments cited by the other Tachyon ZIPs,
the bundle's transaction-digest inputs, the consensus rules scoped to a single
bundle, and the block-scoped rules that validate a block's bundles together. It plays the role for the Tachyon pool that
[ZIP 225](https://zips.z.cash/zip-0225) plays for the v5 transaction.

## Motivation

Tachyon proofs aggregate: the stamps of many transactions merge into one covering
stamp, and covered transactions appear in a block without their own. The transaction
format must therefore allow a stamp to be removed without changing the transaction's
identity and without invalidating any signature. This forces the effecting/authorizing
split down into the wire layout: the bundle's contribution to the signed data is
confined to the body and is identical across bundle states, while the strippable part
is isolated in the stamp.

A single format serves every transaction role: one proof-stamped form whether
the proof covers only the bundle's own actions or other transactions' as well,
and a covered transaction is the same body under a pointer stamp. Every
consensus check on a pointer-stamped transaction operates on data it still
carries.

## Requirements

- A transaction's `txid` contribution is invariant across stamping, merging,
  stripping, and re-stamping.
- Proof-stamped and pointer-stamped forms carry identical effecting data; only the
  stamp differs.
- Every field a validator needs for signature and balance verification is present in
  both states.
- Encodings are canonical: each parsed bundle has exactly one serialization.
- The proof field has a fixed size, so parsing requires no untrusted length.
- Bundles with no actions are representable, under both stamp forms.

## Non-requirements

This ZIP does not specify:

- the proof statement, which is specified by the
  [Tachyon Shielded Protocol](tachyon-shielded-protocol.md#proof-verification) ZIP;
- anchor semantics or the anchor-membership rule, and the epoch window with its
  duplicate-tachygram rule, which are specified by the
  [Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) ZIP;
- the transaction digest trees, the digest leaf algorithms, or the sighash algorithm,
  which are specified by [ZIP 244](https://zips.z.cash/zip-0244) as extended for Tachyon
  ([Transaction digest contributions](zip-244.md#transaction-digest-contributions));
- the aggregation lifecycle, mempool, and relay policy;
- the position of the bundle section within the transaction encoding, which is
  specified by the transaction format of the activating network upgrade.

## Specification

The specification proceeds from the wire layout of the bundle body to the rules over
its fields, the digest and commitment constructions those rules use, the two
stamp forms, the canonical encodings of every field, the bundle's transaction-digest
inputs, a consolidated summary of the bundle-scoped consensus rules, and the
block-scoped rules that validate a block's bundles together.

### Placement and bundle states

The Tachyon bundle is a contiguous section of the transaction encoding, added by a
Tachyon network upgrade. The first byte of the section, `tachyonBundleState`,
selects the bundle state:

| value         | state         | bundle contents                                       |
| ------------- | ------------- | ----------------------------------------------------- |
| `0b0000_0000` | non-tachyon   | no bundle                                             |
| `0b0000_0001` | proof stamp   | bundle with actions digest, anchor, tachygrams, proof |
| `0b0000_0010` | pointer stamp | bundle with covering transaction's wtxid              |
| `...`         | *reserved*    | *n/a*                                                 |

A parser MUST reject any other value of `tachyonBundleState`.

When `tachyonBundleState` is `0x00`, the section contains no further fields:

| Bytes | Name                 | Data Type | Description |
| ----- | -------------------- | --------- | ----------- |
| 1     | `tachyonBundleState` | `uint8`   | `0x00`      |

The bundle lifecycle also passes through states with no wire representation: a
bundle awaiting its proof, and a pointer-stamped transaction whose covering
transaction is not yet assigned. Only the proof-stamp and pointer-stamp states
serialize; the lifecycle itself is not specified by this ZIP.

### Bundle body

When `tachyonBundleState` is not `0x00`, the body follows immediately:

| Bytes                | Name                  | Data Type                        | Description                             |
| -------------------- | --------------------- | -------------------------------- | --------------------------------------- |
| 1                    | `tachyonBundleState`  | `uint8`                          | `0x01` (proof stamp) or `0x02` (pointer stamp) |
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
signatures is unrepresentable. The descriptor sequence's order is the transaction
author's choice. The semantics of the actions themselves (what a spend or an output
effects in the pool) are specified by the [Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP.

### Value balance and the binding signature

`valueBalanceTachyon` asserts the net value of the bundle's actions, spends minus
outputs. A positive balance releases value from the Tachyon pool to the rest of the
transaction; a negative balance absorbs value into it. The balance is not required
to be zero: a transaction MAY balance across pools, and a coinbase transaction MAY
absorb newly created value. Value accounting across a whole transaction is a
transaction-layer rule, not specified here.

Value commitments and balance enforcement are Orchard's constructions, unchanged.
Each action's $\mathsf{cv}$ is a homomorphic Pedersen commitment (§5.4.8.3
‘Homomorphic Pedersen commitments (Sapling and Orchard)’) to the
action's value, using Orchard's value-commitment generators (the `z.cash:Orchard-cv`
hash-to-curve domain) and the net-value sign convention of §4.14 ‘Balance and
Binding Signature (Orchard)’: each
$\mathsf{cv}$ commits to $+v$ for a spend and $-v$ for an output, so their
homomorphic sum commits to spends minus outputs, which is exactly
`valueBalanceTachyon`. The
binding validating key $\mathsf{bvk}$ is derived from the actions' $\mathsf{cv}$
values and `valueBalanceTachyon` exactly as in §4.14, and is not encoded in the
transaction. `bindingSigTachyon` MUST be a valid binding signature over the
transaction sighash under the derived $\mathsf{bvk}$; a valid signature enforces
consistency between the asserted balance and the hidden action values.

### Action signatures

Each action signature in `vActionSigsTachyon` MUST be a valid spend authorization
signature (§4.15 ‘Spend Authorization Signature (Sapling and Orchard)’; RedPallas
with the SpendAuth basepoint of §5.4.7.1, for spends and
outputs alike) over the transaction sighash under the corresponding action's
$\mathsf{rk}$. The sighash is a transaction-level digest, computed as specified by
[ZIP 244](https://zips.z.cash/zip-0244) as extended for Tachyon
([Transaction digest contributions](zip-244.md#transaction-digest-contributions));
all of a bundle's signatures sign the same sighash.

### Action digests

Each action has an action digest, a Poseidon hash of its
$(\mathsf{cv}, \mathsf{rk})$ pair. Let $(\mathsf{cv}_x, \mathsf{cv}_y)$ and
$(\mathsf{rk}_x, \mathsf{rk}_y)$ be the affine Pallas coordinates of the action's
decompressed $\mathsf{cv}$ and $\mathsf{rk}$. Then

$$ d = \mathrm{Poseidon}\bigl(\mathsf{dom},\ \mathsf{cv}_x,\ \mathsf{cv}_y,\
\mathsf{rk}_x,\ \mathsf{rk}_y\bigr) $$

where $\mathsf{dom}$ is the Pallas base field element whose integer value is the
little-endian interpretation of the 16-byte ASCII string `Tachyon-ActionDg`. The
Poseidon instance (width, rounds, round constants, and mode) is the instance fixed
by the Ragu proof system.

If an action's $\mathsf{cv}$ or $\mathsf{rk}$ is the identity point, it has no
affine coordinates, the digest is undefined, and the transaction is invalid.

### Action descriptor digests

An action's descriptor is its 64-byte encoding in `vActionsTachyon`: the 32-byte
encoding of $\mathsf{cv}$ followed by the 32-byte encoding of $\mathsf{rk}$. The
descriptor digest of a sequence of actions is the BLAKE2b-256 hash, with
personalization `Tachyon-Actions`, of the concatenation of their descriptors:

$$ \mathsf{h} = \text{BLAKE2b-256}\bigl(\text{"Tachyon-Actions"},\
\mathsf{cv}_1 \| \mathsf{rk}_1 \| \cdots \| \mathsf{cv}_n \| \mathsf{rk}_n \bigr) $$

The digest of the empty sequence is the hash of the empty string under the same
personalization.

This construction is used for two distinct digests, over two distinct sequences:

- `hActionsTachyon`, an input to the effecting digest contribution
  ([ZIP 244 as extended for Tachyon](zip-244.md#transaction-digest-contributions)),
  is computed over the bundle's own actions in their `vActionsTachyon` wire order.
  It is not carried on the wire.
- `hStampActionsTachyon`, carried on the proof stamp ([Proof stamp](#proof-stamp)),
  is computed over every action a proof stamp covers, first sorted into ascending
  lexicographic order. Sorting makes it a function of the covered action multiset
  alone, independent of which transactions contributed it, or in what order a
  merge combined them.

### Set commitments

Multisets of field elements are committed as polynomials with the members as roots.
For action digests $d_i$ and tachygrams $t_j$:

$$ A(X) = \prod_i \bigl(X - d_i\bigr) \qquad T(X) = \prod_j \bigl(X - t_j\bigr) $$

The commitment to a set polynomial of degree $n$ is the deterministic, untrapdoored
Pedersen commitment to its $n+1$ coefficients over the Vesta group, using the
polynomial-commitment generators fixed by the Ragu proof system. The coefficients are
ordered by ascending degree: the constant term pairs with the first generator, the
degree-$k$ coefficient with the $k$-th. A polynomial is invariant under permutation of
its roots, so the commitment depends only on the multiset, not on any ordering. The
empty multiset has no commitment.

The action-set commitment over a set of actions is the commitment of $A$ formed from
their digests; the tachygram-set commitment of $T$ is formed likewise. Both are
deterministic functions of the public actions and tachygrams they commit to, and
carry no information beyond them.

### Proof stamp

When `tachyonBundleState` is `0x01`, the proof stamp follows the body:

| Bytes            | Name              | Data Type               | Description                                    |
| ---------------- | ----------------- | ----------------------- | ---------------------------------------------- |
| 32               | `hStampActionsTachyon` | `byte[32]`         | Descriptor digest over the covered actions     |
| 32               | `anchorTachyon`   | `byte[32]`              | Anchor referencing the pool state              |
| varies           | `nTachygrams`     | `compactSize`           | The number of tachygrams                       |
| 32 * nTachygrams | `vTachygrams`     | `byte[32][nTachygrams]` | The stamp's tachygrams                         |
| PROOF_SIZE       | `proofTachyon`    | `byte[PROOF_SIZE]`      | Ragu proof                                     |

`hStampActionsTachyon` is the descriptor digest
([Action descriptor digests](#action-descriptor-digests)) over every action the
stamp covers: the bundle's own actions together with the actions of every covered
transaction. How a block's actions are checked against it is specified in
[Block validity](#block-validity).

`anchorTachyon` references the pool state the proof is valid against; its semantics
and the anchor-membership rule are specified by the
[Tachyon Accumulator / Hash Chain](tachyon-accumulator.md) ZIP.

`vTachygrams` publishes the stamp's tachygram multiset for data availability. Which
tachygrams an action contributes is specified by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md) ZIP; this ZIP imposes no
relation between `nTachygrams` and `nActionsTachyon`, and a stamp covering actions
that are not the bundle's own carries their tachygrams too. The tachygrams within one
proof stamp MUST be distinct; a transaction violating this rule is invalid.
Block-level distinctness is a block-validity rule of this ZIP
([Block validity](#block-validity)); epoch-window distinctness is specified by the
[Tachyon Accumulator / Hash Chain](tachyon-accumulator.md#epoch-window) ZIP.

`proofTachyon` is the Ragu proof. The statement it attests to, and the base rule that
a stamp proof MUST verify against the Tachyon statement, are specified by the
[Tachyon Shielded Protocol](tachyon-shielded-protocol.md#proof-verification) ZIP; how
that rule is applied to a block's stamps is specified in
[Block validity](#block-validity).

### Pointer stamp

When `tachyonBundleState` is `0x02`, the pointer stamp follows the body:

| Bytes | Name                 | Data Type  | Description                     |
| ----- | -------------------- | ---------- | ------------------------------- |
| 64    | `tachyonAggregateId` | `byte[64]` | wtxid of a covering transaction |

`tachyonAggregateId` is the `wtxid` ([ZIP 239](https://zips.z.cash/zip-0239)) of
a covering transaction. It MUST NOT be all zero; the rule applies to every
pointer-stamped transaction, with or without actions. Which transaction it must
identify within a block is specified in [Block validity](#block-validity).

### Canonical encodings

- Every compactSize field MUST use the minimal encoding for its value (§7.1
  ‘Transaction Encoding and Consensus’) and
  MUST NOT encode a value exceeding `0x02000000`. A parser MUST reject any other
  encoding.
- `cv` and `rk` are 32-byte compressed encodings of Pallas points. A parser MUST
  reject an encoding that does not decode to a point. `rk` MUST decode as a
  RedPallas validating key (§5.4.7 ‘RedDSA, RedJubjub, and RedPallas’). The
  identity point decodes successfully; it is
  excluded by the rule in [Action digests](#action-digests), not by the parser.
- `anchorTachyon` and each tachygram are canonical little-endian encodings of Pallas
  base field elements; a parser MUST reject an encoding whose value is not less than
  the field modulus.
- `vActionsTachyon` carries no ordering requirement: the descriptors may appear
  in any sequence the transaction author chooses. The signatures in
  `vActionSigsTachyon` follow their descriptors' positions regardless of that
  order.
- The tachygrams in `vTachygrams` MUST be in ascending lexicographic order of their
  32-byte encodings; a parser MUST reject a stamp whose tachygrams are out of order.
  With the distinctness rule ([Proof stamp](#proof-stamp)) the sequence is strictly
  increasing.
- `hStampActionsTachyon` is an opaque 32-byte string at parse time; whether it
  matches the covered actions is a block-validity property
  ([Block validity](#block-validity)).
- Signatures (`vActionSigsTachyon`, `bindingSigTachyon`) are opaque 64-byte strings
  at parse time; their validity is a verification-time property.
- `proofTachyon` is exactly `PROOF_SIZE` bytes and MUST decode as a Ragu proof. The
  proof encoding is defined by the Ragu proof system.

### Transaction digest contributions

The bundle contributes one leaf to each of the transaction's two digest trees
([ZIP 244](https://zips.z.cash/zip-0244)). This section states what the bundle
supplies to each; the leaf algorithms and personalizations are specified by ZIP 244
as extended for Tachyon
([Transaction digest contributions](zip-244.md#transaction-digest-contributions)).

The effecting contribution (to `txid` and the sighash) commits to
`hActionsTachyon`, the descriptor digest over the bundle's own actions
([Action descriptor digests](#action-descriptor-digests)), and to
`valueBalanceTachyon`. `hActionsTachyon` is distinct from `hStampActionsTachyon`,
which may cover more actions than the bundle's own. The stamp is excluded, so the
contribution is invariant across stamping, merging, stripping, and re-stamping.

The authorizing contribution (to `auth_digest`) commits to the action and binding
signatures and to the stamp, the latter through the 64-byte `stamp_digest` whose
algorithm the ZIP 244 update specifies: a proof stamp's covered-actions digest and
remaining fields, or a pointer stamp's `tachyonAggregateId` directly.

A transaction with no Tachyon bundle contributes distinctly from a bundle with
no actions: no bundle produces the empty preimage, while every bundle's effecting
contribution contains its encoded balance and its authorizing contribution
contains at least its binding signature and `stamp_digest`.

### Bundle validity

The rules owned by this ZIP, applying to a single transaction's bundle:

1. `tachyonBundleState` MUST be `0x00`, `0x01`, or `0x02`.
2. Every compactSize MUST be minimally encoded and MUST NOT exceed `0x02000000`.
3. Every point and field-element encoding MUST be canonical, and every sequence in
   canonical order, as specified in [Canonical encodings](#canonical-encodings).
4. An action's $\mathsf{cv}$ and $\mathsf{rk}$ MUST NOT be the identity point.
5. Every action signature MUST verify over the transaction sighash under its
   action's $\mathsf{rk}$.
6. `bindingSigTachyon` MUST verify over the transaction sighash under the derived
   $\mathsf{bvk}$.
7. `valueBalanceTachyon` MUST be in the range $-\mathrm{MAX\_MONEY}$ to
   $\mathrm{MAX\_MONEY}$ inclusive.
8. A bundle with no actions MUST have `valueBalanceTachyon` equal to $0$.
9. A proof stamp's `proofTachyon` MUST be exactly `PROOF_SIZE` bytes and a valid
   proof encoding, and its tachygrams MUST be distinct.
10. An pointer stamp's `tachyonAggregateId` MUST NOT be all zero.

Rules outside the scope of this ZIP are enumerated in
[Non-requirements](#non-requirements).

### Block validity

The rules owned by this ZIP that constrain a block's Tachyon bundles together:

- All tachygrams in a block MUST be distinct.
- Every pointer-stamped transaction MUST bear a `tachyonAggregateId` referring
  to the proof-stamped transaction in the same block covering its actions.
- Every proof-stamped Tachyon transaction MUST bear an `hStampActionsTachyon`
  matching the descriptor digest of the complete set of actions of its covered
  transactions in the same block.
- All proofs in a block MUST verify.

A validator enforces these fail-fast, in this order:

1. **Tachygram uniqueness.** The block's tachygrams are the multiset union of the
   `vTachygrams` of every proof stamp. A single scan enforces this rule and the per-bundle
   distinctness of [Bundle validity](#bundle-validity) rule 9 together; reject on any
   duplicate. Reuse within the wider epoch window
   is governed by the epoch-window rule
   ([Tachyon Accumulator / Hash Chain](tachyon-accumulator.md#epoch-window)).
2. **Proof coverage.** The `tachyonAggregateId` of every pointer-stamped
   transaction MUST identify a proof-stamped transaction in the same block; reject
   if absent or not proof-stamped. A pointer-stamped transaction with no actions
   satisfies this check against any proof-stamped transaction in the block: it
   contributes no action descriptors to step 3, so consensus attaches no further
   meaning to its reference.
3. **Covered-actions digest per stamp.** For each proof stamp, collect the
   descriptors of the bundle's own actions together with those of every
   pointer-stamped transaction naming it, sort them, and compute the descriptor
   digest ([Action descriptor digests](#action-descriptor-digests)); reject on
   mismatch with the carried `hStampActionsTachyon`. The check is a sort and one
   BLAKE2b-256 hash, with no curve arithmetic.
4. **Proof verification.** Every proof stamp MUST verify. The
   validator reassembles the stamp PCD from `proofTachyon`, `anchorTachyon`, a
   Pedersen commitment to `vTachygrams`, and the action-set commitment formed over
   the confirmed action set's digests ([Action digests](#action-digests),
   [Set commitments](#set-commitments)); reject
   if any proof fails. The base requirement that a proof verifies the Tachyon
   statement is the shielded-protocol rule
   ([Tachyon Shielded Protocol](tachyon-shielded-protocol.md#proof-verification));
   these items apply it per stamp within a block.

## Rationale

**The stamp is excluded from the txid contribution.** The effecting contribution
commits only to actions and balance, so stamping, merging, stripping, and
re-stamping preserve a transaction's logical identity. This is the property the
aggregation lifecycle rests on: a pointer-stamped transaction in a block is the
same transaction its author signed.

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

**`MAX_MONEY` bound on the balance.** The Orchard-era bound on `valueBalanceOrchard`
is a protocol-spec consensus rule (§7.1 ‘Transaction Encoding and Consensus’); this ZIP
is that rule's analogous home for `valueBalanceTachyon`.

**Zero-action balance.** The v5 analogue defines an absent `valueBalanceOrchard` as
zero when the action count is zero; this format keeps the field present in every
state, so the equivalent semantics are stated as a rule.

**Identity points are invalid.** The action digest hashes affine coordinates, which
the identity point lacks. Excluding it also rejects a degenerate verification key
and a degenerate value commitment.

**`vActionsTachyon` needs no canonical order.** `hActionsTachyon` hashes the
bundle's own actions in wire order, so reordering them changes `hActionsTachyon`
and therefore the sighash every action and binding signature covers: an attacker
cannot reorder a signed bundle without invalidating its signatures, and the
author is free to choose any order without consequence. This is the same
property Sapling and Orchard rely on for their own spend/output/action arrays,
which are likewise unordered on the wire.

**`hStampActionsTachyon` and `vTachygrams` do need one, for different reasons.**
`hStampActionsTachyon` can cover many transactions' actions, combined by
whatever merge tree an aggregator chose; sorting before hashing makes it a
function of the covered multiset alone, so it reconstructs identically
regardless of merge history. The in-circuit set commitments
([Set commitments](#set-commitments)) get this order-independence for free, as
polynomial multiplication. `vTachygrams`' sortedness is a different concern:
the stamp is authorizing data that no signature covers (see "Signatures survive
stripping" below), so without a canonical order, an observer could freely
reorder `vTachygrams` to mint a distinct `wtxid` for byte-identical semantic
content. Requiring sorted order gives it the one serialization that
`vActionsTachyon` gets from its signature coverage instead.

**A digest, not a commitment, carries the covered actions.** The carried field
serves coverage identification and fail-fast confirmation. The proof binds the
action set through the in-circuit action-set commitment, which validators
reconstruct from the confirmed actions, so the carried field needs no algebraic
structure: a flat hash reconstructs with no curve arithmetic, and the wire carries
no unverified group element.

**Deterministic set commitments.** The committed sets are public data, so a hiding
commitment is unnecessary; determinism is what lets any party recompute a
commitment from the data it covers.

**Fixed-size proof.** Recursion yields one proof size whether a stamp covers one
action or a block's worth. A constant-size field needs no untrusted length prefix,
and a stamp size independent of coverage underlies aggregation's space savings.

**`wtxid`, not `txid`, in `tachyonAggregateId`.** A `txid` is ambiguous across
the authorization forms that share it; the `wtxid` pins the physical covering
transaction, stamp included, which is what the pointer-stamped transaction needs
to reference.

**Nonzero `tachyonAggregateId`.** Every pointer-stamped bundle names a covering
transaction, and the unassigned pointer state has no valid wire form. An
all-zero `wtxid` (which names no transaction) is invalid.

## Security and Privacy Implications

**Canonical encodings, except action order.** Every field but `vActionsTachyon`
has exactly one accepted serialization, so a bundle cannot be re-encoded into a
second accepted serialization except by permuting its actions. That permutation
is not a malleability concern: it changes `hActionsTachyon`, and therefore the
sighash every signature covers, so a re-ordered bundle needs new signatures, not
just new bytes. Authorization-form changes (re-stamping, stripping) produce
distinct bundles by design and are reflected in `auth_digest` and `wtxid`
([ZIP 239](https://zips.z.cash/zip-0239)).

**Balance consistency is enforced by the binding property.** A valid binding
signature establishes that `valueBalanceTachyon` equals the net value committed by
the actions' $\mathsf{cv}$, by the same binding argument as Orchard (§4.14). It
establishes nothing about the transaction's overall balance, which is a
transaction-layer rule.

**`bvk` is derived, not carried.** The binding verification key is recomputed from
`vActionsTachyon` and `valueBalanceTachyon`; a prover cannot supply a key
inconsistent with the public data.

**Signatures survive stripping.** All signatures cover the transaction sighash,
which incorporates only effecting data. A miner stripping a proof stamp changes
no signed data, so aggregation does not invalidate signatures. A signature
authorizes only the sighash it signs; using an action in a transaction with
different effecting data requires a new signature over that transaction's
sighash.

**Absent bundles are distinct from empty bundles.** A transaction with no Tachyon
section and a transaction with a zero-action, zero-balance bundle produce distinct
digest preimages, so their identifier contributions differ (see
[Transaction digest contributions](#transaction-digest-contributions), whose leaf
algorithms are specified by
[ZIP 244 as extended for Tachyon](zip-244.md#transaction-digest-contributions)).

**Public data.** $\mathsf{cv}$ is a hiding commitment to the action's value. The
unlinkability properties of $\mathsf{rk}$, and of tachygrams (which do not
distinguish nullifiers from note commitments), are established by the [Tachyon
Shielded Protocol](tachyon-shielded-protocol.md) ZIP, not by this format.  The
action count, the value balance, and, on a proof-stamped bundle, the tachygram
count are public, as is anything derivable from them.

**Parse validity is not spend validity.** A bundle that parses and whose signatures
verify is not thereby valid to spend; the rules enumerated in
[Non-requirements](#non-requirements) also apply. Implementers and auditors should
not assume the rules in this ZIP alone establish those properties.

## Deployment

This ZIP is deployed with a Tachyon network upgrade. Activation parameters are
specified by the corresponding deployment ZIP
([Network Upgrade Deployment](network-upgrade-deployment.md)).

## Reference implementation

A reference implementation of the bundle wire codec, the digest and commitment
constructions, the value balance, the digest contributions, and signature verification
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
- [ZIP 244 as extended for Tachyon](zip-244.md)
- [Tachyon Shielded Protocol](tachyon-shielded-protocol.md)
- [Tachyon Accumulator / Hash Chain](tachyon-accumulator.md)
- [Network Upgrade Deployment](network-upgrade-deployment.md)
