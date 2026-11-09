# Tachyon formal verification

This directory holds a Lean 4 model of the Tachyon stamp proof tree and of the consensus rules that
publish stamps, with machine-checked proofs about that model. `just fv` builds it. Mathlib is the
only dependency, pinned to the release ragu's `qa/fv` uses.

The theorems are about the model. Each step is modelled by hand from the Rust source, and no check
compares a Lean step with the circuit it models. Read
[Assumptions and open boundaries](#assumptions-and-open-boundaries) before quoting a result.

## The model

`Stamp.lean` and `ProofTree.lean` model the stamp headers and the steps that produce them. Each
Pedersen commitment is read as the polynomial it commits to. Each `enforce_poly_product` and
`enforce_poly_roots` is read as the identity it checks. An accepted header is one that a registered
step derives from accepted inputs (`ActionsDerivable`, `StampDerivable`). This idealizes PCD
knowledge soundness.

`SetPoly.lean` defines `setPoly D`, the product of `X - d` over a multiset `D`. The results are
stated on these root multisets. A product of set polynomials is the sum of their multisets.

`R e d` is the tachygram multiset that a leaf with digest `d` derives at epoch `e`. Taking `R` as a
function encodes the pairing assumption. Two leaf proofs with one digest in one epoch derive the
same tachygrams.

`Consensus/Bundle.lean` models `Bundle::verify`. `Consensus/Chain.lean` models the anchor chain and
the publication rules that `Chain.Valid` collects.

### Results or computed breaks

The reductions follow ragu's discipline for computational assumptions. A reduction returns its
result or a break (`Result ⊕' Break`). The break is data. It holds two colliding hash inputs, two
openings of one commitment, or a nontrivial discrete-log relation among generators. Cryptographic
security enters only to say that computing a break is hard. A break is never stated as an
existential or as `Nonempty`, since an existential break is vacuous for a compressing hash.

A reduction cannot case on a proposition such as `StampDerivable` to compute a break. The
reductions consume data-valued traces (`StampTrace`, `SpendableTrace`, `NodeTrace`, `RunTrace`) and
query certificates that carry the same derivations. Each trace has a `forget` or `toNode` map to
its proposition. No reduction selects a trace or a witness with `Classical.choice`.

Collision freedom is execution-local. `NoCollisionsOn` states it on the finite inputs that one
execution compares, and a `ScopedBreak` records those inputs when it fails. `Chain.HashLaw` remains
as a symbolic reference model. `HashModelBoundary.lean` proves that it cannot hold for a finite
anchor type (`HashLaw.not_finite_anchors`).

Where a module departs from a ragu precedent, its docstring gives the reason.
`QueryIntegration.lean` is `noncomputable` because it specializes to Mathlib polynomials.

## What is verified

### Private arithmetic graph (step-budget)

`FixedBase.lean` models the three fixed radix-8 stages for each of R and G.
`Accepted.invariant` establishes canonical integer limbs and the partial sums at
24/54/85 windows; `Accepted.product` derives the completed multiplication.
`Accepted.complete` constructs the stages from the old scalar opening, including
zero scalars and identity partial sums. `accepted_iff` gives both directions.
The tag decodes to identity only when set, with a finite sentinel carrier;
`decode_encode` and `encode_valid` cover honest export. A sentinel with tag false
remains the sentinel group element.

`windows_correct` proves the sum of fixed table entries equals integer scalar
multiplication. `select8_correct` verifies the three-bit selection tree and
`amount_product` covers the 17-window bounded amount path, with either signed V
base. `suffix_injective` checks the six actual scalar suffixes (17 through 22);
`Accepted.unique_producer` requires the right base's preceding stage.
`StampTrace.mapLeaf` and `StampTrace.refinement_iff` lift two-way leaf refinements
through the existing merge/unmerge/lift graph without changing terminal headers.

This is an integer/group interpretation, not a verified circuit compiler. The
correspondence obligations are Boolean allocation, separate 128/127-bit limb
recomposition below the circuit modulus, the canonical scalar comparison,
correct grouping of the ordered bits across bit 128, the two coordinate
selectors using the same bits, and the complete-add/finite-point codec.
`boolean_recomposition_injective` and `Word.digits_eq` establish uniqueness at
the integer interpretation; the real backend must enforce their premises.
Hash consumers compare both canonical limbs (`hash_limb_match`), not a single
circuit-field residue. Headers containing these limbs stay prover-private.

`StepBudget.lean`, introduced with the group/value and spend-binding models,
gives two-way accepted-relation refinements for `OutputBind`, `SpendBind`,
`OutputAction`, `SpendAction`, `FeeFuse` and `FeeSeed`. The old relations retain
their real finite-export requirements. In particular, SpendAction permits a
zero alpha if adding ak gives a finite rk; OutputAction cannot export identity.
The new relations consume `FixedBase.Accepted` derivations, and reuse
`valueCommit` and the existing module/group algebra. The 17-window amount
computation is read through `FixedBase.amount_product`.

`PreparedAccepted` has only the SpendPrepare producer, joins a certified
NoteSecret to its accepted spendable by cm, and preserves the nullifiers,
anchor, pk and bounded value. NoteSecret's producer ties pk and mk to the same
pak/nk and psi. `ReadyAccepted` requires FeeValueCommit followed by FeeBind,
with exact maximum and scalar-limb linkage and both roots derived from the
same opening. The nine private suffixes are distinct and above the old range.
`FuseAt` takes its two roots from that authenticated right input;
`fee_bad_challenges` specializes the existing polynomial-identity bound with
those roots fixed. Actions retain staged-digest equality and FeeSeed retains
the three staged-owner equalities.

`accepted_refinement` erases or reconstructs the helper graph for each typed
leaf witness. `stamp_refinement` lifts both directions through the whole
trace. `published_through_refinement` and `bundle_through_refinement` recover
the stamp publication and covered-fee conclusions using the erased trace.
The abstract cm-to-nullifier interpretation is preserved by
`prepare_header_eq`; as in the original `SpendBinding`, instantiating that
interpretation requires the same note/master-key pairing assumptions.

The merge and unmerge results follow the soundness argument for `StampUnmerge` in three parts. Every
derivable header pairs its action set with its tachygram set through `R`. A verified bundle
publishes exactly its covered leaves' tachygrams. Every covered digest traces back to a leaf that
derived it.

### Leaf correspondence

A header is generated by a multiset `D` of leaf digests when its action set is `setPoly D` and its
tachygram set is `setPoly` of the sum of `R e d` over `D` (`GeneratedBy`). Every derivable header is
generated at the epoch `e` of its anchor (`ActionsDerivable.leafGenerated`,
`StampDerivable.leafGenerated`). For an `Actions` header, `D` is non-empty and holds no fee digest.

- `ActionMerge` and `StampMerge` add leaf multisets (`Merge.generatedBy`). `FeeFuse` adds one fee
  digest (`GeneratedBy.fuse`).
- If `setPoly r * q = setPoly d` for an arbitrary polynomial `q`, then `r ≤ d` and
  `q = setPoly (d - r)` (`setPoly_mul_eq`). `StampUnmerge` checks its two columns independently, and
  this pins each column's quotient (`Unmerge.columns`).
- The quotient of a dividend generated by `D` and a divisor generated by `D'` is generated by
  `D - D'`, because both columns come from one leaf multiset under one pairing `R`
  (`Unmerge.generatedBy`). The `unmerge` step takes separate derivations of the dividend and the
  divisor, so this covers independently built divisors and earlier unmerges.
- Without the pairing, division can assemble a leaf that no proof derived
  (`unmerge_needs_pairing`). Over `ℚ`, the merge of the leaves `(0, {2})` and `(1, {3})` divided by
  the leaf `(0, {3})` passes both column checks, and the quotient is the leaf `(1, {2})`.
- `FeeFuse` adds exactly one fee leaf over non-empty fee-free content
  (`ActionsDerivable.feeFuse_leaves`). Unmerge can divide that leaf out again. With action digests
  `d₁`, `d₂` and a fee digest `f`, `FeeFuse(d₁ + d₂, f)` divided by `FeeFuse(d₂, f)` is a derivable
  `Stamp` header covering `d₁` alone (`unmerge_strips_fee`). The fee of a published stamp rests on
  consensus coverage of the bundle's fee descriptor.

Merge and unmerge require equal anchors. The lift steps take the lift's epoch preservation as a
hypothesis, which [Bundles and double spends](#bundles-and-double-spends) discusses.

### Publication

`BundleVerified` covers the action digests of the bundle's and its adjuncts' descriptors, followed by
the fee digests of the bundle's and its adjuncts' fees (`coveredDigests`). It requires the
published tachygrams to be non-empty and duplicate-free, with two per descriptor and one per fee.
The carried tachygram-set commitment is `setPoly` of the published tachygrams, and the header built
from the covered digests, that commitment and the anchor is `StampDerivable`.

- A verified bundle publishes exactly its covered leaves' tachygrams, with multiplicity, at its
  anchor's epoch (`StampDerivable.published`, `BundleVerified.tachygrams_eq`).
- No two covered leaf occurrences share a tachygram. A digest covered twice has no tachygrams
  (`BundleVerified.leaves_disjoint`).
- The bundle's own fee leaf's tachygrams are published (`BundleVerified.fee_published`). Coverage
  supplies the fee, since unmerge can divide it out of a derivable stamp.

`BundleVerified` leaves out the BLAKE2b coverage digest, which compares the stamp's coverage field
against the same descriptors. It checks neither anchor membership nor anchor recency. Those are
[consensus rules](#consensus-rules) on the chain.

### Leaf provenance

`ActionsTrace` and `StampTrace` (`ProvenanceTraces.lean`) carry the derivations as data. Each leaf
occurrence records its digest, its anchor and a provenance value of type `Leaf d a`.
`StampTrace.forget` maps a trace to its derivation. A stamp trace signs its leaf occurrences
(`StampTrace.positive`, `StampTrace.negative`). `FeeFuse` and `FeeSeed` leaves start positive, merge
keeps the inputs' signs, and unmerge keeps the dividend's signs and reverses the divisor's.

- A stamp trace's header is generated by some `D` with `D + negative = positive` as digest
  multisets. Every leaf occurrence's anchor is in the header's epoch (`StampTrace.spec`).
- Every digest a stamp covers is found among its positive leaf occurrences, with its provenance and
  an anchor in the stamp's epoch (`StampTrace.findLeaf`). Division never yields a digest that no
  leaf derived.

These results take the trace as an input. `StampDerivable` is a proposition, so nothing produces a
trace from it. That a verified stamp proof has a trace is the
[PCD knowledge extraction](#proof-system) assumption. `Leaf d a` is an uninterpreted type. The
results say which leaf occurrence a covered digest comes from. They say nothing about the witness it
carries or about the leaf step's constraints on it.

### Bundles and double spends

- `no_double_spend` states the argument over abstract epochs. `no_double_spend_of_valid` takes
  anchor recency and the two-epoch window from `Chain.Valid`. `no_double_spend_of_bundles` takes
  each spend's nullifier pair from bundle verification. These three take the second spend's
  spendable lineage as a hypothesis. `BundleVerified.no_double_spend` covers two spends in one
  bundle.
- When a lifted stamp's `anchor_end` is on the chain, every span member is on the chain in the same
  epoch (`SpanDerivable.node_epoch`, `StampLiftStep.epoch_eq`). `ActionsDerivable.liftStep` and
  `StampDerivable.liftStep` use this to discharge the epoch hypothesis of `ActionsDerivable.lift`
  and `StampDerivable.lift` for a lift whose output anchor is on the chain. Consensus checks only
  the published anchor. [Evidence, provenance and publication](#evidence-provenance-and-publication)
  carries that check down through every lift of a stamp trace (`StampTrace.positiveNodes`).
- The tachygrams published in one epoch, and in two consecutive epochs, are duplicate-free
  (`Chain.Valid.nodup_epoch`, `Chain.Valid.nodup_two_epochs`).
- Fixed operands that violate a product identity of degree `n` pass at most `2n` challenges
  (`card_product_check_le`). A fixed accumulator of degree `n` that violates its roots identity
  passes at most `n` challenges (`card_roots_check_le`).

### Spendable lineage and QR routing

- Every pair in a derivable `NoteNullifiers` is the note's nullifier at its epoch
  (`NullifiersDerivable.mem_seq`). `UnspentBind` divisibility forces every tested value to be the
  note's nullifier (`NoteUnspentDerivable.lineage`).
- A derivable `NoteSpendable` proves that the note's nullifier is unpublished at every epoch from
  its lineage start to the epoch before its current one (`SpendableDerivable.lineage`). With
  buckets that hold their whole epochs, this discharges the lineage hypothesis
  (`no_double_spend_of_spendable`). A `SpendableInit` lineage never lifts
  (`spendableInit_cannot_lift`).
- QR routing keeps every root that matches the selected profile (`Route.retains`). A child bucket
  may hold extra roots. An extra root only makes a nonzero opening harder. Exclusion is sound when
  the source holds the epoch's publications and the queried value matches the profile
  (`Route.not_published`). The exceptional-value guard is necessary (`exceptional_guard_needed`).
- `QrIntakeSplit` only factors the source. `QrSideSelect` assigns the exceptional value and fixes
  arbitrary hint commitments (`SideSelection`); `QrSideDescend` matches the selection's source and
  hints before checking their class identity (`SideCheck`). A split that places the exceptional
  root on the non-residue side cannot produce a selection (`split_without_selection`).
- A routed bucket retains the published values that match its profile and may retain other roots.
  Completeness is therefore stated per query (`QueryComplete`). The profile-aware lineage needs completeness only for the
  values it opens (`SpendableDerivable.routed_lineage`, `no_double_spend_of_routed`).
  `routed_query_without_global_completeness` exhibits a valid routed query on a bucket that omits a
  different publication of its epoch.
- A mask whose weight is `d` and whose selected indices sum to `d(d - 1)/2` is the prefix
  `0, ..., d - 1` (`eq_range_of_field_checks`). Equality of the packed register with the bucket
  profile then forces the queried value to match the profile (`matches_of_field_checks`).
- Two runs that start on epoch-boundary digests and end at one anchor have the same start and the
  same product. Sealing against the next entry anchor pins the source to the epoch's publications
  (`Run.sealed_source_eq`, `routedQuery_of_sealed`). Builders may route and merge same-profile
  intakes in any order (`CheckedIntake.complete`).

### Double spends with computed breaks

- Anchor, source and span comparisons return the decoded result or a scoped collision
  (`sameSourceOrBreak`, `nodeEpochOrBreak`, `stampPredecessorOrBreak`). A checked query returns
  completeness or a commitment or hash collision in its source transcript (`queryCompleteOrBreak`,
  `Certificate.oracle`). `ObservedBreak` carries each break with its transcript, so breaks from
  different queries share one type.
- A traced spendable's anchor decodes to its `epoch_current` (`SpendableTrace.anchorEpochOrBreak`).
  Its lineage holds, or the first query break is returned (`SpendableTrace.lineageOrBreak`). Lifts
  along a traced span get their epoch equality (`ActionsDerivable.liftOrBreak`,
  `StampDerivable.liftOrBreak`).
- Two verified bundles that spend one note compute a collision among the node traces and anchor
  preimages, or a query break (`doubleSpendBreak`). `no_double_spend_of_no_collisions` is the
  execution-local corollary. `doubleSpendObservedBreak` instantiates the queries with checked source
  data.

### Indexed nullifier sets and runtime openings

- The indexed encoding of `(i, v)` is `(v + (i + 1) X)^3 - 2`. With a nonzero slope and a cubic
  non-residue, the factor is irreducible (`factor_irreducible`). For indices below `bound` with
  `3 bound^2 < p`, equal factors have equal indices and values (`indexed_factor_injective`). Without
  the bound, indices can collide (`indices_can_collide_without_bound`).
- Associated factors of this form are equal (`indexed_associated_injective`). Exact division of
  indexed products is therefore multiset containment, with the quotient pinned to the remaining
  factors (`indexed_division`). The cubic identity in `UnspentBind` derives the multiset equation
  that the lineage model uses (`lineage_of_polynomial_bind`).
- For the Pallas base field, `2` is a cubic non-residue (`two_noncube`), and the production and test
  epoch bounds satisfy `3 bound^2 < p` (`epoch_bound_safe`, `test_epoch_bound_safe`).
- Spendable traces and source certificates take a runtime opening type with an interpretation into
  polynomials (`OpeningSemantics`). The double-spend reduction over it compiles as ordinary code
  (`doubleSpendRuntimeBreak`). Polynomials appear only in proof fields.

### Evidence, provenance and publication

- Evidence-tree replay returns a certified leaf or two tagged hash inputs with one output
  (`replayOrCollision`). The model builds quaternary nodes directly. Each assembled node in the
  protocol has four certified subtrees, so this tree set contains every real one.
- Replayed evidence and a per-value profile check produce a checked query (`Query.oracle`). The
  double-spend reduction then returns an anchor, source or evidence collision
  (`doubleSpendEvidenceBreak`).
- Each lift in a stamp trace carries its traced span. Descending from a node at the published
  anchor gives every positive leaf a node at the stamp's epoch, or a break
  (`StampTrace.positiveNodes`). Two verified bundles with spend leaves of one note compute a break
  (`doubleSpendBreakOfTraces`). `stampedEvidenceBreak` reads each spendable from the payload of its
  positive leaf and combines this with evidence replay.
- A root of a certified bucket is published in its epoch, or the source traces compute a collision
  (`publicationOrBreak`). Retention of matching roots alone gives only the converse.
- `checkChain` decides `Chain.Valid` over public data (`checkChain_eq_true_iff`). Anchor membership
  is a supplied boolean policy.

### Authorization and fee pairing

- A claimed note with the owner's commitment gives the owner's randomized action key, or a collision
  in the note or payment-key hash (`ownerKeyOrCollision`). The authorizing message is consented to,
  or the reduction returns a hash break or a valid unconsented signature under a randomized owner
  key (`authorizedOrBreak`).
- Two accepted responses at one nonce with different challenges give the owner key's logarithm
  (`ownerLogOrMiss`). Equal challenges are returned as a miss.
- Two fee leaves with one digest have one change tachygram, or the reduction returns a digest or
  blind-hash collision, an encoding failure, or a relation among the value generators
  (`changeEqOrBreak`).

### Notes, creations and republication

- A descriptor's `cv` is the `cv` of the leaf its digest covers, or the two preimages collide
  (`descriptorOpensOrCollision`). The leaves' signed note values sum to the change, the fee and the
  value balance, with the fee at most the max fee, or the bundle yields a break
  (`noteAccountingOrBreak`, `TracedBundle.accountingOrBreak`).
- Two spends of one note compute a break, or the second lineage starts after the first spend's
  publication (`doubleSpendBreakOrLaterStart`). Spends of one `cm` whose lineages start in one epoch
  compute a break (`sameStartBreak`).
- A published note commitment comes from a covered leaf that creates the note, either an output or
  a fee leaf whose change note it is (`publishedNoteOrCollision`, `creationOrCollision`). The
  descriptor covering that leaf debits the note's value (`Creation.debitOrBreak`). Two spends that
  consume one creation compute a break (`sharedCreationBreak`).
- A spendable lineage starts at a publication of its `cm`, or the comparison with a
  publication-linked node or certified bucket source computes a collision
  (`creationPublicationOrBreak`, `SpendableTrace.startPublishedOrBreak`). Any two spends on a chain
  of traced bundles, including two in one bundle, consume distinct creations or compute a break
  (`distinctCreationsOrBreak`, `sameBundleDistinctCreationsOrBreak`). A family of spends at distinct
  positions maps injectively into the chain's creations, or yields a break
  (`spendsUnsharedOrBreak`).
- Two output leaves with one digest have one `(cm, pad)` pair, or the reduction returns a digest,
  nonce or note collision (`tachygramsEqOrBreak`). The canonical lift of Pallas base-field words and
  bounded amounts into the scalar field is injective (`lift_injective`, `noteWordLift_injective`).
  The fee and output pairing reductions drop their encoding-failure branches for Pasta
  (`pastaFeeChangeEqOrBreak`, `pastaOutputPairingOrBreak`).

### Value, fees and removal

- Two distinct openings of one set commitment, both of degree below `n`, give a nontrivial
  discrete-log relation among the commitment generators (`NontrivialDLRelation.ofPolyCollision`).
- An unbalanced binding signature gives a nontrivial relation among the value generators
  (`NontrivialRelation.ofImbalance`). `balanceOrRelation` and `intBalanceOrRelation` return the
  balance or that relation. `feeAccountingOrRelation` adds the max fee commitment and the change
  note.
- Stamps generated by derivable leaf multisets at one anchor are closed under merge and under
  unmerge of contained leaves (`StampDerivable.merge_generated`,
  `StampDerivable.unmerge_generated`). Unmerge can remove `B` from an opaque `A + B` by merging in
  `C` and dividing by `B + C` (`unmerge_through_hidden`).

## Assumptions and open boundaries

A theorem applies only when every hypothesis holds. The items below are hypotheses or modelling
choices that no theorem here discharges.

### Proof system

- **PCD knowledge extraction.** Derivability stands in for it. An accepted proof is assumed to come
  from registered steps on accepted inputs. The reductions take their traces and certificates as
  inputs. A knowledge extractor for the real proof system must supply them, and none is modelled.
- **Commitment binding and the random challenge.** The model reads commitments as polynomials and
  checks as identities. `Idealization.lean` counts the challenges that fixed violating operands
  pass. Dividing by the field size bounds the probability for a uniform challenge drawn after the
  operands are fixed.
- **Rust and circuit equivalence.** No fingerprint or extraction check ties a Lean step to its Rust
  step. Hash inputs are assumed to use canonical encodings with no ignored fields.
- **Typed circuit inputs.** The profile checks take genuine booleans, a canonical depth and explicit
  no-wrap bounds as typed inputs (`ProfileMask.lean`, `ProfileQuery.lean`). The model derives no
  boolean or range constraint from a field witness.

### Field parameters

- **Pasta primality.** The Pallas modulus and the modular exponent witness are checked in the
  kernel. Primality is an explicit `Fact modulus.Prime` argument. Ragu takes it from CompElliptic,
  which this project does not depend on. The Pallas scalar modulus is handled the same way
  (`ScalarEncodings.lean`).

### Hashes and the pairing

- **The pairing `R`.** Unmerge soundness depends on it. In the protocol it rests on Poseidon and on
  the leaf proofs deriving their tachygrams from the digest preimage. Fee/fee and output/output
  pairing are reduced to computed breaks (`FeePairing.lean`, `OutputPairing.lean`). Spend/spend and
  spend/output pairing remain hypotheses.
- **Signatures.** The authorization results take the RedPallas verification equation as given. The
  consent policy stands for the honest owner's signing requests in the security game. RedPallas
  unforgeability and the probability that a Fiat-Shamir forger yields a fork are unproved.
- **Poseidon.** Collision resistance, preimage resistance and domain separation are assumed, never
  proved.
- **`Chain.HashLaw`.** The anchor-chain results take the stamp and epoch folds as injective and
  domain-separated (`Node.epoch_unique`, `SpanDerivable.node_epoch`). This is a global law over the
  fold inputs. No finite hash satisfies it, so results that assume it are symbolic. The trace
  reductions above replace it with execution-local collision freedom.

### Consensus rules

`Chain.Valid` is a hypothesis of the chain-level theorems. It includes these rules.

- **Anchor membership.** A stamp's anchor is an acknowledged end-of-block anchor on the accepted
  chain.
- **Two-epoch window.** A published tachygram is absent from every earlier stamp of its publication
  epoch and the epoch before.
- **Anchor recency.** A stamp's anchor epoch is its publication epoch or the epoch before
  (`StampAccepted.recency`).

The chain model folds each anchor with the epoch of the block that contains it. Consensus must
compute the folds with the same epochs.

Source sealing compares a bucket with the next entry anchor folded from the epoch's chronological
publication list. That anchor and that list are inputs. `Chain.Valid` does not derive them.

`checkChain` covers the public rules only. Wire parsing, signatures, the PCD verifier and anchor
folding have separate inputs.

Anchor recency is load-bearing. A spend anchored at epoch `a` publishes the note's nullifiers for
`a` and `a + 1`. If it is published at an epoch `p ≥ a + 2`, both land in the bucket for `p`. A
later spend's lineage tests the note's nullifier for `p` against that bucket. That nullifier
differs from both published ones. The later spend publishes the nullifiers for its own anchor
epoch, and the window finds no duplicate. Both spends pass.

`Consensus/Bundle.lean` leaves signatures, the value balance and adjunct pointers out of scope.
The value results model the binding signature as its verification equation (`hbvk`). They take
every value, the max fee and the value balance within a bound `M`, with `(n + 2) M` below the
scalar characteristic for `n` value commitments.

### Lineage start

The double-spend theorems assume that the second spend's lineage starts no later than the first
spend's publication. A lineage that starts at a later publication of the same `cm` spends a second
note with the same commitment.

`doubleSpendBreakOrLaterStart` drops that hypothesis and returns the later start as an outcome. The
note-creation results show that such a spend consumes a creation of its own, debited in its own
bundle. They take a publication-linked archive of chain nodes (`LinkedNode`) and certified bucket
sources (`CertifiedSource`) as inputs.

## Axiom census

`Tachyon/Axioms.lean` and the `Axioms.lean` file beside a module run `#print axioms` on each
headline theorem inside `#guard_msgs`. The build fails if a headline theorem gains an axiom. The
headline theorems depend on `propext`, `Classical.choice` and `Quot.sound` only, with no `sorryAx`.
