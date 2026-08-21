# Proof tree

The Tachyon proof tree is a graph of proof steps.
Each step accepts arbitrary witness inputs and up to two PCD inputs, performs computations and checks constraints, and emits a new PCD.

Multiple parties execute the proof tree.

- A **wallet** holds note data and keys
- A **sync service** holds nullifier values shared by the wallet and pool state proofs
- An **aggregator** merges stamps for pool efficiency

## Lifecycle

### Deriving nullifiers

A wallet proves a window of its note's nullifiers were correctly derived[^nullifiers].
`NfMasterSeed` witnesses the note and the proof-authorizing key `pak`, checks `note.pk == pak.derive_payment_key()` (which pins `nk`, and through `nk` the commitment `cm`), derives the master key `mk` and `cm`, and emits an `NfMasterHeader` carrying `(cm, mk)`. `nk` never leaves the step.
`NfDerive` consumes that seed. It witnesses the window's group base, the range `[epoch_start, epoch_end)` to export, and the range sequence; runs four sponges over $(\texttt{Tachyon-NfDerive}, \mathsf{mk}, w)$ to squeeze the window's 16 nullifiers natively; and binds the sequence to the range's members with one opening at a free challenge (below).
`NullifierFuse` concatenates two adjacent nullifier sequences into one, requiring the same `cm` and contiguity (`right.epoch_start == left.epoch_end`).
The result is a `NullifierDerivation` proving the range `[epoch_start, epoch_end)` commits to the genuine nullifiers of the note identified by `cm`, surfacing `nf_start` and `nf_last` as its boundary members.

### Bootstrapping a spendable

A spendable starts when `SpendableInit` consumes a `NullifierDerivation` covering the creation epoch.
It witnesses `(pre_cm_anchor, creation_set, creation_epoch, present_nf)` and the covering read's polynomials: a 1-wide read at the creation epoch forces `present_nf` to the range's genuine member there, it takes `cm` from the range header, checks `cm` is among the creation stamp's tachygrams[^tachygrams], and emits a `SpendableHeader` carrying `(cm, (creation_epoch, present_nf), anchor)` with `anchor = pre_cm_anchor.next_stamp(creation_epoch, creation_commit)`, the position immediately after the creation stamp, advanced by each lift.
`pre_cm_anchor` is a free witness, so the anchor binds only downstream: lift adjacency threads it to the eventual spend anchor, which consensus checks for chain membership, and a chain node's preimage fixes the real predecessor, the real creation epoch (pinning which epoch is read), and the real cm-stamp.

`SpendableBatch` bootstraps from a `Summary` covering the creation instead: membership proves `cm` inside the summarized run, exclusion proves the note unspent anywhere in it, the same 1-wide read pins `present_nf`, and the spendable emerges at the run's terminal anchor.
`SpendableAdvance` then advances it over adjacent same-epoch summaries with one exclusion query each.

### Maintaining a spendable

Maintaining the spendable means advancing its anchor forward over `ArbitraryUnspent` segments while proving the crossed nullifiers absent.
The sync service produces `ArbitraryUnspent` segments without ever holding the note, its `cm`, or `psi`: the values a segment tests are arbitrary field elements as far as its own proof is concerned, and only `UnspentBind` attributes them to a derivation.
`UnspentSeed` absorbs one stamp at a given absolute epoch and proves a wallet-supplied nullifier was absent from that stamp's tachygram set; the resulting `ArbitraryUnspent` crosses no epoch boundary, so `epoch_start == epoch_last` and the tested nullifier is its single `elapsed` member.
A block that publishes no stamp advances no anchor, so a stampless span needs no segment and no proof work.
`UnspentFuse` composes two contiguous ranges that share a junction epoch (`right.epoch_start == left.epoch_last`): it concatenates their `elapsed` histories, keeping the junction member once, at adjacent anchors.
`EndEpochUnspentSeed` is the segment for the boundary itself: it folds the epoch tick from a witnessed epoch-terminal anchor, its two `elapsed` members being the epochs it leaves and enters, so `epoch_last == epoch_start + 1`.
A boundary is therefore a link like any other, and `UnspentFuse` composes it with its neighbours on both sides; an epoch that published nothing is simply two crossings with no stamp segment between them.

The per-stamp steps have summarized counterparts over shared epoch evidence.
A `Summary` accumulates an ordered run of one epoch's stamps into a single set commitment welded to the anchor (`SummarySeed`, `SummaryAdvance`); summaries are note-independent, so anyone can build and publish them.
`UnspentBatch` births the lineage from a summary with one exclusion query against the whole accumulated set; `UnspentAdvance` advances it over an adjacent same-epoch summary the same way; `UnspentEpochLift` crosses a boundary on the outgoing epoch's terminal summary, appending the incoming epoch's member and folding the boundary anchor.
One query per summary replaces one per stamp, and a crossing replaces a seed and a fuse.

`UnspentBind` binds a sync-built `ArbitraryUnspent` to genuine derivation. It is wallet-side: it consumes the `ArbitraryUnspent` and a `NullifierDerivation` covering its span, and reads that span out of the range, so every member of `elapsed` up to its tip is a genuine nullifier of the note.
It emits an `Unspent` carrying the span's boundary nullifiers, anchors and epochs, and the note's `cm`.

`SpendableLift` is wallet-side and witness-free: it consumes a `SpendableHeader` and an `Unspent`.
It checks the verified segment's `cm` equals the spendable's (so the absence-proven nullifiers are this note's, and the value cannot drift), the segment's `nf_start` equals the spendable's `present_nf` (continuity), and the segment's `anchor_prev` equals the spendable's anchor (adjacency).
It advances to the segment's `nf_last` and `anchor_last`, threading `cm` unchanged.
A single lift can consume an arbitrarily long composed `ArbitraryUnspent`, including one that crosses many epoch boundaries.
A lineage resting on its epoch's terminal anchor lifts the same way: the boundary tick is a link, so a segment can open on it.

### Spending

To spend, the wallet runs `SpendBind`.
It consumes the `SpendableHeader` and a `NullifierDerivation` covering the current and next epochs, and witnesses the next-epoch nullifier `nf_next`.
It requires `range.cm == spendable.cm`, then confirms the published pair with a 2-wide read at the lineage's epoch: `present_nf` is the read's first member and `nf_next` its second.
Because `present_nf` is threaded from the lineage, the read is taken at the lineage's current epoch, and `nf_next` is forced to the genuine nullifier of the epoch after it.
Nonzero guards close the `nf == 0` degenerate.
The output `SpendHeader` carries `cm`, the confirmed pair `(present_nf, nf_next)`, and the threaded anchor; it carries no curve points.

`SpendStamp` consumes that `SpendHeader` and witnesses the note and the action fields.
It requires `note.commitment() == cm`, so the witnessed note is the spendable lineage's note: the value commitment `cv` then commits to the minted value[^notes].
It derives the action digest from `cv` and the randomized action key `rk`, and emits a `StampHeader` whose tachygram set contains both nullifiers and whose anchor is threaded from the spend.

An output operation splits the same way, into `OutputBind` and `OutputStamp`.
`OutputBind` witnesses the new note and derives its tachygram pair, the note commitment `cm` and the padding tachygram `pad`, both from the same note fields[^tachygrams]; the resulting `OutputHeader` carries the pair and nothing else.
`OutputStamp` re-witnesses the note against `cm`, adds value-randomness, action-randomness, and an anchor, and emits a single-action `StampHeader` whose tachygram set is the pair. The wallet typically anchors each output at the same height as the transaction's spends so the merge can proceed without an intervening lift.

A transaction with multiple spend and output stamps composes them with `MergeStamp`.
The output is a single `StampHeader` whose multisets are the union of the two inputs' at the shared anchor.

After the transaction stamp is fully composed, the wallet may run `StampLift` over an `AnchorChain` segment to advance the stamp's anchor toward the present tip before publication.

On publication the bundle carries the action descriptors, tachygrams, anchor, and the stamp proof.
Validators reconstruct the action-set and tachygram-set commitments from those published bundles, check the proof against the reconstructed values, and confirm the anchor against the consensus chain.

After publication, an aggregator combines `StampHeader`s from independently-proven bundles into a single **aggregate**[^aggregation] whose proof can stand in for many transactions' worth of stamps, cutting per-transaction verification cost downstream.
Each input is anchored at whatever height its wallet chose, so the aggregator obtains an `AnchorChain` segment per input and runs `StampLift` to bring every input onto a common later anchor.
`MergeStamp` then fuses the aligned stamps pairwise into a single `StampHeader` whose multisets are the union of all the inputs'.
The aggregated stamp has the same shape as any other, so it is itself eligible for further aggregation; aggregators stack to fold many published transactions into one stamp, and miners typically integrate the aggregator role into block production.

## Roles

The wallet runs every step that touches the note's commitment or master key.
It derives its nullifier windows (`NfMasterSeed`, `NfDerive`, `NullifierFuse`), derives spendable status from its own derivation (`SpendableInit`, or `SpendableBatch` and `SpendableAdvance` over summaries), binds and lifts over sync-built segments (`UnspentBind`, `SpendableLift`), and produces spend and output stamps (`SpendBind`, `SpendStamp`, `OutputBind`, `OutputStamp`).

The sync service holds the per-epoch nullifier values the wallet shared and pool history.
It builds the shared epoch summaries (`SummarySeed`, `SummaryAdvance`) and produces the `ArbitraryUnspent` segments that carry the spendable forward (`UnspentBatch`, `UnspentAdvance`, `UnspentEpochLift` over summaries; `UnspentSeed`, `EndEpochUnspentSeed`, `UnspentFuse` per stamp), then hands the composed segment to the wallet to bind and lift over; it never sees a note, `cm`, `psi`, or `mk`.

The aggregator works only with published `StampHeader`s.
It aligns anchors with `StampLift` over `AnchorChain` segments (`AnchorSeed`, `AnchorFuse`) and fuses with `MergeStamp`.

| step | wallet | sync service | aggregator |
| ---- | ------ | ------------ | ---------- |
| AnchorSeed | possible | yes | yes |
| AnchorFuse | possible | yes | yes |
| UnspentSeed | possible | yes | no |
| EndEpochUnspentSeed | possible | yes | no |
| UnspentFuse | possible | yes | no |
| SummarySeed | possible | yes | no |
| SummaryAdvance | possible | yes | no |
| UnspentBatch | possible | yes | no |
| UnspentAdvance | possible | yes | no |
| UnspentEpochLift | possible | yes | no |
| NfMasterSeed | yes | no | no |
| NfDerive | yes | no | no |
| NullifierFuse | yes | no | no |
| UnspentBind | yes | no | no |
| SpendableInit | yes | no | no |
| SpendableBatch | yes | no | no |
| SpendableAdvance | yes | no | no |
| SpendableLift | yes | no | no |
| SpendBind | yes | no | no |
| OutputBind | yes | no | no |
| OutputStamp | yes | no | no |
| SpendStamp | yes | no | no |
| MergeStamp | yes | no | yes |
| StampLift | yes | possible | yes |

## Soundness

The subsections below walk each subtree bottom-up: the chain segments that act as primitives, then the `ArbitraryUnspent` segments and the derivation window that consume them, then the binding at `UnspentBind`, the spendable lineage, then spend binding and stamps.

### Anchor segments

`AnchorSeed`, `UnspentSeed`, and `EndEpochUnspentSeed` each witness a predecessor anchor and prove one anchor step from it.
`AnchorFuse` composes adjacent segments by checking endpoint equality; `UnspentFuse` additionally concatenates the two halves' `elapsed` histories.
A segment ties to real chain history only through a consensus-published stamp whose anchor matches an end-of-block value, emitted at `StampLift`. `SpendableInit`'s anchor closes the same way without a segment: the private spendable's anchor reaches consensus once it is spent into a stamp.

### ArbitraryUnspent composition

An `ArbitraryUnspent` is a contiguous range bracketed by `anchor_prev` and `anchor_last`, with boundary pairs `(epoch_start, nf_start)` and `(epoch_last, nf_last)`, plus `elapsed` (one nullifier coefficient per epoch covered over `[epoch_start, epoch_last]`, in Horner order: `nf_start` at the top degree, the present `nf_last` at degree $0$)[^nullifiers]. The member count is `epoch_last - epoch_start + 1`.
A sequence is never empty and its members are nonzero, so the commitment never falls on the identity point. `nf_start` is the rank pin: guarded nonzero at both seeds and threaded by the fuse, it fixes the announced span as the exact rank, which commit-equality alone bounds only from above.
`UnspentSeed` produces a within-epoch `ArbitraryUnspent` for one stamp's worth of anchor advance: `epoch_start == epoch_last`, and the nullifier it just non-membership-checked is the single member, hence both `nf_start` and `nf_last`.
`EndEpochUnspentSeed` produces the other base case, the epoch boundary itself. It folds a witnessed epoch-terminal anchor through the cross-epoch domain and emits the tick's output as `anchor_last`, with `epoch_last == epoch_start + 1` and a two-member `elapsed`, the nullifier tested in the epoch being left over the one tested in the epoch entered. There is no exclusion to prove; that the witnessed predecessor really is its epoch's terminal anchor rests on consensus anchor membership of the eventual spend, since the tick of a short anchor is not a value consensus recomputes.
`UnspentFuse` composes two contiguous ranges sharing a junction epoch (`right.epoch_start == left.epoch_last`) at adjacent anchors (`left.anchor_last == right.anchor_prev`). Writing $k_R$ for the right half's member count, the concat confirms

$$C(X) = X^{k_R - 1}\,L(X) + R(X) - [\texttt{left.nf\_last}]\,X^{k_R - 1}$$

for the witnessed `combined` $C$, left $L$, and right $R$, at a Fiat-Shamir challenge: both halves hold the junction member, and the monomial removes the double-counted one. At a one-member right it degenerates to $C = L$.
Every seam is intra-epoch, because a crossing arrives as a segment of its own rather than as a property of the merge, so this concatenation is the only sequence relation the composition needs.
$L$, $R$, the monomial's coefficient and its exponent are all bound before the challenge, by the recursive verification of the two input PCDs and their headers; because the identity is linear in $L$ and $R$, that prior binding is what makes the concatenation sound. The junction agreement (`left.nf_last == right.nf_start`) is well-formedness only: a consistent pair of lies yields a wrong `elapsed`, which `UnspentBind` rejects.
A crossing's absolute epoch is consensus-tied where the crossing is built rather than where it merges: `EndEpochUnspentSeed` folds its witnessed epoch through the cross-epoch domain, and a wrong epoch yields an anchor the published sequence does not contain.

### Epoch summaries

A `Summary` carries `(epoch, anchor_prev, anchor_last, acc_commit)`: an ordered run of one epoch's stamps whose tachygram sets fold into one accumulator while the anchor absorbs the same commitments.
`SummarySeed` births a summary from one stamp, structurally `AnchorSeed` with the stamp's set commitment carried on the header; every witness is unconstrained, as at every seed.
`SummaryAdvance` folds the next stamp in: it binds the witnessed accumulator to the header by commit-equality, confirms the extension by a product opening (a product of root-encoded set polynomials is the root polynomial of the multiset union), and advances `anchor_last` by the same `stamp.commit()`, welding accumulator to anchor.
Summary boundaries are prover-chosen and soundness-irrelevant: lineage adjacency forces a consumer through every stamp link regardless of cuts.

`UnspentBatch` births an `ArbitraryUnspent` from a summary: one opening proves the tested value absent from the whole accumulated set ($\mathsf{nf} \notin \mathsf{summary}$ exactly when the accumulator is nonzero at $\mathsf{nf}$), and the summary's bracket becomes the segment's anchors.
`UnspentAdvance` advances the lineage over an adjacent same-epoch summary (`lineage.anchor_last == summary.anchor_prev`, `summary.epoch == lineage.epoch_last`) with the same single query.
`UnspentEpochLift` crosses a boundary on the outgoing epoch's terminal summary: the same checks and query, the Horner append of the incoming member, and the boundary fold `summary.anchor_last.next_epoch(next)`; a cut short of the terminal anchor folds to an anchor consensus never published. The appended member is freely witnessed, as at every crossing, and `UnspentBind` discharges it.
`SpendableBatch` and `SpendableAdvance` consume summaries the same way, membership placing the creation inside the run and exclusion clearing it; the `summary.epoch == creation_epoch` guard transfers the anchor's epoch binding to the read.

Summaries root unbound like every seed and need no external authentication: a consuming lineage splices their links by anchor equality at both endpoints and closes at its own spend, where consensus anchor membership forces the whole spliced chain.
A dishonest evidence builder can only make lineages unspendable, never make a spent note pass as unspent, and anyone can rebuild the summaries from public data.

### Derivation window

`NfMasterSeed` is the only seed. It binds the master key to the note: `note.pk == pak.derive_payment_key()` pins `nk`, and the note commitment digests `nk` (through `pk`) and `psi`, so the derived `mk = Poseidon(psi, nk)` is consistent with the `cm` the seed threads forward.
`NfDerive` threads `mk` from that header rather than witnessing it, squeezes the window's nullifiers natively, and binds the witnessed sequence to them at a fresh challenge $z$:

$$g(z) = \sum_{j < K} \mathsf{nf}_{\texttt{epoch\_start}+j}\, z^{\,K-1-j}$$

for $K$ the exported range's width. Both sides have degree below $K$ and $z$ is free, so the single opening forces every coefficient of $g$ to the genuine nullifier; `nf_start`, guarded nonzero at the top, pins the rank. The base and range are range-checked but otherwise unbound: the range is labelled with its epochs, so a different base yields a correct range for a different span.
`NullifierFuse` binds both sequences and their concatenation by commit-equality and confirms the Horner shift $M(X) = X^{k_R} L(X) + R(X)$ for $k_R$ right's header-fixed member count, requiring the same `cm` and contiguity.
So a `NullifierDerivation` is a sound proof that a contiguous epoch range commits to the genuine nullifiers of the note identified by `cm`.

### Binding unspent to derivation

`UnspentBind` consumes the sync's `ArbitraryUnspent` and a `NullifierDerivation` covering its span (`deriv.epoch_start <= epoch_start`, `epoch_last < deriv.epoch_end`), not one aligned to it.
It binds `elapsed` to the `ArbitraryUnspent` header and the covering sequence $g$ to the derivation header, both by commit-equality, and reads `elapsed` out of $g$ over `[epoch_start, epoch_last + 1)`. For a read of `members` consecutive coefficients sitting `margin` coefficients above $g$'s degree 0, the read confirms

$$z^{\mathrm{CAP}-\texttt{margin}}\,g(z) = z^{\mathrm{CAP}+\texttt{members}}\,(\texttt{older}(z) - 1) + z^{\mathrm{CAP}}\,\texttt{read}(z) + (\texttt{tail}(z) - 1)$$

at a challenge over all four commitments, with free margins `older` above the band and a cap-shifted `tail` below it. $\mathrm{CAP}$ is the witnessable coefficient cap, so the three bands are disjoint: the identity forces the read's coefficients onto $g$'s, and the margins absorb whatever $g$ carries outside the band. The rank pin on $g$ places the bands.
So `elapsed`'s members are exactly the derived nullifiers over the unspent's epochs.
Of the boundary caches, `nf_last` is `elapsed`'s degree-0 coefficient, pinned here by a repeat opening. `nf_start` is the non-extractable top coefficient: it equals `nf_last` for a single-epoch segment, checked here, and is otherwise forced at the lift.
The derivation's `cm` is stamped onto the `Unspent`.

### Spendable lineage

`SpendableInit` is the lineage's only seed and is wallet-only.
It witnesses the creation stamp's tachygrams, the anchor running into the creation stamp, the creation epoch, and the starting-epoch nullifier `present_nf`.
It takes `cm` from the range header and binds the note to the pool (`cm` in `creation_set`), which pins the whole note to the real minted note.
It emits `SpendableHeader(cm, (creation_epoch, present_nf), anchor)`, where `anchor` folds the creation epoch onto the free-witnessed `pre_cm_anchor`; a wrong epoch or predecessor lands the anchor off the published sequence, so consensus anchor membership of the eventual spend forces both.
`present_nf` is forced to the range's member at the creation epoch by a 1-wide read, whose challenge absorbs it; each lift then requires an `Unspent`'s `nf_start` to equal it, keeping the lineage on the note's derived nullifiers.

`SpendableLift` advances the lineage over an `Unspent`.
It threads `cm` by equality (`unspent.cm == spendable.cm`), so every consumed segment belongs to the lineage's one note and the spent value cannot drift to a different same-`mk` note.
Combined with the `nf_last` opening at `UnspentBind` (which makes each new `present_nf` itself genuine), a lineage cannot skip an epoch or splice in another note.

Continuity holds through the boundary pair: `unspent.nf_start == spendable.present_nf` and `unspent.epoch_start == spendable.epoch`. This is where `nf_start`, the cache no opening isolates, is pinned.
The nullifiers are both PRF outputs of the note's sponge, so value-equality alone already forces the same note and the same epoch; carrying the epoch makes that a checked equality per lift, and it is what lets the lineage state its position without a derivation in hand.
The anchor adjacency check (`unspent.anchor_prev == spendable.anchor`) welds the segment to the lineage's current position.

A lineage resting on its epoch's terminal anchor is not a special position: the segment it lifts over opens with the boundary tick, so adjacency holds against the anchor it already sits on.

That the anchor a crossing folds from really is its epoch's terminal anchor is not checked and cannot be, being a negative claim about what was published.
Ticking a mid-epoch anchor lands off the published sequence, which no later link rejoins, so consensus anchor membership of the eventual spend rejects it.
No coverage is skipped: the crossing leaves the epoch at its terminal anchor, and `present_nf`'s absence up to that anchor was proven by whatever placed the lineage there.

### Spend binding

Spending a note publishes two nullifiers, one for the current epoch and one for the next, both pinned to the note's genuine derivation.
`SpendBind` consumes the `SpendableHeader` and a `NullifierDerivation` covering the current and next epochs, witnesses `nf_next`, and requires `range.cm == spendable.cm`.
A 2-wide read confirms the pair: `present_nf` is threaded from the lineage, so it fixes where the read is taken, and `nf_next` is the band's second member. The read's challenge absorbs both scalars; left out, a member is solvable after the challenge is known.
Each published nullifier must be nonzero, or it would collide with the note's own `cm` in the tachygram scan.
No note witness is needed here: the range and the lineage are already tied to the same note by their two `cm` fields, bound where the range was derived and at `SpendableInit` respectively.
The output `SpendHeader` threads `cm`, the confirmed pair, and the anchor, and carries no curve points.

`SpendStamp` completes the publication: it re-witnesses the note against the header's `cm`, derives the value commitment `cv` and the randomized action key `rk`, and commits the one-action set alongside the two-element tachygram set.
Requiring `note.commitment() == cm` rejects a phantom note reusing the same `psi`, and so the same nullifiers, while carrying a different value and hence a different `cm`.
The note is witnessed only in this terminal step, so it never propagates.

The two complementary `cm` checks pin value two independent ways. `cm == note.commitment()` ties `cm` to the note by `Poseidon` collision-resistance (the spender must know `rcm`, `pk`, `value`, `psi`). `spendable.cm == cm` ties it to the lineage, which the creation stamp proved minted. Together they bind the action's value commitment to the note actually being spent. Publishing both nullifiers lets consensus apply the spend across an epoch transition that may occur between proof construction and inclusion.

The note's age never becomes public. The lineage carries only a single current nullifier, not a polynomial with a consumed offset, and the published pair sits at the constant epochs of the live range, so no step reads a position that would leak how long the note has existed.

### Stamp construction

A stamp commits to two multisets, an action-digest set and a tachygram set[^tachygrams].
`OutputBind` derives the output's tachygram pair from one note, the commitment `cm` and the padding tachygram `pad`, so both are fixed before any action material exists. Each is nonzero-guarded, and the pad's preimage is the note opening rather than `cm`, which is what stops an observer pairing the two off in the published set[^tachygrams].
`OutputStamp` then derives a value commitment, action verification key, and action digest from a re-witnessed note, value-randomness, and action-randomness; constraints tie the note to the header's `cm` and reject over-range note values. No key material is witnessed: an output's `rk` is a fresh randomizer's public key, and the recipient's payment key rides inside `cm` where the sender cannot be asked to prove anything about it[^keys].
`SpendStamp` mirrors it on the spend side: it re-witnesses the note against the `SpendHeader`'s `cm`, derives the value commitment, action verification key, and action digest, and emits a stamp whose one-action digest set, two-nullifier tachygram set, and threaded anchor follow. The nullifier pair it publishes was already confirmed against the covering range at `SpendBind`.
`MergeStamp` fuses two stamps by checking anchor equality and confirming each output set is the union of the two inputs': it witnesses the merged sets and enforces, for each, that the merged set polynomial is the product of the input set polynomials.

### Stamp anchor

`OutputStamp` is the only stamp-producing step that takes an anchor as direct witness: an output operation has no prior chain state to thread from.
The other stamp-producing steps thread the anchor from a validated spendable through `SpendBind`/`SpendStamp`, equality-constrain the two inputs' anchors (`MergeStamp`), or advance over an `AnchorChain` segment whose start matches the stamp's prior anchor (`StampLift`).
Consensus verifies the published anchor against the chain before accepting the stamp.

### Rerandomization at trust boundaries

Every stamp-producing step rerandomizes its proof before releasing it: `prove_output`, `prove_spend`, and `prove_merge` each rerandomize the PCD they built. This is obligatory rather than cosmetic.

A PCD proof is a commitment to its own witness data. Two proofs built from overlapping private inputs are correlated as group elements, even when their public headers reveal nothing. The proof a wallet holds after `SpendBind` and the proof it publishes in a stamp share a lineage, so an observer holding both could link them, and an aggregator that merges two stamps sees both inputs directly.

A stamp crosses a trust boundary at exactly these points. A wallet hands an autonome to the p2p network; an aggregator hands a merged stamp onward while retaining the inputs it merged. Rerandomizing at each handoff replaces the proof with an unrelated one that verifies against the same header, so the released artifact carries no correlation back to the private lineage that produced it, and none forward to a later release of the same lineage.

The rule is that a proof leaving the process that built it is rerandomized first. Intermediate PCDs that stay inside a wallet, such as a derivation window or an `ArbitraryUnspent` segment, do not need it: nothing outside the wallet ever observes them.

## Simple transaction

A transaction with one spend and one output, where the spendable was bootstrapped in a previous epoch and lifted over an `ArbitraryUnspent` crossing an epoch boundary before the spend.

```mermaid
flowchart TB
  subgraph derive [nullifier derivation]
    w_seed[/note, pak/]
    s_seed[NfMasterSeed]
    w_window[/group_base, epoch_start, epoch_end, seq/]
    s_window[NfDerive]
    s_dfuse[NullifierFuse]
    nf_range((NullifierDerivation))
  end

  subgraph spendable [spendable advance]
    w_init[/pre_cm_anchor, creation_set, creation_epoch, present_nf/]
    s_init[SpendableInit]
    unspent_in((ArbitraryUnspent))
    s_unspentbind[UnspentBind]
    s_lift[SpendableLift]
  end

  subgraph spend_action [spend action]
    w_bind[/nf_next/]
    s_bind[SpendBind]
  end

  subgraph merge [transaction assembly]
    w_stamp[/note, rcv, alpha, pak/]
    s_spendstamp[SpendStamp]
    w_outbind[/note/]
    s_outbind[OutputBind]
    w_output[/rcv, alpha, note, anchor/]
    s_output[OutputStamp]
    s_merge[MergeStamp]
  end

  stamp_out((StampHeader))

  w_seed --> s_seed
  s_seed -->|NfMasterHeader| s_window
  w_window --> s_window
  s_window -->|NullifierDerivation| s_dfuse
  s_dfuse --> nf_range

  nf_range -->|NullifierDerivation| s_init
  w_init --> s_init
  nf_range --> s_unspentbind
  unspent_in --> s_unspentbind
  s_init -->|SpendableHeader| s_lift
  s_unspentbind -->|Unspent| s_lift
  s_lift -->|SpendableHeader| s_bind

  w_bind --> s_bind
  nf_range -->|NullifierDerivation| s_bind
  s_bind -->|SpendHeader| s_spendstamp
  w_stamp --> s_spendstamp

  w_outbind --> s_outbind
  s_outbind -->|OutputHeader| s_output
  w_output --> s_output
  s_spendstamp -->|StampHeader| s_merge
  s_output -->|StampHeader| s_merge
  s_merge --> stamp_out
```

The single `SpendableLift` consumes one composed `Unspent` (potentially crossing many epoch boundaries); threading `cm` chains the lineage's binding to the note through every advance.

## Focused subgraphs

### Stamp anchor advance

```mermaid
flowchart LR
  sh_in((StampHeader))
  w_seed[/start, epoch, stamp_commit/]
  s_seed[AnchorSeed]
  w_next[/start, epoch, stamp_commit/]
  s_next[AnchorSeed]
  s_fuse[AnchorFuse]
  s_lift[StampLift]
  sh_out((StampHeader))

  w_seed --> s_seed
  w_next --> s_next
  s_seed -->|AnchorChain| s_fuse
  s_next -->|AnchorChain| s_fuse
  sh_in --> s_lift
  s_fuse -->|AnchorChain| s_lift
  s_lift --> sh_out
```

### ArbitraryUnspent composition across epochs

```mermaid
flowchart LR
  w_seed[/anchor_prev, epoch, stamp_tg_set, nf/]
  s_useed[UnspentSeed]
  w_cross[/anchor_prev, epoch_prev, nf_prev, nf/]
  s_cross[EndEpochUnspentSeed]
  w_ufuse[/left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq/]
  s_ufuse[UnspentFuse]
  w_next[/anchor_prev, epoch, stamp_tg_set, nf/]
  s_unext[UnspentSeed]
  w_ufuse2[/left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq/]
  s_ufuse2[UnspentFuse]
  unspent_out((ArbitraryUnspent))

  w_seed --> s_useed
  w_cross --> s_cross
  w_next --> s_unext
  s_useed -->|ArbitraryUnspent| s_ufuse
  s_cross -->|ArbitraryUnspent| s_ufuse
  w_ufuse --> s_ufuse
  s_ufuse -->|ArbitraryUnspent| s_ufuse2
  s_unext -->|ArbitraryUnspent| s_ufuse2
  w_ufuse2 --> s_ufuse2
  s_ufuse2 --> unspent_out
```

### Lineage stream over epoch summaries

```mermaid
flowchart LR
  w_sseed[/anchor_prev, epoch, stamp_commit/]
  s_sseed[SummarySeed]
  w_sadv[/acc, extended, stamp/]
  s_sadv[SummaryAdvance]
  summary_b((Summary))
  summary_c((Summary))
  w_batch[/nf, summary_set/]
  s_ubatch[UnspentBatch]
  w_adv[/summary_set/]
  s_uadv[UnspentAdvance]
  w_elift[/summary_set, elapsed_seq, extended_seq, nf_next/]
  s_uelift[UnspentEpochLift]
  unspent_out2((ArbitraryUnspent))

  w_sseed --> s_sseed
  s_sseed -->|Summary| s_sadv
  w_sadv --> s_sadv
  s_sadv -->|Summary| s_ubatch
  w_batch --> s_ubatch
  s_ubatch -->|ArbitraryUnspent| s_uadv
  summary_b --> s_uadv
  w_adv --> s_uadv
  s_uadv -->|ArbitraryUnspent| s_uelift
  summary_c --> s_uelift
  w_elift --> s_uelift
  s_uelift --> unspent_out2
```

## Headers

| Header | Fields |
| ------ | ------ |
| AnchorChain | (start, end) |
| ArbitraryUnspent | (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_last, nf_last), anchor_last) |
| Unspent | (cm, anchor_prev, (epoch_start, nf_start), (epoch_last, nf_last), anchor_last) |
| Summary | (epoch, anchor_prev, anchor_last, acc_commit) |
| NfMasterHeader | (cm, mk) |
| NullifierDerivation | (cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last)) |
| SpendableHeader | (cm, (epoch, present_nf), anchor) |
| OutputHeader | (cm, pad) |
| SpendHeader | (cm, present_nf, nf_next, anchor) |
| StampHeader | (action_commit, stamp_tg_commit, anchor) |

## Steps

| Step | Left | Right | Witness | Output |
| ---- | ---- | ----- | ------- | ------ |
| AnchorSeed | — | — | start, epoch, stamp_commit | AnchorChain |
| AnchorFuse | AnchorChain | AnchorChain | — | AnchorChain |
| UnspentSeed | — | — | anchor_prev, (epoch, nf), stamp_tg_set | ArbitraryUnspent |
| EndEpochUnspentSeed | — | — | anchor_prev, (epoch_prev, nf_prev), nf | ArbitraryUnspent |
| UnspentFuse | ArbitraryUnspent | ArbitraryUnspent | left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq | ArbitraryUnspent |
| SummarySeed | — | — | anchor_prev, epoch, stamp_commit | Summary |
| SummaryAdvance | Summary | — | acc, extended, stamp | Summary |
| UnspentBatch | Summary | — | nf, summary_set | ArbitraryUnspent |
| UnspentAdvance | ArbitraryUnspent | Summary | summary_set | ArbitraryUnspent |
| UnspentEpochLift | ArbitraryUnspent | Summary | summary_set, elapsed_seq, extended_seq, nf_next | ArbitraryUnspent |
| UnspentBind | ArbitraryUnspent | NullifierDerivation | elapsed_seq, g, older, tail | Unspent |
| NfMasterSeed | — | — | note, pak | NfMasterHeader |
| NfDerive | NfMasterHeader | — | group_base, epoch_start, epoch_end, seq | NullifierDerivation |
| NullifierFuse | NullifierDerivation | NullifierDerivation | left_seq, merged_seq, right_seq | NullifierDerivation |
| SpendableInit | NullifierDerivation | — | pre_cm_anchor, creation_set, creation_epoch, present_nf, g, older, tail | SpendableHeader |
| SpendableBatch | NullifierDerivation | Summary | creation_epoch, present_nf, g, older, tail, summary_set | SpendableHeader |
| SpendableAdvance | SpendableHeader | Summary | summary_set | SpendableHeader |
| SpendableLift | SpendableHeader | Unspent | — | SpendableHeader |
| SpendBind | SpendableHeader | NullifierDerivation | g, older, tail, nf_next | SpendHeader |
| OutputBind | — | — | note | OutputHeader |
| OutputStamp | OutputHeader | — | rcv, alpha, note, anchor | StampHeader |
| SpendStamp | SpendHeader | — | note, rcv, alpha, pak | StampHeader |
| MergeStamp | StampHeader | StampHeader | (action_set, tachygram_set) × left, merged, right | StampHeader |
| StampLift | StampHeader | AnchorChain | — | StampHeader |

[^nullifiers]: See [Nullifiers](./nullifiers.md) for the nullifier sponge, the scalar `psi` seed, and the delegated absence sequence.
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the per-stamp multiset polynomial and its Pedersen commitment.
[^notes]: See [Notes](./notes.md) for the four-field note structure and its commitment.
[^keys]: See [Keys](./keys.md) for the wallet key hierarchy and the per-action derivations.
[^aggregation]: See [Aggregation](./aggregation.md) for the autonome/aggregate/adjunct lifecycle and the miner-side stripping that realizes the chain-cost reduction.
