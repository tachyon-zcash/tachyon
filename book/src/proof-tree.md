# Proof tree

The Tachyon proof tree is a graph of proof steps.
Each step accepts arbitrary witness inputs and up to two PCD inputs, performs computations and checks constraints, and emits a new PCD.

Multiple parties execute the proof tree.

- A **wallet** holds note data and keys
- A **sync service** holds nullifier values shared by the wallet and pool state proofs
- An **aggregator** merges stamps for pool efficiency

## Lifecycle

### Deriving nullifiers

A wallet proves a contiguous run of its note's per-epoch nullifiers were correctly GGM-derived[^nullifiers].
The derivation descends a 64-ary tree of key schedules: a node's schedule keys a child cipher whose 64 whitened outputs are its children's schedules, and a depth-2 node's outputs are the note's nullifiers for a block of 64 consecutive epochs.
`NfMasterSeed` witnesses the note, the proof-authorizing key `pak`, and a part index; it checks `note.pk == pak.derive_payment_key()` (which pins `nk`, and through `nk` the commitment `cm`), derives one part of the master key `mk` from `psi` and `nk`, and emits an `NfMasterHeader` carrying that part, its index, and the note. The master key is split across two parts, each seeded on its own.
`NfMasterStep` reconciles a note's two parts and assembles `mk`, then proves one child chunk's key schedule out of it in a single trace-based step, emitting a depth-1 `NfPrefixHeader`.
`NfPrefixStep` descends one further level on a freely-witnessed chunk: it proves the chunk's child schedule out of the parent schedule and accumulates the chunk into the node index, so the leaf a walk reaches is pinned into the index even though each step's chunk is free.
`NullifierDerivationStep` expands a depth-2 node into a `NullifierDerivation`: its 64 leaf outputs are the nullifiers for epochs `[64·index, 64·index + 64)`, published as one coefficient-form sequence commitment `seq_commit` over that half-open range, alongside `cm`.
`NullifierFuse` shift-concatenates two adjacent derivations into one, requiring the same `cm` and contiguity (`right.epoch_start == left.epoch_end`).
The result is a `NullifierDerivation` proving the range `[epoch_start, epoch_end)` commits to the genuine `GGM(mk, ·)` leaves of the note identified by `cm`. It carries no boundary nullifiers: a consumer reads whatever single leaf or sub-range it needs from the sequence by coverage.

### Bootstrapping a spendable

A spendable starts when `SpendableInit` fuses a boundary-rooted `AnchorChain` with a `NullifierDerivation` covering the creation epoch.
It witnesses `((pre_epoch_anchor, pre_cm_anchor), creation_set, present_nf, creation_epoch)` and the derivation-slice polynomials: it confirms `present_nf` is the derivation's leaf at `creation_epoch` by coverage (a degree-0 opening of the covered tail), takes `cm` from the derivation header, checks `cm` is among the creation stamp's tachygrams[^tachygrams], requires the chain to root at `pre_epoch_anchor.next_epoch(creation_epoch)`, requires the cm-stamp to be the chain's final link, and emits a `SpendableHeader` carrying `(cm, present_nf, anchor)`.
Rooting the chain at `next_epoch(epoch)` pins the starting GGM leaf index to the consensus epoch: consensus anchor membership of the eventual spend anchor forces the boundary, and hence `epoch`, to be the real creation epoch. Without it a note spent in its creation epoch crosses no boundary, leaving the index a free witness.
The anchor is set initially to the position immediately after the creation stamp and advanced by each lift.

### Maintaining a spendable

Maintaining the spendable means advancing its anchor forward over `Unspent` segments while proving the crossed nullifiers absent.
The sync service produces `Unspent` segments without ever holding the note, its `cm`, or `psi`.
`UnspentSeed` absorbs one stamp at a given absolute epoch and proves a wallet-supplied nullifier was absent from that stamp's tachygram set; the resulting `Unspent` has crossed no epoch boundary, so its `elapsed` is empty and `epoch_start == epoch_end` with `nf_start == nf_end` the tested nullifier.
`EmptyBlockUnspentSeed` covers empty blocks.
`UnspentFuse` composes two contiguous ranges that share a junction epoch (`right.epoch_start == left.epoch_end`): it concatenates their `elapsed` histories and seam-binds the junction nullifier (`left.nf_end == right.nf_start`) at adjacent anchors.
`UnspentEpochFuse` crosses an epoch boundary: it advances the anchor across the boundary and splices the left range's completing tip `nf_end` into `elapsed`, so the crossing count grows by exactly one; either half may itself be a multi-epoch range.
An `Unspent` records its span as two absolute epoch endpoints, `epoch_start` and `epoch_end`; the crossing count is their difference.

`UnspentBind` binds a sync-built `Unspent` to genuine derivation. It is wallet-side: it consumes the `Unspent` and a `NullifierDerivation` that merely *covers* the unspent span, and proves the derivation's sequence contains exactly the `elapsed` crossings followed by the tip `nf_end` over the unspent's epochs. So every crossed nullifier and the tip are proven `GGM(mk, ·)` leaves.
It emits a `VerifiedUnspent` carrying the span's boundary epochs and nullifiers, its anchors, and the note's `cm`.

`SpendableLift` is wallet-side and witness-free: it consumes a `SpendableHeader` and a `VerifiedUnspent`.
It checks the verified segment's `cm` equals the spendable's (so the absence-proven nullifiers are this note's, and the value cannot drift), the segment's `nf_start` equals the spendable's `present_nf` (continuity), and the segment's `anchor_prev` equals the spendable's anchor (adjacency).
It advances to the segment's `nf_end` and `anchor_last`, threading `cm` unchanged.
A single lift can consume an arbitrarily long composed `Unspent`, including one that crosses many epoch boundaries.

### Spending

To spend, the wallet runs `SpendBind`.
It consumes the `SpendableHeader` and a `NullifierDerivation` covering the present and next epochs, and witnesses the present epoch and the derivation-slice polynomials.
It ties the derivation to the lineage by `deriv.cm == spendable.cm` (so no note witness is needed here), confirms the lineage's `present_nf` is the derivation's leaf at the present epoch by coverage (a degree-0 opening of the covered tail), and reads the following leaf `nf_next` as the next epoch's nullifier.
Nonzero guards close the `nf == 0` degenerate.
The output `SpendHeader` carries `cm`, the confirmed pair `(present_nf, nf_next)`, and the threaded anchor.

`SpendStamp` proves the spend's action, mirroring `OutputStamp`.
It consumes the `SpendHeader`, witnesses the note and the action material `(rcv, alpha, pak)`, requires `note.commitment() == cm` and `note.pk == pak.derive_payment_key()`, derives the value commitment `cv` and the randomized action verification key `rk`[^notes], and emits a `StampHeader` whose action digest follows from `(cv, rk)`, whose tachygram set is the pair `{present_nf, nf_next}` read off the `SpendHeader`, and whose anchor is threaded from the spend.

An output operation runs `OutputStamp` directly.
The step witnesses the new note, value-randomness, action-randomness, and an anchor; the wallet typically anchors each output at the same height as the transaction's spends so the merge can proceed without an intervening lift.
The resulting `StampHeader` is a single-action stamp committing to the new note's commitment as its sole tachygram.

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
It seeds and walks the private GGM tree (`NfMasterSeed`, `NfMasterStep`, `NfPrefixStep`, `NullifierDerivationStep`, `NullifierFuse`), derives spendable status from its own derivation (`SpendableInit`), binds and lifts over sync-built segments (`UnspentBind`, `SpendableLift`), and produces spend and output stamps (`SpendBind`, `OutputStamp`, `SpendStamp`).

The sync service holds the per-epoch nullifier values the wallet shared and pool history.
It produces the `Unspent` segments that carry the spendable forward (`UnspentSeed`, `EmptyBlockUnspentSeed`, `UnspentFuse`, `UnspentEpochFuse`) and hands the composed segment to the wallet to bind and lift over; it never sees a note, `cm`, `psi`, or `mk`.

The aggregator works only with published `StampHeader`s.
It aligns anchors with `StampLift` over `AnchorChain` segments (`AnchorSeed`, `EmptyBlockSeed`, `AnchorFuse`) and fuses with `MergeStamp`.

| step | wallet | sync service | aggregator |
| ---- | ------ | ------------ | ---------- |
| AnchorSeed | possible | yes | yes |
| EmptyBlockSeed | possible | yes | yes |
| AnchorFuse | possible | yes | yes |
| UnspentSeed | possible | yes | no |
| EmptyBlockUnspentSeed | possible | yes | no |
| UnspentFuse | possible | yes | no |
| UnspentEpochFuse | possible | yes | no |
| NfMasterSeed | yes | no | no |
| NfMasterStep | yes | no | no |
| NfPrefixStep | yes | no | no |
| NullifierDerivationStep | yes | no | no |
| NullifierFuse | yes | no | no |
| UnspentBind | yes | no | no |
| SpendableInit | yes | no | no |
| SpendableLift | yes | no | no |
| SpendBind | yes | no | no |
| OutputStamp | yes | no | no |
| SpendStamp | yes | no | no |
| MergeStamp | yes | no | yes |
| StampLift | yes | possible | yes |

## Soundness

The subsections below walk each subtree bottom-up: the chain segments that act as primitives, then the `Unspent` segments and the derivation chain that consume them, then the binding at `UnspentBind`, the spendable lineage, then spend binding and stamps.

### Anchor segments

`AnchorSeed`, `EmptyBlockSeed`, `UnspentSeed`, and `EmptyBlockUnspentSeed` each witness an `anchor_prev` and prove one anchor step.
`AnchorFuse` composes adjacent segments by checking endpoint equality; `UnspentFuse` additionally concatenates the two halves' `elapsed` histories.
A segment ties to real chain history only through a consensus-published stamp whose anchor matches an end-of-block value: `StampLift` emits that stamp directly, while a segment consumed by `SpendableInit` produces a private spendable whose anchor reaches consensus only once it is spent into a stamp.

### Unspent composition

An `Unspent` is a contiguous range bracketed by `anchor_prev` and `anchor_last`, with boundary pairs `(epoch_start, nf_start)` and `(epoch_end, nf_end)`, plus `elapsed` (one nullifier coefficient per epoch-boundary crossing in its span, forward-chronological, terminated by a sentinel coefficient $1$ at the crossing count)[^nullifiers]. `nf_start`/`nf_end` are the nullifiers at `epoch_start`/`epoch_end`; the crossing count is `epoch_end - epoch_start`.
The sentinel keeps the committed polynomial nonzero for every sequence, so the commitment never falls on the identity point, which the in-circuit point representation cannot hold; it also pins the sequence's exact length, which commit-equality alone bounds only from above.
`UnspentSeed` and `EmptyBlockUnspentSeed` produce within-epoch `Unspent`s for one stamp's worth of anchor advance: `elapsed` is empty (the sentinel constant $1$, committing to $\mathcal{G}_0$), `epoch_start == epoch_end`, and the nullifier they just non-membership-checked is both `nf_start` and `nf_end`.
`UnspentFuse` composes two contiguous ranges sharing a junction epoch (`right.epoch_start == left.epoch_end`) at adjacent anchors (`left.anchor_last == right.anchor_prev`): it concatenates their histories and seam-binds the junction nullifier (`left.nf_end == right.nf_start`). Writing $s$ for the left crossing count, the concat confirms

$$C(X) = L(X) + X^{s}\,(R(X) - 1)$$

for the witnessed `combined` $C$, left $L$, and right $R$, at a Fiat-Shamir challenge: the $-1$ cancels the left half's sentinel at degree $s$, the right half's first crossing takes its slot, and the right half's sentinel re-terminates the combined sequence; the seam-bind makes the shared junction epoch's nullifier unambiguous across the merge.
`UnspentEpochFuse` crosses an epoch boundary: it witnesses the two halves' nullifier polynomials and the combined result, advances the anchor via the cross-epoch domain, and splices the left range's completing tip between them.
Writing $p$ for the left tip `nf_end`, the splice confirms

$$C(X) = L(X) + X^{s}\,(p - 1) + X^{s+1}\,R(X)$$

at a Fiat-Shamir challenge: the spliced tip overwrites the left half's sentinel and the right half's sentinel re-terminates the combined sequence.
$L$ and $R$ are bound by the recursive verification of the two input PCDs, and the scalar $p$ is a left-header value bound likewise, all before the challenge; because the identity is linear in $L$, $R$, and $p$, that prior binding is what makes the splice sound.
The crossing epoch is the right half's `epoch_start`, which must be exactly one past the left tip, and folding it into the boundary anchor via the cross-epoch domain consensus-ties the absolute epoch.

### Derivation chain

`NfMasterSeed` is the chain's only seed and runs once per master-key part. It binds each part to the note: `note.pk == pak.derive_payment_key()` pins `nk`, and the note commitment digests `nk` (through `pk`) and `psi`, so a part derived from `psi` and `nk` is consistent with the `cm` the seed threads forward.
`NfMasterStep` reconciles a note's two parts (pinned to part indices $0$ and $1$, same note across both) and assembles `mk`, then proves one child chunk's key schedule out of `mk` as a committed cipher trace, accumulating the chunk into the emitted node index.
`NfPrefixStep` proves the next level's child schedule out of the parent schedule, which it binds to the parent's commitment before use, accumulating its free chunk into the node index; the index pins which leaf a walk reaches even though chunks are free.
`NullifierDerivationStep` expands the depth-2 node under the leaf domain and certifies its 64 outputs in evaluation form as the leaf polynomial $B$ (with $B(\zeta^p) = \texttt{nf}_{64\,\texttt{index}+p}$), then binds them to the published coefficient-form sequence $q$ homomorphically. A running-sum accumulator $A$ carries the geometric total $A(1) = \sum_p B(\zeta^p)\,\beta^p$ at a challenge $\beta$ derived from both commitments, and discharging $q$'s sentinel,

$$q(\beta) - \beta^{64} = A(1),$$

forces every published coefficient of $q$ to the genuine leaf by Schwartz-Zippel.
`NullifierFuse` witnesses the two sequences and their concatenation, binds each by commit-equality, and confirms the shift-concat at the constant offset `left.epoch_end - left.epoch_start`, requiring the same `cm` and contiguity.
So a `NullifierDerivation` is a sound proof that a contiguous epoch range commits to the genuine leaves of the note identified by `cm`.

### Binding unspent to derivation

`UnspentBind` consumes the sync's `Unspent` and a `NullifierDerivation` that merely *covers* the unspent span (`deriv.start <= unspent.start`, `unspent.end < deriv.end`), not one aligned to it.
It binds `elapsed` to the `Unspent` header and the derivation sequence $q$ to the `NullifierDerivation`, both by commit-equality. It first rebuilds the tested sub-sequence `nf_seq = elapsed ++ [nf_end]` (the crossings followed by the tip) as a shifted combination, its appended tip a left-header scalar fixed before the challenge. It then coverage-extracts `nf_seq` from $q$: writing `off = unspent.start - deriv.start` for the header-fixed coverage offset and `len` for `nf_seq`'s member count,

$$q(X) = \texttt{prefix}(X) + X^{\texttt{off}}\,\texttt{nf\_seq}(X) + X^{\texttt{off}+\texttt{len}}\,\texttt{suffix}(X) - X^{\texttt{off}} - X^{\texttt{off}+\texttt{len}}$$

at a Fiat-Shamir challenge: the two monomials cancel the `prefix` and `nf_seq` sentinels, and the sentinels pin each part's length, so with the header-fixed offsets the decomposition is unique.
This proves the crossings and the tip are exactly the derived `GGM(mk, ·)` leaves over the unspent's epochs: the tip nullifier is a genuine leaf, not a free value.
It reads the span's boundary nullifiers as degree-0 openings and threads the derivation's `cm`.

### Spendable lineage

`SpendableInit` is the lineage's only seed and is wallet-only.
It consumes a covering `NullifierDerivation` and witnesses the creation stamp's tachygrams, the anchors running into the creation stamp, the creation epoch, and the starting nullifier `present_nf`.
It takes `cm` from the derivation and binds the note to the pool (`cm` in `creation_set`), which pins the note to the real minted note; it confirms `present_nf` is the derivation's leaf at the creation epoch by coverage, so `present_nf` is a genuine leaf from the outset, tied to the consensus creation epoch by the boundary-rooted chain.
It emits `SpendableHeader(cm, present_nf, anchor)`.

`SpendableLift` advances the lineage over a `VerifiedUnspent` and is witness-free.
It threads `cm` by equality (`verified.cm == spendable.cm`), so every consumed segment belongs to the lineage's one note and the spent value cannot drift to a different same-`mk` note.
Continuity holds through nullifier values: `verified.nf_start == spendable.present_nf`.
Both are `GGM(mk, ·)` PRF outputs, so value-equality forces the same note and the same epoch; combined with the tip binding at `UnspentBind` (which makes each new `present_nf` itself a genuine leaf), a lineage cannot skip an epoch or splice in another note.
The anchor adjacency check (`verified.anchor_prev == spendable.anchor`) welds the segment to the lineage's current position.

### Spend binding

Spending a note publishes two nullifiers, one for the current epoch and one for the next, both pinned to the note's genuine leaves.
`SpendBind` consumes the `SpendableHeader` and a `NullifierDerivation` covering the present and next epochs. It ties the derivation to the lineage by `deriv.cm == spendable.cm`, so the pair it confirms is this note's, and it needs no note witness of its own.
It confirms the lineage's `present_nf` as the derivation's leaf at the present epoch by coverage (a degree-0 opening of the covered tail) and reads the following leaf `nf_next` as the next epoch's, so both published nullifiers are genuine `GGM(mk, ·)` leaves at adjacent epochs.
Each must be nonzero, or it would collide with the note's own `cm` in the tachygram scan.
The output `SpendHeader` carries `cm`, the pair `(present_nf, nf_next)`, and the anchor; `SpendBind` is an intermediate step, its `SpendHeader` consumed only by `SpendStamp`.

`SpendStamp` proves the action, mirroring `OutputStamp`, and completes publication.
It witnesses the note and the action material, requires `note.commitment() == cm` and `note.pk == pak.derive_payment_key()`, and derives the value commitment `cv`, the randomized action verification key `rk`, and the action digest; it emits a `StampHeader` whose tachygram set is the pair `{present_nf, nf_next}` read off the `SpendHeader`.
Splitting the pair-binding from the action keeps each step within its per-step gate budget and lets `SpendStamp` stay focused on the action, like `OutputStamp`.

Value is pinned two independent ways. `note.commitment() == cm` at `SpendStamp` ties `cm` to the note by `Poseidon` collision-resistance (the spender must know `rcm`, `pk`, `value`, `psi`), so the value commitment `cv` commits to the minted value[^notes]. `deriv.cm == spendable.cm` at `SpendBind` ties the published nullifiers to the lineage the creation stamp proved minted. Together they bind the action's value commitment to the note actually being spent. Publishing both nullifiers lets consensus apply the spend across an epoch transition that may occur between proof construction and inclusion.

The note's age never becomes public. The lineage carries only a single current nullifier, and `SpendBind` reads the pair by coverage from a derivation whose epoch range never reaches a published header, so no step surfaces a position that would leak how long the note has existed.

### Stamp construction

A stamp commits to two multisets, an action-digest set and a tachygram set[^tachygrams].
`OutputStamp` derives a value commitment, action verification key, and action digest from a witnessed note, value-randomness, and action-randomness; constraints reject zero or over-range note values and require the note's payment key to match the witnessed key material[^keys].
`SpendStamp` consumes a `SpendHeader` (carrying `cm`, the pair `(present_nf, nf_next)`, and the anchor), witnesses the note and randomness, checks the note against `cm` and its payment key against the witnessed key material[^keys], derives the value commitment, action verification key, and action digest, and emits a stamp whose one-action digest set, two-nullifier tachygram set `{present_nf, nf_next}`, and threaded anchor follow.
`MergeStamp` fuses two stamps by checking anchor equality and confirming each output set is the union of the two inputs': it witnesses the merged sets and enforces, for each, that the merged set polynomial is the product of the input set polynomials.

### Stamp anchor

`OutputStamp` is the only stamp-producing step that takes an anchor as direct witness: an output operation has no prior chain state to thread from.
The other stamp-producing steps thread the anchor from a validated spendable through `SpendBind`/`SpendStamp`, equality-constrain the two inputs' anchors (`MergeStamp`), or advance over an `AnchorChain` segment whose start matches the stamp's prior anchor (`StampLift`).
Consensus verifies the published anchor against the chain before accepting the stamp.

## Simple transaction

A transaction with one spend and one output, where the spendable was bootstrapped in a previous epoch and lifted over an `Unspent` crossing an epoch boundary before the spend.

```mermaid
flowchart TB
  subgraph derive [nullifier derivation]
    w_seed[/note, pak, part/]
    s_seed0[NfMasterSeed]
    s_seed1[NfMasterSeed]
    s_master[NfMasterStep]
    s_walk[NfPrefixStep]
    s_leaf[NullifierDerivationStep]
    s_dfuse[NullifierFuse]
    nf_range((NullifierDerivation))
  end

  subgraph spendable [spendable advance]
    w_init[/pre_epoch_anchor, pre_cm_anchor, creation_set, present_nf, creation_epoch/]
    anchor_init((AnchorChain))
    s_init[SpendableInit]
    unspent_in((Unspent))
    s_verify[UnspentBind]
    s_lift[SpendableLift]
  end

  subgraph spend_action [spend action]
    w_bind[/present_epoch/]
    s_bind[SpendBind]
  end

  subgraph merge [transaction assembly]
    w_stamp[/note, rcv, alpha, pak/]
    s_spendstamp[SpendStamp]
    w_output[/rcv, alpha, note, anchor/]
    s_output[OutputStamp]
    s_merge[MergeStamp]
  end

  stamp_out((StampHeader))

  w_seed --> s_seed0
  w_seed --> s_seed1
  s_seed0 -->|NfMasterHeader| s_master
  s_seed1 -->|NfMasterHeader| s_master
  s_master -->|NfPrefixHeader| s_walk
  s_walk -->|NfPrefixHeader| s_leaf
  s_leaf -->|NullifierDerivation| s_dfuse
  s_dfuse --> nf_range

  anchor_init --> s_init
  nf_range -->|NullifierDerivation| s_init
  w_init --> s_init
  nf_range -->|NullifierDerivation| s_verify
  unspent_in --> s_verify
  s_init -->|SpendableHeader| s_lift
  s_verify -->|VerifiedUnspent| s_lift
  s_lift -->|SpendableHeader| s_bind

  nf_range -->|NullifierDerivation| s_bind
  w_bind --> s_bind
  s_bind -->|SpendHeader| s_spendstamp
  w_stamp --> s_spendstamp

  w_output --> s_output
  s_spendstamp -->|StampHeader| s_merge
  s_output -->|StampHeader| s_merge
  s_merge --> stamp_out
```

The single `SpendableLift` consumes one composed `VerifiedUnspent` (potentially crossing many epoch boundaries); threading `cm` chains the lineage's binding to the note through every advance.

## Focused subgraphs

### Stamp anchor advance

```mermaid
flowchart LR
  sh_in((StampHeader))
  w_seed[/start, stamp_commit/]
  s_seed[AnchorSeed]
  w_fuse[/empty start/]
  s_empty[EmptyBlockSeed]
  s_fuse[AnchorFuse]
  s_lift[StampLift]
  sh_out((StampHeader))

  w_seed --> s_seed
  w_fuse --> s_empty
  s_seed -->|AnchorChain| s_fuse
  s_empty -->|AnchorChain| s_fuse
  sh_in --> s_lift
  s_fuse -->|AnchorChain| s_lift
  s_lift --> sh_out
```

### Unspent composition across epochs

```mermaid
flowchart LR
  w_seed[/start, epoch, stamp_tg_set, nf/]
  s_useed[UnspentSeed]
  w_empty[/start, epoch, nf/]
  s_uempty[EmptyBlockUnspentSeed]
  s_ufuse[UnspentFuse]
  w_efuse[/left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq/]
  s_efuse[UnspentEpochFuse]
  unspent_out((Unspent))

  w_seed --> s_useed
  w_empty --> s_uempty
  s_useed -->|Unspent| s_ufuse
  s_uempty -->|Unspent| s_ufuse
  s_ufuse -->|Unspent| s_efuse
  w_efuse --> s_efuse
  s_efuse --> unspent_out
```

## Headers

| Header | Fields |
| ------ | ------ |
| AnchorChain | (start, end) |
| Unspent | (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_end, nf_end), anchor_last) |
| VerifiedUnspent | (cm, anchor_prev, (epoch_start, nf_start), (epoch_end, nf_end), anchor_last) |
| NfMasterHeader | (mk_part, part, note) |
| NfPrefixHeader | (node_commit, depth, index, note) |
| NullifierDerivation | (cm, epoch_start, epoch_end, seq_commit) |
| SpendableHeader | (cm, present_nf, anchor) |
| SpendHeader | (cm, present_nf, nf_next, anchor) |
| StampHeader | (action_commit, tachygram_commit, anchor) |

## Steps

| Step | Left | Right | Witness | Output |
| ---- | ---- | ----- | ------- | ------ |
| AnchorSeed | — | — | start, stamp_commit | AnchorChain |
| EmptyBlockSeed | — | — | start | AnchorChain |
| AnchorFuse | AnchorChain | AnchorChain | — | AnchorChain |
| UnspentSeed | — | — | anchor_prev, (epoch, nf), stamp_tg_set | Unspent |
| EmptyBlockUnspentSeed | — | — | anchor_prev, (epoch, nf) | Unspent |
| UnspentFuse | Unspent | Unspent | left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq | Unspent |
| UnspentEpochFuse | Unspent | Unspent | left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq | Unspent |
| UnspentBind | Unspent | NullifierDerivation | elapsed_seq, nf_seq, deriv_seq, prefix_seq, suffix_seq | VerifiedUnspent |
| NfMasterSeed | — | — | note, pak, part | NfMasterHeader |
| NfMasterStep | NfMasterHeader | NfMasterHeader | trace, quotients, child_poly, decimation_quotient, chunk | NfPrefixHeader |
| NfPrefixStep | NfPrefixHeader | — | node_poly, trace, quotients, child_poly, decimation_quotient, chunk | NfPrefixHeader |
| NullifierDerivationStep | NfPrefixHeader | — | node_poly, trace, quotients, decimation_quotient, leaf_poly, seq_poly, accumulator, evaluation_quotient | NullifierDerivation |
| NullifierFuse | NullifierDerivation | NullifierDerivation | left_seq, merged_seq, right_seq | NullifierDerivation |
| SpendableInit | AnchorChain | NullifierDerivation | (pre_epoch_anchor, pre_cm_anchor), creation_set, present_nf, creation_epoch, deriv_seq, prefix_seq, tail_seq | SpendableHeader |
| SpendableLift | SpendableHeader | VerifiedUnspent | — | SpendableHeader |
| SpendBind | SpendableHeader | NullifierDerivation | present_epoch, deriv_seq, prefix_seq, tail_seq, next_tail_seq | SpendHeader |
| OutputStamp | — | — | rcv, alpha, note, anchor | StampHeader |
| SpendStamp | SpendHeader | — | note, rcv, alpha, pak | StampHeader |
| MergeStamp | StampHeader | StampHeader | (action_set, tachygram_set) × left, merged, right | StampHeader |
| StampLift | StampHeader | AnchorChain | — | StampHeader |

[^nullifiers]: See [Nullifiers](./nullifiers.md) for the GGM derivation, the scalar `psi` seed, and the re-based absence sequence.
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the per-stamp multiset polynomial and its Pedersen commitment.
[^notes]: See [Notes](./notes.md) for the four-field note structure and its commitment.
[^keys]: See [Keys](./keys.md) for the wallet key hierarchy and the per-action derivations.
[^aggregation]: See [Aggregation](./aggregation.md) for the autonome/aggregate/adjunct lifecycle and the miner-side stripping that realizes the chain-cost reduction.
