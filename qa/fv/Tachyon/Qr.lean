import Tachyon.Consensus.Entry

/-!
# QR buckets

Summaries, intakes and buckets (`crates/tachyon/src/stamp/proof/summary.rs`, `qr.rs`) and evidence
trees (`evidence.rs`). A bucket holds one profile's members of one epoch. The steps prove two
things about it, and the model proves both.

* **Completeness.** Every tachygram the bucket's stamps carry whose sides match the bucket's path
  is a root of the contents. `QrUnspentInit` opens the contents nonzero at a value whose sides
  match, so the value is absent from those stamps.
* **Inclusion.** The contents divide the product of the bucket's stamps, so a root of the contents
  is a tachygram of one of them.

`QrBucket.Covers` states both over the stamp polynomials the bucket's anchors fold, and
`QrBucketDerivable.covers` proves it for every derivable bucket. A bucket that ends on the
published entry anchor of the next epoch folds exactly the stamps published in its epoch
(`QrBucket.Covers.onChain`).

A value takes the residue side at a discriminant `R` iff `t + R` is a square, zero included, and a
path records one side per depth: depth `j` classifies at `R₀ + j` and `true` is the residue side.
The model carries a profile as its path. `QrSideDescend` checks the parent depth below 32, so
`bits < 2 ^ 32` and the field pair `(depth, bits)` determines the path.

The model folds `QrIntakeSplit`, `QrSideSelect` and `QrSideDescend` into one constructor.
`QrSideSelect` and `QrSideDescend` both consume a `QrIntakeSides`, and the two may come from
different splits. The fold is still sound: both share every header field and the
`non_residue_hash`, so under bridge binding they share the non-residue polynomial, which is the only
polynomial the selection checks, and no contents ride on either header. The selection's non-residue
bridge hash is read as the split's non-residue polynomial.

The model omits constraints that the two properties don't use: the non-empty stamp and intake
checks, `QrSideDescend`'s distinct-sides check, and the evidence trees' network field equalities.
Omitting a constraint admits more derivations, so the results cover every derivation the steps
admit. Two constraints are built into the representation, not omitted: epochs are natural numbers,
which relies on the `EpochIndex` range checks for `e + 1` not to wrap, and a profile is its path,
which relies on `QrSideDescend`'s depth bound for `(depth, bits)` to determine the path.
-/

namespace Tachyon

open Polynomial Chain

variable {F A D : Type*} [Field F]

/-- `t` takes the sides of `path` at the discriminants `R₀ + j`. -/
def Matches (R₀ : F) (path : List Bool) (t : F) : Prop :=
  ∀ j (hj : j < path.length), (path[j] = true ↔ IsSquare (t + (R₀ + j)))

/-- A value matching a path with one more side matches the shorter path and takes that side at the
next discriminant, for inducting over a bucket's descents. -/
theorem Matches.of_concat {R₀ t : F} {path : List Bool} {b : Bool}
    (h : Matches R₀ (path ++ [b]) t) :
    Matches R₀ path t ∧ (b = true ↔ IsSquare (t + (R₀ + path.length))) := by
  refine ⟨fun j hj => ?_, by simpa using h path.length (by simp)⟩
  have := h j (by simp; omega)
  rwa [List.getElem_append_left hj] at this

/-- A run of an epoch's stamps: header data `(epoch, anchor_prev, anchor_end)` and the
`ACCUMULATED` slot. The `LAST_STAMP` slot is the polynomial the last fold absorbs. -/
structure Summary (F A : Type*) [Field F] where
  epoch : ℕ
  anchor_prev : A
  anchor_end : A
  accumulated : F[X]

/-- `SummarySeed` and `SummaryAdvance`, over the anchor-fold calls `q`. -/
inductive SummaryDerivable (q : AnchorQueries F A ℕ) (nextStamp : A → ℕ → F[X] → A) :
    Summary F A → Prop
  | seed (anchor_prev : A) (epoch : ℕ) (stamp : F[X]) :
      q.stamp anchor_prev epoch stamp →
      SummaryDerivable q nextStamp ⟨epoch, anchor_prev, nextStamp anchor_prev epoch stamp, stamp⟩
  | advance {s : Summary F A} (stamp : F[X]) :
      SummaryDerivable q nextStamp s → q.stamp s.anchor_end s.epoch stamp →
        SummaryDerivable q nextStamp
          ⟨s.epoch, s.anchor_prev, nextStamp s.anchor_end s.epoch stamp, s.accumulated * stamp⟩

/-- An intake: header data `(epoch, anchor_prev, anchor_end, discriminant, profile)` with the
profile as its path, and the contents slot. -/
structure QrIntake (F A : Type*) [Field F] where
  epoch : ℕ
  anchor_prev : A
  anchor_end : A
  discriminant : F
  path : List Bool
  contents : F[X]

/-- `QrSummaryIntake`, `QrStampIntakeSeed`, `QrEmptyIntakeSeed`, `QrIntakeMerge`, and
`QrIntakeSplit` with `QrSideSelect` and `QrSideDescend`. `qnr` is the quadratic non-residue. -/
inductive QrIntakeDerivable (q : AnchorQueries F A ℕ) (nextStamp : A → ℕ → F[X] → A) (qnr : F) :
    QrIntake F A → Prop
  | summary {s : Summary F A} (discriminant : F) :
      SummaryDerivable q nextStamp s →
        QrIntakeDerivable q nextStamp qnr
          ⟨s.epoch, s.anchor_prev, s.anchor_end, discriminant, [], s.accumulated⟩
  | stamp (anchor_prev : A) (epoch : ℕ) (discriminant : F) (stamp : F[X]) :
      q.stamp anchor_prev epoch stamp →
      QrIntakeDerivable q nextStamp qnr
        ⟨epoch, anchor_prev, nextStamp anchor_prev epoch stamp, discriminant, [], stamp⟩
  | empty (anchor : A) (epoch : ℕ) (discriminant : F) :
      QrIntakeDerivable q nextStamp qnr ⟨epoch, anchor, anchor, discriminant, [], 1⟩
  | merge {left right : QrIntake F A} :
      QrIntakeDerivable q nextStamp qnr left → QrIntakeDerivable q nextStamp qnr right →
      left.epoch = right.epoch → left.discriminant = right.discriminant →
      left.path = right.path → left.anchor_end = right.anchor_prev →
        QrIntakeDerivable q nextStamp qnr
          ⟨left.epoch, left.anchor_prev, right.anchor_end, left.discriminant, left.path,
            left.contents * right.contents⟩
  | descend {intake : QrIntake F A} (residue non_residue interpolant quotient : F[X]) (bit : Bool) :
      QrIntakeDerivable q nextStamp qnr intake →
      intake.contents = residue * non_residue →
      non_residue.eval (-(intake.discriminant + intake.path.length)) ≠ 0 →
      interpolant ^ 2 - (if bit then non_residue else residue) * quotient =
        C (if bit then qnr else 1) * (X + C (intake.discriminant + intake.path.length)) →
        QrIntakeDerivable q nextStamp qnr
          ⟨intake.epoch, intake.anchor_prev, intake.anchor_end, intake.discriminant,
            intake.path ++ [bit], if bit then residue else non_residue⟩

/-- A bucket: header data `(epoch, anchor_start, anchor_next, discriminant, profile,
contents_hash)` with the profile as its path, and the contents slot that `contents_hash`
certifies. -/
structure QrBucket (F A : Type*) [Field F] where
  epoch : ℕ
  anchor_start : A
  anchor_next : A
  discriminant : F
  path : List Bool
  contents : F[X]

/-- The QR evidence headers: a bucket, a half-assembled evidence node, and an evidence tree root. -/
inductive QrEvidence (F A D : Type*) [Field F]
  | bucket (b : QrBucket F A)
  | pair (left right : D)
  | tree (root : D)

/-- The evidence digest calls under consideration: `leaf b` is a call `leaf b`, and
`node c₀ c₁ c₂ c₃` a call `node c₀ c₁ c₂ c₃`. -/
structure EvidenceQueries (F A D : Type*) [Field F] where
  leaf : QrBucket F A → Prop
  node : D → D → D → D → Prop

/-- `QrBucketSeal`, the evidence-tree steps and `EvidenceTreeOpen`. `leaf` is the
`Tachyon-QrBucket` leaf digest and `node` the `Tachyon-EvidNode` node digest. `descend` walks one
level; `EvidenceTreeDescend` composes a fixed number of them. -/
inductive QrEvidenceDerivable (q : AnchorQueries F A ℕ) (r : EvidenceQueries F A D)
    (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) (qnr : F)
    (leaf : QrBucket F A → D) (node : D → D → D → D → D) : QrEvidence F A D → Prop
  | seal {intake : QrIntake F A} (anchor_final_prev : A) :
      QrIntakeDerivable q nextStamp qnr intake →
      intake.anchor_prev = nextEpoch anchor_final_prev intake.epoch →
      q.boundary anchor_final_prev intake.epoch → q.boundary intake.anchor_end (intake.epoch + 1) →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node
          (.bucket ⟨intake.epoch, intake.anchor_prev, nextEpoch intake.anchor_end (intake.epoch + 1),
            intake.discriminant, intake.path, intake.contents⟩)
  | leafPair {left right : QrBucket F A} :
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.bucket left) →
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.bucket right) →
      r.leaf left → r.leaf right →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.pair (leaf left) (leaf right))
  | pairFuse {left right : D} :
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree left) →
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree right) →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.pair left right)
  | fuse {l₀ l₁ r₀ r₁ : D} :
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.pair l₀ l₁) →
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.pair r₀ r₁) →
      r.node l₀ l₁ r₀ r₁ →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree (node l₀ l₁ r₀ r₁))
  | cap {root : D} :
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree root) →
      r.node root root root root →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree (node root root root root))
  | descend {c₀ c₁ c₂ c₃ : D} (k : Fin 4) :
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree (node c₀ c₁ c₂ c₃)) →
      r.node c₀ c₁ c₂ c₃ →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree (![c₀, c₁, c₂, c₃] k))
  | open {b : QrBucket F A} :
      QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.tree (leaf b)) → r.leaf b →
        QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.bucket b)

/-- The buckets `QrBucketSeal` and `EvidenceTreeOpen` emit. -/
def QrBucketDerivable (q : AnchorQueries F A ℕ) (r : EvidenceQueries F A D)
    (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) (qnr : F)
    (leaf : QrBucket F A → D) (node : D → D → D → D → D) (b : QrBucket F A) : Prop :=
  QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node (.bucket b)

/-- Collision resistance and domain separation of the leaf and node digests on the calls `r`. The
leaf digest absorbs every bucket header field and the contents' bridge hash. A finite `r` without a
collision satisfies it. -/
structure EvidenceLaw (r : EvidenceQueries F A D) (leaf : QrBucket F A → D)
    (node : D → D → D → D → D) : Prop where
  leaf_inj : ∀ {b₁ b₂ : QrBucket F A}, r.leaf b₁ → r.leaf b₂ → leaf b₁ = leaf b₂ → b₁ = b₂
  node_inj : ∀ {a₀ a₁ a₂ a₃ b₀ b₁ b₂ b₃ : D}, r.node a₀ a₁ a₂ a₃ → r.node b₀ b₁ b₂ b₃ →
    node a₀ a₁ a₂ a₃ = node b₀ b₁ b₂ b₃ → a₀ = b₀ ∧ a₁ = b₁ ∧ a₂ = b₂ ∧ a₃ = b₃
  leaf_ne_node : ∀ {b : QrBucket F A} {a₀ a₁ a₂ a₃ : D}, r.leaf b → r.node a₀ a₁ a₂ a₃ →
    leaf b ≠ node a₀ a₁ a₂ a₃

/-- What an intake proves about the stamps its anchors fold. -/
def QrIntake.Covers (q : AnchorQueries F A ℕ) (nextStamp : A → ℕ → F[X] → A)
    (intake : QrIntake F A) : Prop :=
  ∃ stamps : List F[X],
    intake.anchor_end = foldBlock nextStamp intake.epoch intake.anchor_prev stamps ∧
    FoldQueried q nextStamp intake.epoch intake.anchor_prev stamps ∧
    (∀ stamp ∈ stamps, ∀ t, stamp.IsRoot t → Matches intake.discriminant intake.path t →
      intake.contents.IsRoot t) ∧
    intake.contents ∣ stamps.prod

/-- What a bucket proves: its range starts on a boundary digest into its epoch, ends on the
boundary digest of a run of stamp folds into the next epoch, all three calls in `q`, and its
contents are complete for its path and divide that run's product. -/
def QrBucket.Covers (q : AnchorQueries F A ℕ) (nextStamp : A → ℕ → F[X] → A)
    (nextEpoch : A → ℕ → A) (b : QrBucket F A) : Prop :=
  ∃ (anchor_final_prev : A) (stamps : List F[X]),
    b.anchor_start = nextEpoch anchor_final_prev b.epoch ∧ q.boundary anchor_final_prev b.epoch ∧
    FoldQueried q nextStamp b.epoch b.anchor_start stamps ∧
    b.anchor_next = nextEpoch (foldBlock nextStamp b.epoch b.anchor_start stamps) (b.epoch + 1) ∧
    q.boundary (foldBlock nextStamp b.epoch b.anchor_start stamps) (b.epoch + 1) ∧
    (∀ stamp ∈ stamps, ∀ t, stamp.IsRoot t → Matches b.discriminant b.path t →
      b.contents.IsRoot t) ∧
    b.contents ∣ stamps.prod

variable {q : AnchorQueries F A ℕ} {r : EvidenceQueries F A D} {nextStamp : A → ℕ → F[X] → A}
  {nextEpoch : A → ℕ → A} {qnr : F} {leaf : QrBucket F A → D} {node : D → D → D → D → D}

/-- A summary's anchors fold a run of stamp calls in `q`, and it accumulates their product. -/
theorem SummaryDerivable.folds {s : Summary F A} (h : SummaryDerivable q nextStamp s) :
    ∃ stamps : List F[X], s.anchor_end = foldBlock nextStamp s.epoch s.anchor_prev stamps ∧
      FoldQueried q nextStamp s.epoch s.anchor_prev stamps ∧ s.accumulated = stamps.prod := by
  induction h with
  | seed a e c hq => exact ⟨[c], rfl, .singleton hq, by simp⟩
  | advance c _ hq ih =>
    obtain ⟨stamps, hend, hfold, hacc⟩ := ih
    exact ⟨stamps ++ [c], by simp [foldBlock, hend],
      FoldQueried.append.mpr ⟨hfold, .singleton (hend ▸ hq)⟩, by simp [hacc]⟩

/-- Every derivable intake covers the stamps its anchors fold. -/
theorem QrIntakeDerivable.covers (hqnr : ¬ IsSquare qnr) {intake : QrIntake F A}
    (h : QrIntakeDerivable q nextStamp qnr intake) : intake.Covers q nextStamp := by
  induction h with
  | summary R₀ hs =>
    obtain ⟨stamps, hend, hfold, hacc⟩ := hs.folds
    refine ⟨stamps, hend, hfold, fun st hst t ht _ => ?_, by simp [hacc]⟩
    rw [hacc]
    exact ht.dvd (List.dvd_prod hst)
  | stamp a e R₀ st hq =>
    refine ⟨[st], rfl, .singleton hq, fun st' hst' t ht _ => ?_, by simp⟩
    rw [List.mem_singleton] at hst'
    exact hst' ▸ ht
  | empty a e R₀ =>
    exact ⟨[], rfl, fun _ _ _ h => absurd h (by simp), fun _ hst => absurd hst List.not_mem_nil,
      one_dvd _⟩
  | merge _ _ hepoch hdisc hpath hjoin ihl ihr =>
    obtain ⟨Ls, hLend, hLfold, hLcov, hLdvd⟩ := ihl
    obtain ⟨Rs, hRend, hRfold, hRcov, hRdvd⟩ := ihr
    refine ⟨Ls ++ Rs, ?_, FoldQueried.append.mpr ⟨hLfold, by rw [← hLend, hjoin, hepoch]; exact hRfold⟩,
      fun st hst t ht hm => ?_, ?_⟩
    · simp only [foldBlock, List.foldl_append] at hLend hRend ⊢
      rw [← hLend, hjoin, hRend, hepoch]
    · rcases List.mem_append.mp hst with hst | hst
      · exact (hLcov st hst t ht hm).dvd (dvd_mul_right _ _)
      · rw [hdisc, hpath] at hm
        exact (hRcov st hst t ht hm).dvd (dvd_mul_left _ _)
    · rw [List.prod_append]
      exact mul_dvd_mul hLdvd hRdvd
  | descend res nr u q bit _ hsplit hexc hclass ih =>
    obtain ⟨stamps, hend, hfold, hcov, hdvd⟩ := ih
    refine ⟨stamps, hend, hfold, fun st hst t ht hm => ?_, ?_⟩
    · obtain ⟨hm, hside⟩ := Matches.of_concat hm
      have hroot := hcov st hst t ht hm
      rw [hsplit, IsRoot.def, eval_mul, mul_eq_zero] at hroot
      have hsib := congrArg (eval t) hclass
      simp only [eval_sub, eval_mul, eval_pow, eval_C, eval_add, eval_X] at hsib
      cases bit with
      | true =>
        refine hroot.resolve_right fun hnr => ?_
        simp only [if_true, hnr, zero_mul, sub_zero] at hsib
        obtain ⟨w, hw⟩ := hside.mp rfl
        by_cases hw0 : w = 0
        · rw [hw0, mul_zero, add_eq_zero_iff_eq_neg] at hw
          exact hexc (hw ▸ hnr)
        · refine hqnr ⟨eval t u / w, ?_⟩
          rw [hw] at hsib
          rw [div_mul_div_comm, ← sq, hsib, mul_div_assoc, div_self (mul_ne_zero hw0 hw0),
            mul_one]
      | false =>
        refine hroot.resolve_left fun hres => ?_
        simp only [Bool.false_eq_true, if_false, hres, zero_mul, sub_zero, one_mul] at hsib
        exact Bool.false_ne_true (hside.mpr ⟨eval t u, by rw [← hsib, sq]⟩)
    · refine dvd_trans ?_ (hsplit ▸ hdvd)
      cases bit
      · exact dvd_mul_left _ _
      · exact dvd_mul_right _ _

/-- Evidence digests whose every leaf is the digest of a bucket satisfying `P`. -/
inductive EvidenceSound (P : QrBucket F A → Prop) (r : EvidenceQueries F A D)
    (leaf : QrBucket F A → D) (node : D → D → D → D → D) : D → Prop
  | leaf {b : QrBucket F A} : P b → r.leaf b → EvidenceSound P r leaf node (leaf b)
  | node {c₀ c₁ c₂ c₃ : D} :
      EvidenceSound P r leaf node c₀ → EvidenceSound P r leaf node c₁ →
      EvidenceSound P r leaf node c₂ → EvidenceSound P r leaf node c₃ → r.node c₀ c₁ c₂ c₃ →
        EvidenceSound P r leaf node (node c₀ c₁ c₂ c₃)

/-- Sound evidence at a leaf call is the digest of a bucket satisfying `P`. -/
theorem EvidenceSound.of_leaf (hlaw : EvidenceLaw r leaf node) {P : QrBucket F A → Prop}
    {b : QrBucket F A} (hq : r.leaf b) (h : EvidenceSound P r leaf node (leaf b)) : P b := by
  generalize hd : leaf b = d at h
  cases h with
  | leaf hP hq' => exact hlaw.leaf_inj hq' hq hd.symm ▸ hP
  | node _ _ _ _ hq' => exact absurd hd (hlaw.leaf_ne_node hq hq')

/-- Sound evidence at a node call has sound children. -/
theorem EvidenceSound.of_node (hlaw : EvidenceLaw r leaf node) {P : QrBucket F A → Prop}
    {c₀ c₁ c₂ c₃ : D} (hq : r.node c₀ c₁ c₂ c₃) (h : EvidenceSound P r leaf node (node c₀ c₁ c₂ c₃))
    (k : Fin 4) : EvidenceSound P r leaf node (![c₀, c₁, c₂, c₃] k) := by
  generalize hd : node c₀ c₁ c₂ c₃ = d at h
  cases h with
  | leaf _ hq' => exact absurd hd.symm (hlaw.leaf_ne_node hq' hq)
  | node h₀ h₁ h₂ h₃ hq' =>
    obtain ⟨rfl, rfl, rfl, rfl⟩ := hlaw.node_inj hq hq' hd
    fin_cases k <;> assumption

/-- A covering bucket, or evidence whose every leaf is the digest of one. -/
def QrEvidence.Sound (q : AnchorQueries F A ℕ) (r : EvidenceQueries F A D)
    (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A)
    (leaf : QrBucket F A → D) (node : D → D → D → D → D) : QrEvidence F A D → Prop
  | .bucket b => b.Covers q nextStamp nextEpoch
  | .pair d d' => EvidenceSound (QrBucket.Covers q nextStamp nextEpoch) r leaf node d ∧
      EvidenceSound (QrBucket.Covers q nextStamp nextEpoch) r leaf node d'
  | .tree d => EvidenceSound (QrBucket.Covers q nextStamp nextEpoch) r leaf node d

/-- Every derivable bucket covers the stamps its anchors fold, whether `QrBucketSeal` emitted it or
`EvidenceTreeOpen` replayed it. -/
theorem QrBucketDerivable.covers (hqnr : ¬ IsSquare qnr) (hlaw : EvidenceLaw r leaf node)
    {b : QrBucket F A} (h : QrBucketDerivable q r nextStamp nextEpoch qnr leaf node b) :
    b.Covers q nextStamp nextEpoch := by
  suffices ∀ x, QrEvidenceDerivable q r nextStamp nextEpoch qnr leaf node x →
      x.Sound q r nextStamp nextEpoch leaf node from this _ h
  intro x hx
  induction hx with
  | «seal» p hi hprev hqp hqend =>
    obtain ⟨stamps, hend, hfold, hcov, hdvd⟩ := hi.covers hqnr
    exact ⟨p, stamps, hprev, hqp, hfold, by rw [hend], hend ▸ hqend, hcov, hdvd⟩
  | leafPair _ _ hl hr ihl ihr => exact ⟨.leaf ihl hl, .leaf ihr hr⟩
  | pairFuse _ _ ihl ihr => exact ⟨ihl, ihr⟩
  | fuse _ _ hq ihl ihr => exact .node ihl.1 ihl.2 ihr.1 ihr.2 hq
  | cap _ hq ih => exact .node ih ih ih ih hq
  | descend k _ hq ih => exact ih.of_node hlaw hq k
  | «open» _ hq ih => exact ih.of_leaf hlaw hq

/-- A covering bucket that ends on the published entry anchor of the next epoch, up to the bound
`N` of the chain's calls, starts on the entry anchor of its epoch, holds every tachygram published
in that epoch with a matching path, and holds only tachygrams published in that epoch. -/
theorem QrBucket.Covers.onChain {genesis : A} {e₀ : ℕ}
    (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch) {zero : A} {chain : List (Chain.Stamp F A)}
    {N : ℕ} (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {b : QrBucket F A}
    (he : b.epoch + 1 ≤ N) (hb : b.Covers q nextStamp nextEpoch)
    (hnext : b.anchor_next = entry nextStamp nextEpoch zero chain (b.epoch + 1)) :
    b.anchor_start = entry nextStamp nextEpoch zero chain b.epoch ∧
      (∀ t, published chain b.epoch t → Matches b.discriminant b.path t → b.contents.IsRoot t) ∧
      (∀ t, b.contents.IsRoot t → published chain b.epoch t) := by
  obtain ⟨p, stamps, hstart, hqp, hfold, hnext', hqend, hcov, hdvd⟩ := hb
  obtain ⟨hentry, rfl⟩ :=
    entry_succ_inj hlaw hchain he ⟨p, b.epoch, hstart, hqp⟩ hfold hqend (hnext' ▸ hnext)
  refine ⟨hentry, fun t ht hm => ?_, fun t ht => published_of_root_prod (ht.dvd hdvd)⟩
  obtain ⟨st, hst, hroot⟩ := published_root ht
  exact hcov st hst t hroot hm

end Tachyon
