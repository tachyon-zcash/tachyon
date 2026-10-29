import Tachyon.AnchorTraces
import Tachyon.SpendBinding

/-!
# Spendable traces

`SpendableDerivable` and the unspent predicates it consumes are propositions, so a reduction cannot
case on them to compute a collision. `UnspentTrace`, `NoteUnspentTrace` and `SpendableTrace` carry
the same derivations as data, with each bucket's sealing predecessor explicit (`SealedBucket`):
`QrBucketSeal` ends a bucket on the boundary digest into the epoch after it. Each opening carries its
query evidence `Query b v` as data. Each `forget` recovers the proposition, in the safe direction
from data to proof.

Every `SpendableTrace` exposes the tagged hash input its anchor is the output of (`anchorInput`):
the stamp absorption `SpendableInit` folds, or the closing boundary digest of the last bucket for
`QrSpendableInit` and `SpendableLift`. Its label is the lineage's `epoch_current`, so decoding the
anchor's epoch against a chain `NodeTrace` returns `epoch_current` or a scoped collision
(`SpendableTrace.anchorEpochOrBreak`), with no global injectivity assumed.

The lineage is decided per query (`SpendableTrace.lineageOrBreak`): an oracle turns each opening's
evidence into completeness of its bucket at the opened value, or a break `R`. The lineage holds, or
the first break is returned; no bucket's completeness is assumed.
-/

namespace Tachyon

open Polynomial AnchorBreaks

universe u v w x

variable {F : Type u} {C : Type v} {A : Type w} [Field F] {m : Model F[X] C A ℕ}
  {ValidBucket : QrBucket F A → Prop} {Query : QrBucket F A → F → Type x} {nf : F → ℕ → F}

/-- A `QrBucket` with its sealing predecessor as data: the bucket ends on the boundary digest into
the epoch after it. -/
structure SealedBucket (m : Model F[X] C A ℕ) where
  bucket : QrBucket F A
  previous : A
  sealing : bucket.anchor_next = m.epochHash previous (bucket.epoch + 1)

/-- The boundary-digest preimage a sealed bucket ends on. -/
def SealedBucket.closing (b : SealedBucket m) : Input C A ℕ :=
  .epoch b.previous (b.bucket.epoch + 1)

theorem SealedBucket.closing_eval (b : SealedBucket m) : m.eval b.closing = b.bucket.anchor_next :=
  b.sealing.symm

/-- `QrUnspentInit`, `UnspentLift` and `UnspentFuse` as data, over sealed buckets, with each opened
value's query evidence. -/
inductive UnspentTrace (m : Model F[X] C A ℕ) (ValidBucket : QrBucket F A → Prop)
    (Query : QrBucket F A → F → Type x) : ArbitraryUnspent F A → Type (max u w x)
  | init (b : SealedBucket m) (v : F) (query : Query b.bucket v) :
      ValidBucket b.bucket → v ≠ 0 → b.bucket.contents.eval v ≠ 0 →
      UnspentTrace m ValidBucket Query
        ⟨b.bucket.anchor_start, b.bucket.epoch, {(b.bucket.epoch, v)}, b.bucket.epoch + 1,
          b.bucket.anchor_next⟩
  | lift {u : ArbitraryUnspent F A} (previous : UnspentTrace m ValidBucket Query u)
      (b : SealedBucket m) (v : F) (query : Query b.bucket v) {extended : Multiset (ℕ × F)} :
      ValidBucket b.bucket → u.anchor_next = b.bucket.anchor_start →
      u.epoch_next = b.bucket.epoch → v ≠ 0 → b.bucket.contents.eval v ≠ 0 →
      extended = u.elapsed + {(b.bucket.epoch, v)} →
      UnspentTrace m ValidBucket Query
        ⟨u.anchor_start, u.epoch_start, extended, b.bucket.epoch + 1, b.bucket.anchor_next⟩
  | fuse {left right : ArbitraryUnspent F A} {combined : Multiset (ℕ × F)}
      (leftTrace : UnspentTrace m ValidBucket Query left)
      (rightTrace : UnspentTrace m ValidBucket Query right) :
      left.anchor_next = right.anchor_start → right.epoch_start = left.epoch_next →
      combined = left.elapsed + right.elapsed →
      UnspentTrace m ValidBucket Query
        ⟨left.anchor_start, left.epoch_start, combined, right.epoch_next, right.anchor_next⟩

theorem UnspentTrace.forget {u : ArbitraryUnspent F A} :
    UnspentTrace m ValidBucket Query u → ArbitraryUnspentDerivable ValidBucket u
  | .init b v _ hb hv hne => .init b.bucket v hb hv hne
  | .lift previous b v _ hb hanchor hepoch hv hne hext =>
      .lift b.bucket v previous.forget hb hanchor hepoch hv hne hext
  | .fuse leftTrace rightTrace hjoin hepoch hcombined =>
      .fuse leftTrace.forget rightTrace.forget hjoin hepoch hcombined

/-- The boundary-digest preimage the segment ends on: its last bucket's closing. -/
def UnspentTrace.closing {u : ArbitraryUnspent F A} :
    UnspentTrace m ValidBucket Query u → Input C A ℕ
  | .init b .. => b.closing
  | .lift _ b .. => b.closing
  | .fuse _ rightTrace .. => rightTrace.closing

theorem UnspentTrace.closing_eval {u : ArbitraryUnspent F A} :
    (t : UnspentTrace m ValidBucket Query u) → m.eval t.closing = u.anchor_next
  | .init b .. => b.closing_eval
  | .lift _ b .. => b.closing_eval
  | .fuse _ rightTrace .. => rightTrace.closing_eval

theorem UnspentTrace.closing_label {u : ArbitraryUnspent F A} :
    (t : UnspentTrace m ValidBucket Query u) → t.closing.label = u.epoch_next
  | .init .. => rfl
  | .lift .. => rfl
  | .fuse _ rightTrace .. => rightTrace.closing_label

/-- Every epoch of the segment has an opened value unpublished in that epoch, or the oracle breaks
on one of the segment's queries. -/
def UnspentTrace.testedOrBreak {R : Sort*} {chain : List (Chain.Stamp F A)}
    (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' R) :
    {u : ArbitraryUnspent F A} → UnspentTrace m ValidBucket Query u →
      (∀ x, u.epoch_start ≤ x → x < u.epoch_next →
        ∃ v, (x, v) ∈ u.elapsed ∧ ¬ Chain.published chain x v) ⊕' R
  | _, .init b v query _ _ hne =>
      mapOutcome (oracle b.bucket v query) fun hcomplete x hlo hhi => by
        dsimp only at hlo hhi ⊢
        obtain rfl : x = b.bucket.epoch := by omega
        exact ⟨v, Multiset.mem_singleton_self _, fun hpub => hne (hcomplete hpub)⟩
  | _, .lift previous b v query _ _ hepoch _ hne hext =>
      match previous.testedOrBreak oracle, oracle b.bucket v query with
      | .inr r, _ => .inr r
      | .inl _, .inr r => .inr r
      | .inl hprevious, .inl hcomplete => .inl fun x hlo hhi => by
          dsimp only at hlo hhi ⊢
          rcases (by omega : x < b.bucket.epoch ∨ x = b.bucket.epoch) with hx | rfl
          · obtain ⟨v', hmem, hnot⟩ := hprevious x hlo (by omega)
            exact ⟨v', hext ▸ Multiset.mem_add.mpr (Or.inl hmem), hnot⟩
          · exact ⟨v, hext ▸ Multiset.mem_add.mpr (Or.inr (Multiset.mem_singleton_self _)),
              fun hpub => hne (hcomplete hpub)⟩
  | _, .fuse (left := left) leftTrace rightTrace _ hepoch hcombined =>
      match leftTrace.testedOrBreak oracle, rightTrace.testedOrBreak oracle with
      | .inr r, _ => .inr r
      | .inl _, .inr r => .inr r
      | .inl hleft, .inl hright => .inl fun x hlo hhi => by
          dsimp only at hlo hhi ⊢
          by_cases hx : x < left.epoch_next
          · obtain ⟨v, hmem, hnot⟩ := hleft x hlo hx
            exact ⟨v, hcombined ▸ Multiset.mem_add.mpr (Or.inl hmem), hnot⟩
          · obtain ⟨v, hmem, hnot⟩ := hright x (by omega) hhi
            exact ⟨v, hcombined ▸ Multiset.mem_add.mpr (Or.inr hmem), hnot⟩

/-- `UnspentBind` as data over an `UnspentTrace`. -/
inductive NoteUnspentTrace (m : Model F[X] C A ℕ) (ValidBucket : QrBucket F A → Prop)
    (Query : QrBucket F A → F → Type x) (nf : F → ℕ → F) : NoteUnspent F A → Type (max u w x)
  | bind {u : ArbitraryUnspent F A} {n : NoteNullifiers F} (complement : Multiset (ℕ × F))
      (unspent : UnspentTrace m ValidBucket Query u) :
      NullifiersDerivable nf n → n.seq = u.elapsed + complement →
      NoteUnspentTrace m ValidBucket Query nf
        ⟨n.cm, u.anchor_start, u.epoch_start, u.epoch_next, u.anchor_next⟩

theorem NoteUnspentTrace.forget {nu : NoteUnspent F A} :
    NoteUnspentTrace m ValidBucket Query nf nu → NoteUnspentDerivable ValidBucket nf nu
  | .bind complement unspent hn hdiv => .bind complement unspent.forget hn hdiv

def NoteUnspentTrace.closing {nu : NoteUnspent F A} :
    NoteUnspentTrace m ValidBucket Query nf nu → Input C A ℕ
  | .bind _ unspent .. => unspent.closing

theorem NoteUnspentTrace.closing_eval {nu : NoteUnspent F A} :
    (t : NoteUnspentTrace m ValidBucket Query nf nu) → m.eval t.closing = nu.anchor_next
  | .bind _ unspent .. => unspent.closing_eval

theorem NoteUnspentTrace.closing_label {nu : NoteUnspent F A} :
    (t : NoteUnspentTrace m ValidBucket Query nf nu) → t.closing.label = nu.epoch_next
  | .bind _ unspent .. => unspent.closing_label

/-- The note's nullifier is unpublished in every epoch of the bound segment, or the oracle breaks
on one of its queries. -/
def NoteUnspentTrace.lineageOrBreak {R : Sort*} {chain : List (Chain.Stamp F A)}
    (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' R) {nu : NoteUnspent F A} :
    NoteUnspentTrace m ValidBucket Query nf nu →
      (∀ x, nu.epoch_start ≤ x → x < nu.epoch_next → ¬ Chain.published chain x (nf nu.cm x)) ⊕' R
  | .bind _ unspent hn hdiv =>
      mapOutcome (unspent.testedOrBreak oracle) fun htested x hlo hhi => by
        obtain ⟨v, hmem, hnot⟩ := htested x hlo hhi
        have hv := hn.mem_seq (hdiv ▸ Multiset.mem_add.mpr (Or.inl hmem))
        exact hv ▸ hnot

/-- `SpendableInit`, `QrSpendableInit` and `SpendableLift` as data, indexed by the epoch the
lineage starts from. -/
inductive SpendableTrace (m : Model F[X] C A ℕ) (ValidBucket : QrBucket F A → Prop)
    (Query : QrBucket F A → F → Type x) (nf : F → ℕ → F) :
    ℕ → NoteSpendable F A → Type (max u w x)
  | init {n : NoteNullifiers F} (previous : A) (contents : F[X]) (e : ℕ) :
      NullifiersDerivable nf n → contents.eval n.cm = 0 → contents ≠ 1 →
      SpendableTrace m ValidBucket Query nf e ⟨n.cm, e, m.nextStamp previous e contents⟩
  | qrInit {nu : NoteUnspent F A} (b : SealedBucket m)
      (unspent : NoteUnspentTrace m ValidBucket Query nf nu) :
      ValidBucket b.bucket → nu.epoch_start = b.bucket.epoch →
      nu.anchor_start = b.bucket.anchor_start → nu.anchor_next = b.bucket.anchor_next →
      nu.epoch_next = b.bucket.epoch + 1 → b.bucket.contents.eval nu.cm = 0 →
      SpendableTrace m ValidBucket Query nf b.bucket.epoch ⟨nu.cm, nu.epoch_next, nu.anchor_next⟩
  | lift {start : ℕ} {sp : NoteSpendable F A} {nu : NoteUnspent F A}
      (previous : SpendableTrace m ValidBucket Query nf start sp)
      (unspent : NoteUnspentTrace m ValidBucket Query nf nu) :
      nu.cm = sp.cm → nu.epoch_start = sp.epoch_current → nu.anchor_start = sp.anchor →
      SpendableTrace m ValidBucket Query nf start ⟨sp.cm, nu.epoch_next, nu.anchor_next⟩

theorem SpendableTrace.forget {start : ℕ} {sp : NoteSpendable F A} :
    SpendableTrace m ValidBucket Query nf start sp →
      Tachyon.SpendableDerivable ValidBucket nf m.nextStamp start sp
  | .init previous contents e hn hroot hne => .init previous contents e hn hroot hne
  | .qrInit b unspent hb hepoch hstart hnext hepochNext hroot =>
      .qrInit b.bucket unspent.forget hb hepoch hstart hnext hepochNext hroot
  | .lift previous unspent hcm hepoch hanchor => .lift previous.forget unspent.forget hcm hepoch hanchor

/-- The tagged hash preimage the spendable's anchor is the output of. -/
def SpendableTrace.anchorInput {start : ℕ} {sp : NoteSpendable F A} :
    SpendableTrace m ValidBucket Query nf start sp → Input C A ℕ
  | .init previous contents e .. => m.stampInput previous e contents
  | .qrInit b .. => b.closing
  | .lift _ unspent .. => unspent.closing

theorem SpendableTrace.anchorInput_eval {start : ℕ} {sp : NoteSpendable F A} :
    (t : SpendableTrace m ValidBucket Query nf start sp) → m.eval t.anchorInput = sp.anchor
  | .init .. => rfl
  | .qrInit b _ _ _ _ hnext _ _ => b.closing_eval.trans hnext.symm
  | .lift _ unspent .. => unspent.closing_eval

theorem SpendableTrace.anchorInput_label {start : ℕ} {sp : NoteSpendable F A} :
    (t : SpendableTrace m ValidBucket Query nf start sp) → t.anchorInput.label = sp.epoch_current
  | .init .. => rfl
  | .qrInit _ _ _ _ _ _ hepochNext _ => hepochNext.symm
  | .lift _ unspent .. => unspent.closing_label

/-- The lineage starts no later than its current epoch, and the note's nullifier is unpublished in
every epoch from the start up to the current one, or the oracle breaks on one of its queries. -/
def SpendableTrace.lineageOrBreak {R : Sort*} {chain : List (Chain.Stamp F A)}
    (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' R) :
    {start : ℕ} → {sp : NoteSpendable F A} → SpendableTrace m ValidBucket Query nf start sp →
      (start ≤ sp.epoch_current ∧
        ∀ x, start ≤ x → x < sp.epoch_current → ¬ Chain.published chain x (nf sp.cm x)) ⊕' R
  | _, _, .init .. => .inl ⟨le_rfl, fun _ hlo hhi => absurd hhi (by dsimp only; omega)⟩
  | _, _, .qrInit _ unspent _ hepoch _ _ hepochNext _ =>
      mapOutcome (unspent.lineageOrBreak oracle) fun hlineage => by
        dsimp only
        exact ⟨by omega, fun x hlo hhi => hlineage x (by omega) hhi⟩
  | _, _, .lift (sp := sp) (nu := nu) previous unspent hcm hepoch _ =>
      match previous.lineageOrBreak oracle, unspent.lineageOrBreak oracle with
      | .inr r, _ => .inr r
      | .inl _, .inr r => .inr r
      | .inl ⟨hstart, hprevious⟩, .inl hunspent => .inl <| by
          have hlt := unspent.forget.tested_nullifiers.1
          dsimp only
          refine ⟨by omega, fun x hlo hhi => ?_⟩
          by_cases hx : x < sp.epoch_current
          · exact hprevious x hlo hx
          · exact hcm ▸ hunspent x (by omega) hhi

variable [DecidableEq F[X]] [DecidableEq C] [DecidableEq A]

/-- A spendable anchored at a traced chain node of epoch `e` has `epoch_current = e`, or the two
preimages of its anchor compute a collision within the node trace's scope. Noncomputable only
because `F[X]`'s `One` instance is; the break is assembled from the traces, not chosen. -/
noncomputable def SpendableTrace.anchorEpochOrBreak {start e : ℕ} {sp : NoteSpendable F A}
    (t : SpendableTrace m ValidBucket Query nf start sp) (node : NodeTrace m e sp.anchor) :
    (sp.epoch_current = e) ⊕' ScopedBreak m node.openings (t.anchorInput :: node.inputs) :=
  mapOutcome (inputLabelOrBreak m t.anchorInput node t.anchorInput_eval)
    fun hlabel => t.anchorInput_label.symm.trans hlabel

/-- A spend leaf from a spendable anchored at a traced chain node of epoch `e`, covered by a stamp
at that epoch, publishes the note's nullifier pair at `e`, or computes a scoped collision. -/
noncomputable def SpendableTrace.spendPairOrBreak {start e : ℕ} {sp : NoteSpendable F A}
    {R : ℕ → F → Multiset F} {d : F} (t : SpendableTrace m ValidBucket Query nf start sp)
    (node : NodeTrace m e sp.anchor) (haction : SpendAction R e (spendBind nf sp) d) :
    (R e d = {nf sp.cm e, nf sp.cm (e + 1)}) ⊕'
      ScopedBreak m node.openings (t.anchorInput :: node.inputs) :=
  mapOutcome (t.anchorEpochOrBreak node) fun hcurrent => by
    rw [SpendAction, spendBind, hcurrent] at haction
    exact haction

end Tachyon
