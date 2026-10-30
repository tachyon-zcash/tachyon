import Tachyon.BundleAccounting
import Tachyon.ChainSpends

/-!
# Spend credits

`TracedBundle.accountingOrBreak` balances a bundle over the signed values of the leaves its action
descriptors cover. A chain spend's `SpendAction` fixes the tachygrams of the leaf at its descriptor:
its note's nullifiers at the lineage's epoch and the next. A leaf with those tachygrams is a spend of
that note, so its signed value is the note's value; otherwise a nullifier has two preimages, or a
note commitment equals a nullifier (`TachygramLeaf.creditsOrCollision`). Each chain spend thus
credits its own note's value to its bundle's balance (`ChainSpend.creditOrCollision`).
-/

namespace Tachyon

open AnchorBreaks

universe w

variable {F A : Type*} [Field F] [DecidableEq F] {H : TachygramHash F} {Opens : F → ℤ → Option ℕ → Type*}
  {R : ℕ → F → Multiset F} {epoch : A → ℕ}

/-- Two notes with one nullifier are equal, or the nullifier has two preimages. -/
def nullifierNoteOrCollision (H : TachygramHash F) (n n' : Note F) (x x' : ℕ)
    (heq : H.nullifier (H.noteCommit n') x' = H.nullifier (H.noteCommit n) x) :
    (n' = n) ⊕' TachygramCollision H :=
  if hinput : (TachygramInput.nullifier (H.noteCommit n') x' : TachygramInput F) =
      .nullifier (H.noteCommit n) x then
    noteEqOrCollision H n n' (TachygramInput.nullifier.inj hinput).1.symm
  else .inr ⟨_, _, hinput, heq⟩

/-- A leaf whose tachygrams are note `n`'s nullifiers at `x` and `x + 1` has `n`'s value as its
signed value, or a tachygram has two preimages. -/
def TachygramLeaf.creditsOrCollision {d : F} {a : A} {n : Note F} {x : ℕ}
    (k : TachygramLeaf H Opens R epoch d a)
    (hR : R (epoch a) d = {H.nullifier (H.noteCommit n) x, H.nullifier (H.noteCommit n) (x + 1)}) :
    (k.signedValue = n.value) ⊕' TachygramCollision H :=
  match k with
  | .spend n' x' _ hR' _ =>
      have hmem : H.nullifier (H.noteCommit n') x' ∈
          ({H.nullifier (H.noteCommit n) x, H.nullifier (H.noteCommit n) (x + 1)} : Multiset F) := by
        rw [← hR, hR']
        exact Multiset.mem_cons_self _ _
      mapOutcome
        (if hx : H.nullifier (H.noteCommit n') x' = H.nullifier (H.noteCommit n) x then
          nullifierNoteOrCollision H n n' x x' hx
        else nullifierNoteOrCollision H n n' (x + 1) x' (by simpa [hx] using hmem))
        fun hnote => congrArg (fun n : Note F => (n.value : ℤ)) hnote
  | .output n' _ hR' _ =>
      have hmem : H.noteCommit n' ∈
          ({H.nullifier (H.noteCommit n) x, H.nullifier (H.noteCommit n) (x + 1)} : Multiset F) := by
        rw [← hR, hR']
        exact Multiset.mem_cons_self _ _
      .inr <| if hx : H.noteCommit n' = H.nullifier (H.noteCommit n) x then
        ⟨.note n', .nullifier (H.noteCommit n) x, nofun, hx⟩
      else ⟨.note n', .nullifier (H.noteCommit n) (x + 1), nofun, by simpa [hx] using hmem⟩
  | .fee _ _ _ _ _ hR' _ => False.elim <| by
      have hcard := congrArg Multiset.card (hR'.symm.trans hR)
      simp at hcard

variable {K G Rk C P : Type*} [Field K] [AddCommGroup G] [Module K G] [Monoid P]
  [OpeningSemantics P F] [DecidableEq P] [DecidableEq C] [DecidableEq A] {Hd : TaggedDigest G Rk F}
  {V W : G} {m : Model P C A ℕ} {ValidBucket : QrBucket F A → Prop}
  {Query : QrBucket F A → F → Type*} {IsFee : F → Prop} {Δ Φ : Type w} {actionDigest : Δ → F}
  {feeDigest : Φ → F} {Lift : Stamp F A → A → Type w}
  {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)}

/-- The leaf covering a chain spend's descriptor has the spend's note value as its signed value,
or a tachygram has two preimages. -/
def ChainSpend.creditOrCollision (s : ChainSpend m ValidBucket Query H.nullifier bundles) :
    ((bundles[s.bundle].actionLeaf s.position).provenance.signedValue = s.note.value) ⊕'
      TachygramCollision H :=
  (bundles[s.bundle].actionLeaf s.position).provenance.creditsOrCollision
    (x := s.spendable.epoch_current) <| by
      have hepoch : epoch (bundles[s.bundle].actionLeaf s.position).anchor =
          epoch bundles[s.bundle].stamp.anchor :=
        (bundles[s.bundle].trace.findLeaf bundles[s.bundle].actions
          (bundles[s.bundle].actionDigest_mem s.position)).2.2.2.trans
          (congrArg epoch bundles[s.bundle].anchor)
      have haction := s.action
      simp only [SpendAction, spendBind, s.commits] at haction
      rw [hepoch, (bundles[s.bundle].actionLeaf_spec s.position).2]
      exact haction

end Tachyon
