import Tachyon.Consensus.Bundle
import Tachyon.ProvenanceTraces

/-!
# Published notes

Every tachygram is the output of one of three domain-separated Poseidon hashes: a note commitment
(`Tachyon-CmDerive`), an output's padding tachygram (`Tachyon-CmOutPad`), or a nullifier
(`Tachyon-NfDerive`). `TachygramInput` tags each preimage with its domain, following
`AnchorBreaks.Input`. The nullifier preimage is the note commitment and the epoch, with the note's
master key folded in as in `NullifiersDerivable`.

Each leaf's provenance records its kind, its note and an opening of its value commitment
(`TachygramLeaf`): `SpendBind` over a note's
commitment derives a nullifier pair, `OutputBind` derives a note's commitment and pad, and `FeeFuse`
and `FeeSeed` derive the commitment of the change note, which keeps the max fee note's `rcm`, `pk`
and `psi` and holds `maxFee - fee`.

A verified bundle that publishes note `n`'s commitment holds a covered leaf that creates `n`: an
output of `n`, or a fee leaf whose change note is `n`. Otherwise the published tachygram's two
preimages collide (`publishedNoteOrCollision`).
-/

namespace Tachyon

universe u v w

/-- A note's opening `(rcm, pk, value, psi)`. -/
structure Note (F : Type u) where
  rcm : F
  pk : F
  value : ℕ
  psi : F
  deriving DecidableEq

/-- `MAX_MONEY`, the bound `SpendBind`, `OutputBind` and `FeeFuse` check note values against. -/
def maxMoney : ℕ := 2_100_000_000_000_000

/-- The change note of a max fee note: its `rcm`, `pk` and `psi`, holding `change`. -/
def Note.withValue {F : Type u} (n : Note F) (change : ℕ) : Note F :=
  ⟨n.rcm, n.pk, change, n.psi⟩

/-- Domain-tagged tachygram preimages. -/
inductive TachygramInput (F : Type u)
  | note (n : Note F)
  | pad (n : Note F)
  | nullifier (cm : F) (epoch : ℕ)
  deriving DecidableEq

/-- The tachygram hashes, with no injectivity assumptions. -/
structure TachygramHash (F : Type u) where
  noteCommit : Note F → F
  pad : Note F → F
  nullifier : F → ℕ → F

variable {F : Type u} {A : Type v}

def TachygramHash.eval (H : TachygramHash F) : TachygramInput F → F
  | .note n => H.noteCommit n
  | .pad n => H.pad n
  | .nullifier cm x => H.nullifier cm x

/-- Distinct tagged preimages with one tachygram. -/
structure TachygramCollision (H : TachygramHash F) where
  left : TachygramInput F
  right : TachygramInput F
  distinct : left ≠ right
  equal : H.eval left = H.eval right

/-- A leaf's kind and note. Covered by a stamp at anchor epoch `epoch a`, its tachygrams under the
pairing `R` are a spent note's nullifier pair at some epoch `x`, an output note's commitment and pad,
or the change note's commitment. `Opens d v` opens the value commitment behind digest `d` to the
signed value `v`: `SpendBind` commits `+v`, `OutputBind` commits `-v`, and `FeeFuse` and `FeeSeed`
commit `-maxFee`. Each step checks its note value against `maxMoney`. -/
inductive TachygramLeaf (H : TachygramHash F) (Opens : F → ℤ → Type w) (R : ℕ → F → Multiset F)
    (epoch : A → ℕ) (d : F) (a : A) : Type (max u w)
  | spend (n : Note F) (x : ℕ) : Opens d n.value →
      R (epoch a) d = {H.nullifier (H.noteCommit n) x, H.nullifier (H.noteCommit n) (x + 1)} →
        n.value ≤ maxMoney → TachygramLeaf H Opens R epoch d a
  | output (n : Note F) : Opens d (-n.value) →
      R (epoch a) d = {H.noteCommit n, H.pad n} → n.value ≤ maxMoney →
        TachygramLeaf H Opens R epoch d a
  | fee (maxFee : Note F) (fee change : ℕ) : Opens d (-maxFee.value) →
      change + fee = maxFee.value → R (epoch a) d = {H.noteCommit (maxFee.withValue change)} →
        maxFee.value ≤ maxMoney → TachygramLeaf H Opens R epoch d a

variable {H : TachygramHash F} {Opens : F → ℤ → Type w} {R : ℕ → F → Multiset F}
  {epoch : A → ℕ}

/-- The leaf creates note `n`: it outputs `n`, or its change note is `n`. -/
def TachygramLeaf.Creates {d : F} {a : A} (n : Note F) : TachygramLeaf H Opens R epoch d a → Prop
  | .spend .. => False
  | .output n' .. => n' = n
  | .fee maxFee _ change .. => maxFee.withValue change = n

variable [DecidableEq F]

/-- Two notes with one commitment are equal, or their preimages collide. -/
def noteEqOrCollision (H : TachygramHash F) (n n' : Note F)
    (hcm : H.noteCommit n = H.noteCommit n') : (n' = n) ⊕' TachygramCollision H :=
  if h : n' = n then .inl h
  else .inr ⟨.note n, .note n', fun heq => h (TachygramInput.note.inj heq).symm, hcm⟩

/-- A leaf whose tachygrams hold note `n`'s commitment creates `n`, or a tachygram has two
preimages. -/
def TachygramLeaf.createsOrCollision {d : F} {a : A} {n : Note F}
    (k : TachygramLeaf H Opens R epoch d a) (hmem : H.noteCommit n ∈ R (epoch a) d) :
    k.Creates n ⊕' TachygramCollision H :=
  match k with
  | .spend n' x _ hR _ =>
      .inr <| if hx : H.noteCommit n = H.nullifier (H.noteCommit n') x then
        ⟨.note n, .nullifier (H.noteCommit n') x, nofun, hx⟩
      else
        ⟨.note n, .nullifier (H.noteCommit n') (x + 1), nofun, by
          rw [hR] at hmem
          simpa [hx] using hmem⟩
  | .output n' _ hR _ =>
      if hcm : H.noteCommit n = H.noteCommit n' then noteEqOrCollision H n n' hcm
      else .inr ⟨.note n, .pad n', nofun, by
        rw [hR] at hmem
        simpa [hcm] using hmem⟩
  | .fee maxFee _ change _ _ hR _ =>
      noteEqOrCollision H n (maxFee.withValue change) (by rw [hR] at hmem; simpa using hmem)

variable {IsFee : F → Prop} {Δ Φ : Type*} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {descs : List Δ} {fee : Φ} {adjunctFees : List Φ} [Field F] {stamp : PublishedStamp F A}

/-- A tachygram a verified bundle publishes belongs to one of its covered digests. -/
def BundleVerified.coveredLeaf
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp) {t : F}
    (ht : t ∈ stamp.tachygrams) :
    {d : F // d ∈ coveredDigests actionDigest feeDigest descs (fee :: adjunctFees) ∧
      t ∈ R (epoch stamp.anchor) d} :=
  match hfind : (descs.map actionDigest ++ (fee :: adjunctFees).map feeDigest).find?
      (fun d => decide (t ∈ R (epoch stamp.anchor) d)) with
  | some d => ⟨d, Multiset.mem_coe.mpr (List.mem_of_find?_eq_some hfind),
      by simpa using List.find?_some hfind⟩
  | none => False.elim <| by
      have hbind : t ∈ (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)).bind
          (R (epoch stamp.anchor)) := h.tachygrams_eq ▸ Multiset.mem_coe.mpr ht
      obtain ⟨d, hd, htd⟩ := Multiset.mem_bind.mp hbind
      exact List.find?_eq_none.mp hfind d (Multiset.mem_coe.mp hd) (by simpa using htd)

/-- A verified bundle, traced with each leaf's kind, that publishes note `n`'s commitment holds a
positive leaf at a covered digest that creates `n`, or a tachygram has two preimages. The trace's
header need only cover the bundle's digests at the published anchor. -/
def publishedNoteOrCollision {Lift : Stamp F A → A → Type*} {header : Stamp F A}
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp)
    (T : StampTrace IsFee epoch R (TachygramLeaf H Opens R epoch) Lift header)
    (hactions : header.actions =
      setPoly (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)))
    (hanchor : header.anchor = stamp.anchor)
    {n : Note F} (hn : H.noteCommit n ∈ stamp.tachygrams) :
    {l : LeafRecord (TachygramLeaf H Opens R epoch) // l ∈ T.positive ∧
      l.digest ∈ coveredDigests actionDigest feeDigest descs (fee :: adjunctFees) ∧
      l.provenance.Creates n} ⊕' TachygramCollision H :=
  let ⟨d, hd, hmem⟩ := h.coveredLeaf hn
  let ⟨l, hl, hdigest, hepoch⟩ := T.findLeaf hactions hd
  match l.provenance.createsOrCollision (n := n)
      (by rw [hepoch, hanchor, hdigest]; exact hmem) with
  | .inl hcreates => .inl ⟨l, hl, hdigest ▸ hd, hcreates⟩
  | .inr collision => .inr collision

end Tachyon
