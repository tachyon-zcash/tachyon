import Tachyon.NoteCreations
import Tachyon.Value

/-!
# Paid creations

Consensus computes each covered digest from its descriptor: an action digest hashes `(cv, rk)`
(`Tachyon-ActionDg`) and a fee digest hashes `(cvMax, fee)` (`Tachyon-FeeDg`). `DigestInput` tags
each preimage with its domain. A leaf's value opening is a tagged preimage of its digest whose value
commitment opens to the leaf's signed value (`DigestOpening`): `+v` for a spend, `-v` for an output,
and `-maxFee` for a fee.

A leaf that creates note `n` debits at least `n`'s value: an output debits `v`, and a fee leaf debits
`maxFee = change + fee`, where `n` is the change note (`TachygramLeaf.Creates.debit`). The descriptor
covering a creation's leaf commits to that debit, or two tagged preimages share the digest
(`Creation.debitOrBreak`). A note commitment published twice is thus two creations
(`sharedCreationBreak`), each debited by a covered descriptor of its own bundle.
-/

namespace Tachyon

universe u v w x

variable {K G Rk : Type*} {F : Type u} {A : Type v}

/-- Domain-tagged digest preimages: an action's `(cv, rk)`, or a fee's `(cvMax, fee)`. -/
inductive DigestInput (G Rk : Type*)
  | action (cv : G) (rk : Rk)
  | fee (cvMax : G) (fee : ℕ)
  deriving DecidableEq

/-- The value commitment a digest preimage carries. -/
def DigestInput.commitment : DigestInput G Rk → G
  | .action cv _ => cv
  | .fee cvMax _ => cvMax

/-- The action and fee digest hashes, with no injectivity assumptions. -/
structure TaggedDigest (G Rk F : Type*) where
  action : G → Rk → F
  fee : G → ℕ → F

def TaggedDigest.eval (Hd : TaggedDigest G Rk F) : DigestInput G Rk → F
  | .action cv rk => Hd.action cv rk
  | .fee cvMax fee => Hd.fee cvMax fee

/-- Distinct tagged preimages with one digest. -/
structure TaggedDigestCollision (Hd : TaggedDigest G Rk F) where
  left : DigestInput G Rk
  right : DigestInput G Rk
  distinct : left ≠ right
  equal : Hd.eval left = Hd.eval right

variable [Field K] [AddCommGroup G] [Module K G]

variable (K) in
/-- A tagged preimage of digest `d` whose value commitment opens to the signed value `v`. -/
structure DigestOpening (Hd : TaggedDigest G Rk F) (V W : G) (d : F) (v : ℤ) where
  input : DigestInput G Rk
  rcv : K
  digest : Hd.eval input = d
  opens : input.commitment = valueCommit V W (v : K) rcv

variable {H : TachygramHash F} {Opens : F → ℤ → Type x} {R : ℕ → F → Multiset F} {epoch : A → ℕ}

/-- The signed value a leaf's value commitment opens to. -/
def TachygramLeaf.signedValue {d : F} {a : A} : TachygramLeaf H Opens R epoch d a → ℤ
  | .spend n .. => n.value
  | .output n .. => -n.value
  | .fee maxFee .. => -maxFee.value

/-- The leaf's value opening. -/
def TachygramLeaf.opening {d : F} {a : A} :
    (k : TachygramLeaf H Opens R epoch d a) → Opens d k.signedValue
  | .spend _ _ o .. => o
  | .output _ o .. => o
  | .fee _ _ _ o .. => o

/-- A leaf's signed value is within `maxMoney`. -/
theorem TachygramLeaf.signedValue_abs_le {d : F} {a : A} (k : TachygramLeaf H Opens R epoch d a) :
    |k.signedValue| ≤ maxMoney := by
  cases k with
  | spend n _ _ _ hrange => simpa [TachygramLeaf.signedValue] using hrange
  | output n _ _ hrange => simpa [TachygramLeaf.signedValue] using hrange
  | fee maxFee _ _ _ _ _ hrange => simpa [TachygramLeaf.signedValue] using hrange

/-- A leaf that creates note `n` debits at least `n`'s value. -/
theorem TachygramLeaf.Creates.debit {d : F} {a : A} {n : Note F}
    {k : TachygramLeaf H Opens R epoch d a} (h : k.Creates n) : k.signedValue + n.value ≤ 0 := by
  cases k with
  | spend => exact h.elim
  | output n' => subst h; simp [TachygramLeaf.signedValue]
  | fee maxFee fee change _ hchange =>
      subst h
      simp only [TachygramLeaf.signedValue, Note.withValue]
      omega

/-- The descriptor preimages a bundle covers: its action descriptors', then its fee descriptors'. -/
def coveredInputs {Δ Φ : Type*} (actionInput : Δ → DigestInput G Rk)
    (feeInput : Φ → DigestInput G Rk) (descs : List Δ) (fees : List Φ) : List (DigestInput G Rk) :=
  descs.map actionInput ++ fees.map feeInput

variable [Field F] [DecidableEq F] [DecidableEq G] [DecidableEq Rk] {Hd : TaggedDigest G Rk F}
  {V W : G} {IsFee : F → Prop} {Δ Φ : Type w} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {Lift : Stamp F A → A → Type w}
  {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)}
  {actionInput : Δ → DigestInput G Rk} {feeInput : Φ → DigestInput G Rk}

/-- A creation of note `n` is covered by a descriptor of its bundle whose value commitment opens to
a value `v` with `v + n.value ≤ 0`, or two tagged preimages share the leaf's digest. Consensus
computes each action digest from `actionInput` and each fee digest from `feeInput`. -/
def Creation.debitOrBreak (hactionDigest : ∀ δ, actionDigest δ = Hd.eval (actionInput δ))
    (hfeeDigest : ∀ φ, feeDigest φ = Hd.eval (feeInput φ)) {n : Note F} {e : ℕ}
    (c : Creation bundles n e) :
    {y : DigestInput G Rk // y ∈ coveredInputs actionInput feeInput c.bundle.descs
        (c.bundle.fee :: c.bundle.adjunctFees) ∧
      ∃ (v : ℤ) (rcv : K), v + n.value ≤ 0 ∧ y.commitment = valueCommit V W (v : K) rcv} ⊕'
      TaggedDigestCollision Hd :=
  match hfind : (coveredInputs actionInput feeInput c.bundle.descs
      (c.bundle.fee :: c.bundle.adjunctFees)).find? (fun y => decide (Hd.eval y = c.leaf.digest)) with
  | some y =>
      have hy : Hd.eval y = c.leaf.digest := by simpa using List.find?_some hfind
      let o := c.leaf.provenance.opening
      if hinput : y = o.input then
        .inl ⟨y, List.mem_of_find?_eq_some hfind, c.leaf.provenance.signedValue, o.rcv,
          c.creates.debit, hinput ▸ o.opens⟩
      else .inr ⟨y, o.input, hinput, hy.trans o.digest.symm⟩
  | none => False.elim <| by
      have hd := c.covered
      simp only [coveredDigests, Multiset.mem_coe, List.mem_append, List.mem_map] at hd
      rcases hd with ⟨δ, hδ, hdigest⟩ | ⟨φ, hφ, hdigest⟩
      · exact List.find?_eq_none.mp hfind (actionInput δ)
          (List.mem_append_left _ (List.mem_map_of_mem hδ))
          (by simpa [← hactionDigest] using hdigest)
      · exact List.find?_eq_none.mp hfind (feeInput φ)
          (List.mem_append_right _ (List.mem_map_of_mem hφ))
          (by simpa [← hfeeDigest] using hdigest)

end Tachyon
