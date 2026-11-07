import Tachyon.SpendAuthorization
import Tachyon.Foundation.DiscreteLogRelation
import Mathlib.Tactic.Abel

/-!
# Fee digest-to-change pairing, or computed breaks

This verifies one concrete subcase of the stamp model's pairing hypothesis:
two fee leaves with the same digest have the same change tachygram, or produce
explicit digest/blind-hash collisions, encoding collisions, or a nontrivial
linear relation between the value/blinding generators.

`V` is the note/hash word type, `K` the commitment scalar field, and `G` the
value-commitment group. They are not silently identified. A failed word-to-
scalar embedding or bounded amount cast is returned as an encoding witness,
not mislabelled as a Poseidon or DL break. Actual canonical encodings can
discharge those branches separately. Hash inputs contain canonical public
commitments and bounded fee values; concrete serialization/circuit equality
and PCD witness extraction remain external implementation boundaries.

The blinding and change hashes are computed from the same secret tuple, as
in `FeeBind`/`FeeSeed`. `StepBudget.ready_refinement` erases FeeValueCommit →
FeeBind to the same old fee-opening relation; FeeFuse consumes those certified
roots. No raw free blind can absorb a changed maximum fee.
This proves fee/fee pairing only, not spend/spend or mixed action pairing.
-/

namespace Tachyon.FeePairing

variable {V K G : Type*} [Field K] [AddCommGroup G] [Module K G] {money : ℕ}

structure Secrets (V : Type*) where
  pk : V
  psi : V
  rcm : V
  deriving DecidableEq

structure Frame (V : Type*) (money : ℕ) where
  secrets : Secrets V
  maximum : Fin money
  fee : Fin money
  fee_le_maximum : fee.val ≤ maximum.val

structure DigestInput (G : Type*) (money : ℕ) where
  commitment : G
  fee : Fin money
  deriving DecidableEq

structure Model (V K G : Type*) (money : ℕ) where
  valueBase : G
  blindBase : G
  blindHash : Secrets V → V
  embed : V → K
  digestHash : DigestInput G money → V
  changeHash : Secrets V → ℕ → V

def Model.maxScalar (_m : Model V K G money) (frame : Frame V money) : K := frame.maximum.val
def Model.blindScalar (m : Model V K G money) (frame : Frame V money) : K :=
  m.embed (m.blindHash frame.secrets)
def Model.cv (m : Model V K G money) (frame : Frame V money) : G :=
  (-m.maxScalar frame) • m.valueBase + m.blindScalar frame • m.blindBase
def Model.descriptor (m : Model V K G money) (frame : Frame V money) : DigestInput G money :=
  ⟨m.cv frame, frame.fee⟩
def Model.digest (m : Model V K G money) (frame : Frame V money) : V :=
  m.digestHash (m.descriptor frame)
def Model.change (m : Model V K G money) (frame : Frame V money) : V :=
  m.changeHash frame.secrets (frame.maximum.val - frame.fee.val)

inductive Break (m : Model V K G money)
  | digest (witness : Authorization.Collision m.digestHash)
  | blind (witness : Authorization.Collision m.blindHash)
  | embedding (witness : Authorization.Collision m.embed)
  | amount (witness : Authorization.Collision (fun n : Fin money => (n.val : K)))
  | relation (witness : NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) m.valueBase m.blindBase)

variable [DecidableEq V] [DecidableEq K] [DecidableEq G]

/-- Equal commitments with unequal scalar openings compute the actual
nonzero relation coefficients, following ragu's binding reduction pattern. -/
def relationOfOpenings (m : Model V K G money) (left right : Frame V money)
    (hcv : m.cv left = m.cv right)
    (hne : ¬ (m.maxScalar left = m.maxScalar right ∧ m.blindScalar left = m.blindScalar right)) :
    NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) m.valueBase m.blindBase := by
  have hnonzero : (-m.maxScalar left) - (-m.maxScalar right) ≠ 0 ∨
      m.blindScalar left - m.blindScalar right ≠ 0 := by
    by_cases hm : m.maxScalar left = m.maxScalar right
    · exact Or.inr (fun hb => hne ⟨hm, sub_eq_zero.mp hb⟩)
    · exact Or.inl (sub_ne_zero.mpr (fun h => hm (neg_inj.mp h)))
  refine ⟨0, (-m.maxScalar left) - (-m.maxScalar right),
    m.blindScalar left - m.blindScalar right, Or.inr hnonzero, ?_⟩
  simp only [Fintype.sum_empty, zero_add]
  calc
    _ = m.cv left - m.cv right := by rw [Model.cv, Model.cv, sub_smul, sub_smul]; abel
    _ = 0 := sub_eq_zero.mpr hcv

/-- Fee/fee pairing is a reduction, not a global injectivity axiom. -/
def changeEqOrBreak (m : Model V K G money) (left right : Frame V money)
    (hdigest : m.digest left = m.digest right) :
    (m.change left = m.change right) ⊕' Break m := by
  by_cases hdesc : m.descriptor left = m.descriptor right
  · have hcv := (DigestInput.mk.inj hdesc).1
    have hfee := (DigestInput.mk.inj hdesc).2
    by_cases hopen : m.maxScalar left = m.maxScalar right ∧ m.blindScalar left = m.blindScalar right
    · by_cases hmax : left.maximum = right.maximum
      · by_cases hraw : m.blindHash left.secrets = m.blindHash right.secrets
        · by_cases hsecrets : left.secrets = right.secrets
          · exact .inl (by simp only [Model.change, hsecrets, hmax, hfee])
          · exact .inr (.blind ⟨left.secrets, right.secrets, hsecrets, hraw⟩)
        · exact .inr (.embedding ⟨_, _, hraw, hopen.2⟩)
      · exact .inr (.amount ⟨left.maximum, right.maximum, hmax, hopen.1⟩)
    · exact .inr (.relation (relationOfOpenings m left right hcv hopen))
  · exact .inr (.digest ⟨m.descriptor left, m.descriptor right, hdesc, hdigest⟩)

namespace Examples

def model : Model ℚ ℚ ℚ 100 :=
  ⟨1, 1, fun s => s.pk, id, fun _ => 0, fun s change => s.pk + change⟩
def left : Frame ℚ 100 := ⟨⟨11, 0, 0⟩, ⟨10, by decide⟩, ⟨3, by decide⟩, by decide⟩
def right : Frame ℚ 100 := ⟨⟨21, 0, 0⟩, ⟨20, by decide⟩, ⟨3, by decide⟩, by decide⟩
def changedFee : Frame ℚ 100 := ⟨⟨11, 0, 0⟩, ⟨10, by decide⟩, ⟨4, by decide⟩, by decide⟩

-- Deliberately equal generators make a relation easy to exhibit; the
-- reduction returns its actual coefficients rather than assuming it away.
#guard match changeEqOrBreak model left right rfl with
  | .inl _ => false
  | .inr (.relation w) => w.α == 10 && w.β == -10
  | .inr _ => false

#guard match changeEqOrBreak model left changedFee rfl with
  | .inl _ => false
  | .inr (.digest _) => true
  | .inr _ => false

#guard match changeEqOrBreak model left left rfl with
  | .inl _ => true
  | .inr _ => false

def blindCollisions : Model ℚ ℚ ℚ 100 :=
  ⟨1, 1, fun _ => 0, id, fun _ => 0, fun s change => s.pk + change⟩
def changedSecrets : Frame ℚ 100 := ⟨⟨12, 0, 0⟩, ⟨10, by decide⟩, ⟨3, by decide⟩, by decide⟩

#guard match changeEqOrBreak blindCollisions left changedSecrets rfl with
  | .inl _ => false
  | .inr (.blind _) => true
  | .inr _ => false

end Examples

end Tachyon.FeePairing
