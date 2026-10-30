import Tachyon.ScalarEncodings

/-!
# Output digest-to-tachygram pairing, or computed breaks

`OutputAction` derives its key directly as `[embed H(theta,cm)]G`, unlike a
spend key which adds an owner key. Equal output descriptors therefore pin the
nonce scalar when `G` is nonzero. Comparing the raw nonce and note preimages
then gives the same `(cm,pad)` pair, or concrete digest/nonce/note collisions.

The scalar and note-word fields are separate. Encoding collisions are explicit
in the generic reduction and excluded for canonical Pasta embedding by the
arithmetic proof in `ScalarEncodings`.

The value commitment is threaded data here. Its note-value opening/range is
the separate value/provenance model's obligation; allowing arbitrary commitments
only enlarges this pairing model and does not weaken the key-to-note argument.
No spend/spend or spend/output pairing theorem is claimed. Actual canonical
curve/hash encodings and PCD witness extraction remain implementation boundaries.
-/

namespace Tachyon.OutputPairing

variable {V K G : Type*} [Field K] [AddCommGroup G] [Module K G]

structure Frame (V G : Type*) where
  note : Authorization.NoteInput V
  theta : V
  cv : G

structure DigestInput (G : Type*) where
  cv : G
  rk : G
  deriving DecidableEq

structure Model (V K G : Type*) where
  keyBase : G
  noteHash : Authorization.NoteInput V → V
  padHash : Authorization.NoteInput V → V
  nonceHash : V × V → V
  embed : V → K
  digestHash : DigestInput G → V

def Model.nonceInput (m : Model V K G) (frame : Frame V G) : V × V :=
  (frame.theta, m.noteHash frame.note)
def Model.alpha (m : Model V K G) (frame : Frame V G) : K :=
  m.embed (m.nonceHash (m.nonceInput frame))
def Model.rk (m : Model V K G) (frame : Frame V G) : G := m.alpha frame • m.keyBase
def Model.descriptor (m : Model V K G) (frame : Frame V G) : DigestInput G := ⟨frame.cv, m.rk frame⟩
def Model.digest (m : Model V K G) (frame : Frame V G) : V := m.digestHash (m.descriptor frame)
def Model.tachygrams (m : Model V K G) (frame : Frame V G) : V × V :=
  (m.noteHash frame.note, m.padHash frame.note)

inductive Break (m : Model V K G)
  | digest (witness : Authorization.Collision m.digestHash)
  | nonce (witness : Authorization.Collision m.nonceHash)
  | note (witness : Authorization.Collision m.noteHash)
  | embedding (witness : Authorization.Collision m.embed)

variable [DecidableEq V] [DecidableEq K] [DecidableEq G]

omit [DecidableEq G] in
theorem scalar_eq_of_smul_eq {base : G} (hbase : base ≠ 0) {a b : K}
    (heq : a • base = b • base) : a = b := by
  by_cases hab : a = b
  · exact hab
  · have hzero : (a - b) • base = 0 := by rw [sub_smul, heq, sub_self]
    have hbaseZero : base = 0 := by
      have h := congrArg (fun point : G => (a - b)⁻¹ • point) hzero
      simpa only [smul_smul, inv_mul_cancel₀ (sub_ne_zero.mpr hab), one_smul, smul_zero] using h
    exact False.elim (hbase hbaseZero)

/-- Equal output digests preserve the complete output pair, unless the
comparison returns explicit colliding inputs at one of its binding layers. -/
def tachygramsEqOrBreak (m : Model V K G) (hbase : m.keyBase ≠ 0) (left right : Frame V G)
    (hdigest : m.digest left = m.digest right) :
    (m.tachygrams left = m.tachygrams right) ⊕' Break m := by
  by_cases hdesc : m.descriptor left = m.descriptor right
  · have hrk : m.rk left = m.rk right := (DigestInput.mk.inj hdesc).2
    have halpha : m.alpha left = m.alpha right := scalar_eq_of_smul_eq hbase hrk
    by_cases hraw : m.nonceHash (m.nonceInput left) = m.nonceHash (m.nonceInput right)
    · by_cases hnonce : m.nonceInput left = m.nonceInput right
      · have hcm : m.noteHash left.note = m.noteHash right.note := (Prod.mk.inj hnonce).2
        by_cases hnote : left.note = right.note
        · exact .inl (by simp only [Model.tachygrams, hnote])
        · exact .inr (.note ⟨left.note, right.note, hnote, hcm⟩)
      · exact .inr (.nonce ⟨m.nonceInput left, m.nonceInput right, hnonce, hraw⟩)
    · exact .inr (.embedding ⟨_, _, hraw, halpha⟩)
  · exact .inr (.digest ⟨m.descriptor left, m.descriptor right, hdesc, hdigest⟩)

inductive CryptoBreak (m : Model V K G)
  | digest (witness : Authorization.Collision m.digestHash)
  | nonce (witness : Authorization.Collision m.nonceHash)
  | note (witness : Authorization.Collision m.noteHash)

def refineBreak (m : Model V K G) (hembed : Function.Injective m.embed) : Break m → CryptoBreak m
  | .digest w => .digest w
  | .nonce w => .nonce w
  | .note w => .note w
  | .embedding w => False.elim (w.distinct (hembed w.equal))

def tachygramsEqOrCryptoBreak (m : Model V K G) (hbase : m.keyBase ≠ 0)
    (hembed : Function.Injective m.embed) (left right : Frame V G)
    (hdigest : m.digest left = m.digest right) :
    (m.tachygrams left = m.tachygrams right) ⊕' CryptoBreak m :=
  match tachygramsEqOrBreak m hbase left right hdigest with
  | .inl result => .inl result
  | .inr witness => .inr (refineBreak m hembed witness)

namespace Examples

def model : Model ℚ ℚ ℚ :=
  ⟨1, fun n => n.pk, fun n => n.value, Prod.snd, id, fun _ => 0⟩
def left : Frame ℚ ℚ := ⟨⟨0, 3, 4, 0⟩, 0, 5⟩
def changedTheta : Frame ℚ ℚ := ⟨⟨0, 3, 4, 0⟩, 1, 5⟩
def changedNote : Frame ℚ ℚ := ⟨⟨0, 3, 5, 0⟩, 0, 5⟩
def changedCV : Frame ℚ ℚ := ⟨⟨0, 3, 4, 0⟩, 0, 6⟩

#guard match tachygramsEqOrBreak model (by norm_num [model]) left left rfl with
  | .inl _ => true
  | .inr _ => false

#guard match tachygramsEqOrBreak model (by norm_num [model]) left changedTheta rfl with
  | .inl _ => false
  | .inr (.nonce _) => true
  | .inr _ => false

#guard match tachygramsEqOrBreak model (by norm_num [model]) left changedNote rfl with
  | .inl _ => false
  | .inr (.note _) => true
  | .inr _ => false

#guard match tachygramsEqOrBreak model (by norm_num [model]) left changedCV rfl with
  | .inl _ => false
  | .inr (.digest _) => true
  | .inr _ => false

def badEmbedding : Model ℚ ℚ ℚ :=
  ⟨1, fun n => n.pk, fun n => n.value, Prod.snd, fun _ => 1, fun _ => 0⟩
def changedCM : Frame ℚ ℚ := ⟨⟨0, 4, 4, 0⟩, 0, 5⟩

#guard match tachygramsEqOrBreak badEmbedding (by norm_num [badEmbedding]) left changedCM rfl with
  | .inl _ => false
  | .inr (.embedding _) => true
  | .inr _ => false

end Examples

end Tachyon.OutputPairing

namespace Tachyon.ScalarEncodings

variable {G : Type*} [AddCommGroup G] [Fact scalarModulus.Prime] [Module (ZMod scalarModulus) G]
  [DecidableEq G]

def pastaOutputPairingOrBreak
    (m : OutputPairing.Model (ZMod noteModulus) (ZMod scalarModulus) G)
    (hbase : m.keyBase ≠ 0) (hembed : m.embed = noteWordLift)
    (left right : OutputPairing.Frame (ZMod noteModulus) G) (hdigest : m.digest left = m.digest right) :
    (m.tachygrams left = m.tachygrams right) ⊕' OutputPairing.CryptoBreak m :=
  OutputPairing.tachygramsEqOrCryptoBreak m hbase (hembed ▸ noteWordLift_injective) left right hdigest

end Tachyon.ScalarEncodings
