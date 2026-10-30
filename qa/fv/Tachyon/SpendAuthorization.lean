import Mathlib.Algebra.Module.Defs
import Mathlib.Algebra.Field.Defs
import Mathlib.Data.List.Basic
import Mathlib.Algebra.Field.Rat
import Mathlib.Algebra.Module.Basic

/-!
# Spend ownership and an unconsented-signature break

The ownership checks in `SpendAction` tie a payment-key opening to the spent
note; `SpendBind` threads that same note commitment. If a claimed note has the
owner's commitment, comparison computes either the owner's randomized action
key relation or an explicit collision in the note/payment-key hashes.

`authorizedOrBreak` then returns consent for the authorizing transaction
message, or an explicit hash break/valid unconsented signature for a randomized
owner key. The consent policy represents the honest owner's signing requests
in the security game; it is not inferred from on-chain data or human intent.

This does not infer knowledge of `ask` from one valid signature. Signature
unforgeability/forking is a separate cryptographic layer. The verification
equation is the prime-order Schnorr/RedPallas equation; actual canonical
encodings, challenge hash, circuit/Rust equivalence and key generation must
instantiate the model correctly. Note words are already field-encoded, and
the public-key representation must be canonical, with no ignored metadata.

Following ragu's witness discipline, collisions/forgeries are returned as data
from supplied finite inputs. No global hash injectivity or existential break
assumption is used.
-/

namespace Tachyon.Authorization

variable {V K G M : Type*} [Field K] [AddCommGroup G] [Module K G]

structure NoteInput (V : Type*) where
  rcm : V
  pk : V
  value : V
  psi : V
  deriving DecidableEq

structure PaymentInput (V G : Type*) where
  ak : G
  nk : V
  deriving DecidableEq

structure Signature (K G : Type*) where
  commitment : G
  response : K

structure Model (V K G M : Type*) where
  base : G
  noteHash : NoteInput V → V
  paymentHash : PaymentInput V G → V
  randomizer : V → V → K
  challenge : G → G → M → K

def Model.actionKey (m : Model V K G M) (note : NoteInput V) (pak : PaymentInput V G)
    (theta : V) : G := pak.ak + m.randomizer theta (m.noteHash note) • m.base

def Model.Verified (m : Model V K G M) (key : G) (message : M) (signature : Signature K G) : Prop :=
  signature.response • m.base = signature.commitment +
    m.challenge signature.commitment key message • key

structure Collision {I O : Type*} (hash : I → O) where
  left : I
  right : I
  distinct : left ≠ right
  equal : hash left = hash right

/-- An execution-local corollary needs only the two witnessed hash inputs. -/
def Collision.elim {I O : Type*} {hash : I → O} (w : Collision hash)
    (hlocal : hash w.left = hash w.right → w.left = w.right) : False := w.distinct (hlocal w.equal)

inductive OwnershipBreak (m : Model V K G M)
  | note (witness : Collision m.noteHash)
  | payment (witness : Collision m.paymentHash)

structure RelatedKey (m : Model V K G M) (actual owner : G) where
  alpha : K
  key_eq : actual = owner + alpha • m.base

variable [DecidableEq V] [DecidableEq G]

/-- Same-note and payment-key checks compute owner-key linkage or concrete
colliding typed preimages. No owner secret signing scalar is assumed known. -/
def ownerKeyOrCollision (m : Model V K G M) (ownerNote actualNote : NoteInput V)
    (ownerPak actualPak : PaymentInput V G) (theta : V)
    (howner : ownerNote.pk = m.paymentHash ownerPak)
    (hspend : actualNote.pk = m.paymentHash actualPak)
    (hcm : m.noteHash actualNote = m.noteHash ownerNote) :
    RelatedKey m (m.actionKey actualNote actualPak theta) ownerPak.ak ⊕' OwnershipBreak m := by
  by_cases hnote : actualNote = ownerNote
  · cases hnote
    have hpayment : m.paymentHash actualPak = m.paymentHash ownerPak := hspend.symm.trans howner
    by_cases hpak : actualPak = ownerPak
    · exact .inl ⟨m.randomizer theta (m.noteHash ownerNote), by rw [hpak]; rfl⟩
    · exact .inr (.payment ⟨actualPak, ownerPak, hpak, hpayment⟩)
  · exact .inr (.note ⟨actualNote, ownerNote, hnote, hcm⟩)

/-- A valid signature on a message outside the honest owner's consent log,
under an explicitly related randomized key. This is the forgery-game outcome,
not a proof of concrete RedPallas unforgeability. -/
structure RandomizedForgery (m : Model V K G M) (consented : M → Bool) (owner : G) where
  alpha : K
  message : M
  signature : Signature K G
  verified : m.Verified (owner + alpha • m.base) message signature
  fresh : consented message = false

inductive AuthorizationBreak (m : Model V K G M) (consented : M → Bool) (owner : G)
  | ownership (witness : OwnershipBreak m)
  | signature (witness : RandomizedForgery m consented owner)

/-- A purported valid spend of the owner's note either has a consented message
or computes a hash collision / randomized-owner-key signature forgery. -/
def authorizedOrBreak (m : Model V K G M) (consented : M → Bool)
    (ownerNote actualNote : NoteInput V) (ownerPak actualPak : PaymentInput V G)
    (theta : V) (message : M) (signature : Signature K G)
    (howner : ownerNote.pk = m.paymentHash ownerPak)
    (hspend : actualNote.pk = m.paymentHash actualPak)
    (hcm : m.noteHash actualNote = m.noteHash ownerNote)
    (hverify : m.Verified (m.actionKey actualNote actualPak theta) message signature) :
    (consented message = true) ⊕' AuthorizationBreak m consented ownerPak.ak := by
  cases hconsent : consented message with
  | true => exact .inl rfl
  | false =>
    cases ownerKeyOrCollision m ownerNote actualNote ownerPak actualPak theta howner hspend hcm with
    | inr witness => exact .inr (.ownership witness)
    | inl related =>
      exact .inr (.signature ⟨related.alpha, message, signature, related.key_eq ▸ hverify, hconsent⟩)

namespace Examples

-- Deliberately insecure finite-input hashes/challenges let the tests exercise
-- each break branch without assuming any cryptographic hardness theorem.
def model : Model Bool ℚ ℚ Bool :=
  ⟨1, fun note => note.pk, fun _ => false, fun _ _ => 0, fun _ _ _ => 0⟩
def note : NoteInput Bool := ⟨false, false, false, false⟩
def changedNote : NoteInput Bool := ⟨false, false, false, true⟩
def pak : PaymentInput Bool ℚ := ⟨3, false⟩
def changedPak : PaymentInput Bool ℚ := ⟨4, false⟩
def signature : Signature ℚ ℚ := ⟨0, 0⟩

#guard match authorizedOrBreak model (fun _ => false) note note pak pak false false signature
    rfl rfl rfl (by simp [Model.Verified, model, signature]) with
  | .inl _ => false
  | .inr (.signature _) => true
  | .inr (.ownership _) => false

#guard match authorizedOrBreak model (fun _ => true) note note pak pak false false signature
    rfl rfl rfl (by simp [Model.Verified, model, signature]) with
  | .inl _ => true
  | .inr _ => false

#guard match ownerKeyOrCollision model note changedNote pak pak false rfl rfl rfl with
  | .inl _ => false
  | .inr (.note _) => true
  | .inr (.payment _) => false

#guard match ownerKeyOrCollision model note note pak changedPak false rfl rfl rfl with
  | .inl _ => false
  | .inr (.note _) => false
  | .inr (.payment _) => true

end Examples

end Tachyon.Authorization
