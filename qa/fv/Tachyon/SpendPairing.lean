import Tachyon.OutputPairing
import Tachyon.OracleDependencies
import Tachyon.Foundation.OracleReadLocations

/-!
# Spend/output action pairing from typed oracle observations

The nonce domains follow `primitives/effect.rs`: spend and output use distinct
tags. Frames carry claimed commitments and action keys as data. `Valid` checks
their note, payment-key and randomized-key equations against one typed table.
Verifier inputs depend only on these supplied frames, not on access to an
external oracle table hidden in the verifier-read selector.

Equal digests compute equal tachygram pairs, actual hash collisions, or a
fresh query whose answer hits a prefix-fixed bad-word set. With an injective
scalar embedding and nonzero base, that set has at most `2n+n(n+1)^2` words
after `n` queries. The completed, normalized two-frame execution costs at most
`Q+8` queries. This is a deterministic reduction and one-word counting result,
not an adaptive random-oracle probability or concrete Poseidon theorem.

This is a typed security model. Canonical Poseidon encodings and extraction of
these frames from actual PCD proofs are separate implementation obligations.
The nullifier function consumes the certified note and payment-key opening.
`seedPairOrCollision` reconciles distinct NoteSeed/SpendAction openings by
computing a payment hash collision. `loggedPairOrBreak` consumes the reconciled
frames; extraction of those frames from proofs is not established here.
-/

namespace Tachyon.SpendPairing

open Foundation.Oracle Foundation.Oracle.OracleComp

inductive Effect where
  | spend
  | output
  deriving DecidableEq

inductive Input (V G : Type*) where
  | payment (pak : Authorization.PaymentInput V G)
  | note (note : Authorization.NoteInput V)
  | nonce (effect : Effect) (theta cm : V)
  | digest (descriptor : OutputPairing.DigestInput G)
  deriving DecidableEq

structure Frame (V G : Type*) where
  note : Authorization.NoteInput V
  pak : Option (Authorization.PaymentInput V G)
  theta : V
  cm : V
  cv : G
  rk : G

variable {V G : Type*}

def Frame.effect (frame : Frame V G) : Effect :=
  match frame.pak with | some _ => .spend | none => .output

def Frame.nonceInput (frame : Frame V G) : Input V G := .nonce frame.effect frame.theta frame.cm
def Frame.descriptor (frame : Frame V G) : OutputPairing.DigestInput G := ⟨frame.cv, frame.rk⟩

def keyOf : Input V G → Option G
  | .payment pak => some pak.ak
  | _ => none

def paymentGuess : Input V G → Option V
  | .note note => some note.pk
  | _ => none

def commitmentGuess : Input V G → Option V
  | .nonce _ _ cm => some cm
  | _ => none

variable {K : Type*} [Field K] [AddCommGroup G] [Module K G]

structure Model (V K G : Type*) where
  base : G
  embed : V → K
  pad : Authorization.NoteInput V → V
  nullifier : Authorization.NoteInput V → Authorization.PaymentInput V G → ℕ → V

def Frame.offset (frame : Frame V G) : G :=
  match frame.pak with | some pak => pak.ak | none => 0

structure Valid (m : Model V K G) (table : Input V G → V) (frame : Frame V G) : Prop where
  note : table (.note frame.note) = frame.cm
  payment : ∀ pak, frame.pak = some pak → table (.payment pak) = frame.note.pk
  key : frame.rk = frame.offset + m.embed (table frame.nonceInput) • m.base

def Frame.tachygrams (frame : Frame V G) (m : Model V K G) (epoch : ℕ) : V × V :=
  match frame.pak with
  | some pak => (m.nullifier frame.note pak epoch, m.nullifier frame.note pak (epoch + 1))
  | none => (frame.cm, m.pad frame.note)

variable [DecidableEq V] [DecidableEq G]

/-- Reconcile the seed opening that determines the actual nullifiers with
the action opening that determines the randomized key. Equality of payment
hashes is checked on these two supplied inputs, not assumed injective. -/
def seedPairOrCollision (m : Model V K G) (table : Input V G → V)
    (frame : Frame V G) (valid : Valid m table frame) (seedPak actionPak : Authorization.PaymentInput V G)
    (hpak : frame.pak = some actionPak) (hseed : table (.payment seedPak) = frame.note.pk) (epoch : ℕ) :
    ((m.nullifier frame.note seedPak epoch, m.nullifier frame.note seedPak (epoch + 1)) =
      frame.tachygrams m epoch) ⊕' Authorization.Collision table := by
  by_cases heq : seedPak = actionPak
  · exact .inl (by simp [Frame.tachygrams, hpak, heq])
  · exact .inr ⟨.payment seedPak, .payment actionPak,
      (fun h => heq (Input.payment.inj h)), hseed.trans (valid.payment actionPak hpak).symm⟩

/-- Equal nonce inputs fix the action kind and commitment. Comparing note
and payment openings then fixes the pair, or computes a typed hash collision. -/
def sameNoncePairOrCollision (m : Model V K G) (table : Input V G → V)
    (left right : Frame V G) (epoch : ℕ) (hl : Valid m table left) (hr : Valid m table right)
    (hsame : left.nonceInput = right.nonceInput) :
    (left.tachygrams m epoch = right.tachygrams m epoch) ⊕' Authorization.Collision table := by
  have hnonce := Input.nonce.inj hsame
  have hcm : left.cm = right.cm := hnonce.2.2
  by_cases hnote : left.note = right.note
  · cases hlpak : left.pak with
    | none =>
      cases hrpak : right.pak with
      | none => exact .inl (by simp [Frame.tachygrams, hlpak, hrpak, hcm, hnote])
      | some pak => simp [Frame.nonceInput, Frame.effect, hlpak, hrpak] at hsame
    | some lpak =>
      cases hrpak : right.pak with
      | none => simp [Frame.nonceInput, Frame.effect, hlpak, hrpak] at hsame
      | some rpak =>
        by_cases hpak : lpak = rpak
        · exact .inl (by simp [Frame.tachygrams, hlpak, hrpak, hnote, hpak])
        · exact .inr ⟨.payment lpak, .payment rpak,
            (fun heq => hpak (Input.payment.inj heq)),
            (hl.payment lpak hlpak).trans (hnote ▸ (hr.payment rpak hrpak).symm)⟩
  · exact .inr ⟨.note left.note, .note right.note,
      (fun heq => hnote (Input.note.inj heq)), hl.note.trans (hcm.trans hr.note.symm)⟩

/-- Four reads cover each supplied frame, including a duplicate note read
for an output's absent payment key. Deduplication removes that repeat. -/
def Frame.points (frame : Frame V G) : Fin 4 → Input V G :=
  ![.note frame.note, (match frame.pak with | some pak => .payment pak | none => .note frame.note),
    frame.nonceInput, .digest frame.descriptor]

structure Located (history : List (Input V G × V)) (frame : Frame V G) where
  note : Fin history.length
  nonce : Fin history.length
  payment : Fin history.length
  note_input : history[note.val].1 = .note frame.note
  nonce_input : history[nonce.val].1 = frame.nonceInput
  payment_input : ∀ pak, frame.pak = some pak → history[payment.val].1 = .payment pak

def locate (history : List (Input V G × V)) (frame : Frame V G)
    (hmem : ∀ i, frame.points i ∈ history.map Prod.fst) : Located history frame where
  note := observationIndex history (frame.points 0) (hmem 0)
  nonce := observationIndex history (frame.points 2) (hmem 2)
  payment := observationIndex history (frame.points 1) (hmem 1)
  note_input := observationIndex_input history (frame.points 0) (hmem 0)
  nonce_input := observationIndex_input history (frame.points 2) (hmem 2)
  payment_input := by
    intro pak hpak
    simpa [Frame.points, hpak] using observationIndex_input history (frame.points 1) (hmem 1)

def pairPoints (pair : Frame V G × Frame V G) : Fin 8 → Input V G :=
  Fin.append pair.1.points pair.2.points

def offsetReadyOrPrediction (m : Model V K G) (table : Input V G → V)
    (history : List (Input V G × V)) (hnodup : (history.map Prod.fst).Nodup)
    (hconsistent : ∀ i : Fin history.length, table history[i.val].1 = history[i.val].2)
    (frame : Frame V G) (valid : Valid m table frame) (located : Located history frame) :
    (frame.offset ∈ insert 0 (PairingTargets.keys keyOf (history.take located.nonce.val))) ⊕'
      (OracleDependencies.PredictionHit paymentGuess history ⊕'
        OracleDependencies.PredictionHit commitmentGuess history) := by
  cases hpak : frame.pak with
  | none => exact .inl (by simp [Frame.offset, hpak])
  | some pak =>
    have hpayment : history[located.payment.val].2 = frame.note.pk := by
      rw [← hconsistent located.payment, located.payment_input pak hpak]
      exact valid.payment pak hpak
    have hnote : history[located.note.val].2 = frame.cm := by
      rw [← hconsistent located.note, located.note_input]
      exact valid.note
    have hfirst : history[located.payment.val].1 ≠ history[located.note.val].1 := by
      rw [located.payment_input pak hpak, located.note_input]
      intro heq; cases heq
    have hsecond : history[located.note.val].1 ≠ history[located.nonce.val].1 := by
      rw [located.note_input, located.nonce_input]
      intro heq; cases heq
    have hfirstWord : paymentGuess history[located.note.val].1 = some history[located.payment.val].2 := by
      rw [located.note_input, hpayment]; rfl
    have hsecondWord : commitmentGuess history[located.nonce.val].1 = some history[located.note.val].2 := by
      rw [located.nonce_input, hnote]; rfl
    cases OracleDependencies.chainOrPrediction paymentGuess commitmentGuess history hnodup
        located.payment located.note located.nonce hfirst hsecond hfirstWord hsecondWord with
    | inr prediction => exact .inr prediction
    | inl hbefore =>
      apply PSum.inl
      apply Finset.mem_insert_of_mem
      apply (PairingTargets.mem_keys_iff keyOf _ _).mpr
      refine ⟨history[located.payment.val],
        OracleDependencies.row_mem_take history located.payment located.nonce.val hbefore, ?_⟩
      rw [located.payment_input pak hpak]
      simp [keyOf, Frame.offset, hpak]

omit [AddCommGroup G] [DecidableEq V] in
theorem keys_take_mono (history : List (Input V G × V)) (i j : ℕ) (hle : i ≤ j) :
    PairingTargets.keys keyOf (history.take i) ⊆ PairingTargets.keys keyOf (history.take j) := by
  intro key hkey
  obtain ⟨row, hrow, hkey⟩ := (PairingTargets.mem_keys_iff keyOf _ _).mp hkey
  obtain ⟨n, hn, heq⟩ := List.mem_iff_getElem.mp hrow
  have hnlen : n < history.length := by simp only [List.length_take] at hn; omega
  have hnj : n < j := by simp only [List.length_take] at hn; omega
  have heq' : history[n] = row := by simpa only [List.getElem_take] using heq
  exact (PairingTargets.mem_keys_iff keyOf _ _).mpr
    ⟨row, heq' ▸ OracleDependencies.row_mem_take history ⟨n, hnlen⟩ j hnj, hkey⟩

structure NonceHit (m : Model V K G) (history : List (Input V G × V)) where
  position : Fin history.length
  effect : Effect
  theta : V
  cm : V
  input_eq : history[position.val].1 = .nonce effect theta cm
  fresh : history[position.val].1 ∉ (history.take position.val).map Prod.fst
  hit : m.embed history[position.val].2 • m.base ∈
    PairingTargets.targets m.embed m.base keyOf (history.take position.val)

inductive Break (m : Model V K G) (table : Input V G → V) (history : List (Input V G × V))
  | hash (witness : Authorization.Collision table)
  | paymentPrediction (witness : OracleDependencies.PredictionHit paymentGuess history)
  | commitmentPrediction (witness : OracleDependencies.PredictionHit commitmentGuess history)
  | nonce (witness : NonceHit m history)

def nonceHitOfLater (m : Model V K G) (table : Input V G → V)
    (history : List (Input V G × V)) (hnodup : (history.map Prod.fst).Nodup)
    (hconsistent : ∀ i : Fin history.length, table history[i.val].1 = history[i.val].2)
    (old new : Frame V G) (hold : Valid m table old) (hnew : Valid m table new)
    (oldLoc : Located history old) (newLoc : Located history new)
    (hbefore : oldLoc.nonce.val < newLoc.nonce.val) (heq : new.rk = old.rk)
    (holdReady : old.offset ∈ insert 0 (PairingTargets.keys keyOf (history.take oldLoc.nonce.val)))
    (hnewReady : new.offset ∈ insert 0 (PairingTargets.keys keyOf (history.take newLoc.nonce.val))) :
    NonceHit m history := by
  have holdOffset : old.offset ∈ insert 0 (PairingTargets.keys keyOf (history.take newLoc.nonce.val)) := by
    rcases Finset.mem_insert.mp holdReady with hzero | hkey
    · exact Finset.mem_insert.mpr (.inl hzero)
    · exact Finset.mem_insert_of_mem (keys_take_mono history _ _ hbefore.le hkey)
  have holdWord : history[oldLoc.nonce.val].2 ∈ PairingTargets.words (history.take newLoc.nonce.val) :=
    (PairingTargets.mem_words_iff _ _).mpr ⟨_,
      OracleDependencies.row_mem_take history oldLoc.nonce newLoc.nonce.val hbefore, rfl⟩
  have oldKey : old.rk = old.offset + m.embed history[oldLoc.nonce.val].2 • m.base := by
    rw [hold.key, ← oldLoc.nonce_input, hconsistent oldLoc.nonce]
  have newKey : new.rk = new.offset + m.embed history[newLoc.nonce.val].2 • m.base := by
    rw [hnew.key, ← newLoc.nonce_input, hconsistent newLoc.nonce]
  exact ⟨newLoc.nonce, new.effect, new.theta, new.cm, newLoc.nonce_input,
    OracleDependencies.input_fresh history hnodup newLoc.nonce,
    PairingTargets.collision_mem_targets m.embed m.base keyOf _ holdOffset hnewReady holdWord
      (newKey.symm.trans (heq.trans oldKey))⟩

/-- Complete deterministic spend/spend, output/output and mixed comparison.
The nonce/prediction branches are counted bad events, not hash collisions or
a theorem that the concrete hash is secure. -/
def pairOrBreak (m : Model V K G) (table : Input V G → V)
    (history : List (Input V G × V)) (hnodup : (history.map Prod.fst).Nodup)
    (hconsistent : ∀ i : Fin history.length, table history[i.val].1 = history[i.val].2)
    (left right : Frame V G) (epoch : ℕ) (hl : Valid m table left) (hr : Valid m table right)
    (ll : Located history left) (rl : Located history right)
    (hdigest : table (.digest left.descriptor) = table (.digest right.descriptor)) :
    (left.tachygrams m epoch = right.tachygrams m epoch) ⊕' Break m table history := by
  by_cases hdesc : left.descriptor = right.descriptor
  · by_cases hnonce : left.nonceInput = right.nonceInput
    · cases sameNoncePairOrCollision m table left right epoch hl hr hnonce with
      | inl heq => exact .inl heq
      | inr collision => exact .inr (.hash collision)
    · cases offsetReadyOrPrediction m table history hnodup hconsistent left hl ll with
      | inr prediction =>
        cases prediction with
        | inl witness => exact .inr (.paymentPrediction witness)
        | inr witness => exact .inr (.commitmentPrediction witness)
      | inl lready =>
        cases offsetReadyOrPrediction m table history hnodup hconsistent right hr rl with
        | inr prediction =>
          cases prediction with
          | inl witness => exact .inr (.paymentPrediction witness)
          | inr witness => exact .inr (.commitmentPrediction witness)
        | inl rready =>
          have hrk : left.rk = right.rk := congrArg OutputPairing.DigestInput.rk hdesc
          by_cases hbefore : ll.nonce.val < rl.nonce.val
          · exact .inr (.nonce (nonceHitOfLater m table history hnodup hconsistent
              left right hl hr ll rl hbefore hrk.symm lready rready))
          · have hne : ll.nonce.val ≠ rl.nonce.val := by
              intro heq
              apply hnonce
              calc left.nonceInput = history[ll.nonce.val].1 := ll.nonce_input.symm
                   _ = history[rl.nonce.val].1 := by simp only [heq]
                   _ = right.nonceInput := rl.nonce_input
            have hafter : rl.nonce.val < ll.nonce.val := by omega
            exact .inr (.nonce (nonceHitOfLater m table history hnodup hconsistent
              right left hr hl rl ll hafter hrk rready lready))
  · exact .inr (.hash ⟨.digest left.descriptor, .digest right.descriptor,
      (fun heq => hdesc (Input.digest.inj heq)), hdigest⟩)

def history (program : OracleComp (Input V G) V (Frame V G × Frame V G))
    (table : Input V G → V) : List (Input V G × V) :=
  (dedup [] (withReads pairPoints program)).observations table

/-- The output's eight designated reads supply every location required by
the reduction, even when the adversary guessed all hashes without querying. -/
def loggedPairOrBreak (m : Model V K G)
    (program : OracleComp (Input V G) V (Frame V G × Frame V G)) (table : Input V G → V)
    (epoch : ℕ) (hl : Valid m table (program.run table).1) (hr : Valid m table (program.run table).2)
    (hdigest : table (.digest (program.run table).1.descriptor) =
      table (.digest (program.run table).2.descriptor)) :
    ((program.run table).1.tachygrams m epoch = (program.run table).2.tachygrams m epoch) ⊕'
      Break m table (history program table) := by
  have hmem : ∀ i, pairPoints (program.run table) i ∈ (history program table).map Prod.fst := by
    intro i
    simpa [history, observations, List.map_map, Function.comp_def] using
      designated_mem_normalized pairPoints program table i
  have hlmem : ∀ i, (program.run table).1.points i ∈ (history program table).map Prod.fst := by
    intro i
    simpa only [pairPoints, Fin.append_left] using hmem (Fin.castAdd 4 i)
  have hrmem : ∀ i, (program.run table).2.points i ∈ (history program table).map Prod.fst := by
    intro i
    simpa only [pairPoints, Fin.append_right] using hmem (Fin.natAdd 4 i)
  apply pairOrBreak m table _ (OracleDependencies.normalized_inputs_nodup _ table) _
    (program.run table).1 (program.run table).2 epoch hl hr
    (locate _ _ hlmem) (locate _ _ hrmem) hdigest
  intro i
  exact OracleDependencies.observations_consistent _ table _ (List.getElem_mem i.isLt)

omit [AddCommGroup G] in
theorem history_length_le {program : OracleComp (Input V G) V (Frame V G × Frame V G)} {Q : ℕ}
    (hprogram : QueryBound program Q) (table : Input V G → V) :
    (history program table).length ≤ Q + 8 := by
  simp only [history, observations, List.length_map]
  exact queries_length_le (dedup_queryBound (queryBound_withReads pairPoints hprogram) []) table

section Counting

variable [Fintype V] [DecidableEq K]

/-- One prefix-fixed set covers every non-hash break branch. Its definition
does not depend on the final chosen frame, nonce position, or fresh answer. -/
def badWords (m : Model V K G) (prior : List (Input V G × V)) : Finset V :=
  (PairingTargets.keys paymentGuess prior ∪ PairingTargets.keys commitmentGuess prior) ∪
    (Finset.univ.filter fun word =>
      m.embed word • m.base ∈ PairingTargets.targets m.embed m.base keyOf prior)

theorem badWords_card_le (m : Model V K G) (hembed : Function.Injective m.embed)
    (hbase : m.base ≠ 0) (prior : List (Input V G × V)) :
    (badWords m prior).card ≤ 2 * prior.length + (prior.length + 1) * prior.length * (prior.length + 1) := by
  calc
    _ ≤ (PairingTargets.keys paymentGuess prior ∪ PairingTargets.keys commitmentGuess prior).card +
        (Finset.univ.filter fun word =>
          m.embed word • m.base ∈ PairingTargets.targets m.embed m.base keyOf prior).card :=
      Finset.card_union_le _ _
    _ ≤ ((PairingTargets.keys paymentGuess prior).card +
        (PairingTargets.keys commitmentGuess prior).card) +
        ((prior.length + 1) * prior.length * (prior.length + 1)) :=
      Nat.add_le_add (Finset.card_union_le _ _) (PairingTargets.eligible_words_card_le
        m.embed hembed m.base hbase keyOf prior)
    _ ≤ _ := by
      have hp := PairingTargets.keys_card_le paymentGuess prior
      have hc := PairingTargets.keys_card_le commitmentGuess prior
      omega

omit [DecidableEq K] in
theorem badWords_prefix_update {α : Type*} (m : Model V K G)
    (n : ℕ) (program : OracleComp (Input V G) V α) (table : Input V G → V)
    (input : Input V G) (word : V) (hfresh : input ∉ (program.queries table).take n) :
    badWords m (before n program (Function.update table input word)) =
      badWords m (before n program table) :=
  congrArg (badWords m) (before_update n program table input word hfresh)

structure BadWordHit (m : Model V K G) (history : List (Input V G × V)) where
  position : Fin history.length
  fresh : history[position.val].1 ∉ (history.take position.val).map Prod.fst
  hit : history[position.val].2 ∈ badWords m (history.take position.val)

/-- Hash collisions remain a separate explicit outcome. Every other failure
identifies a real query whose answer lies in the fixed prefix's bad-word set. -/
def Break.hashOrBadWord (m : Model V K G) (table : Input V G → V)
    (history : List (Input V G × V)) : Break m table history →
    Authorization.Collision table ⊕' BadWordHit m history
  | .hash witness => .inl witness
  | .paymentPrediction witness => .inr ⟨witness.position, witness.fresh,
      Finset.mem_union_left _ (Finset.mem_union_left _ witness.hit)⟩
  | .commitmentPrediction witness => .inr ⟨witness.position, witness.fresh,
      Finset.mem_union_left _ (Finset.mem_union_right _ witness.hit)⟩
  | .nonce witness => .inr ⟨witness.position, witness.fresh,
      Finset.mem_union_right _ (Finset.mem_filter.mpr ⟨Finset.mem_univ _, witness.hit⟩)⟩

theorem badWords_uniform_fraction_le (m : Model V K G) (hembed : Function.Injective m.embed)
    (hbase : m.base ≠ 0) (prior : List (Input V G × V)) :
    ((badWords m prior).card : ℚ) / Fintype.card V ≤
      ((2 * prior.length + (prior.length + 1) * prior.length * (prior.length + 1) : ℕ) : ℚ) /
        Fintype.card V := by
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  exact_mod_cast badWords_card_le m hembed hbase prior

theorem history_badWords_card_le (m : Model V K G) (hembed : Function.Injective m.embed)
    (hbase : m.base ≠ 0) {program : OracleComp (Input V G) V (Frame V G × Frame V G)} {Q : ℕ}
    (hprogram : QueryBound program Q) (table : Input V G → V)
    (i : Fin (history program table).length) :
    (badWords m ((history program table).take i.val)).card ≤
      2 * (Q + 8) + (Q + 9) * (Q + 8) * (Q + 9) := by
  have htotal := history_length_le hprogram table
  have hlen : ((history program table).take i.val).length ≤ Q + 8 := by
    simp only [List.length_take]
    omega
  have hnext : ((history program table).take i.val).length + 1 ≤ Q + 9 := by omega
  exact (badWords_card_le m hembed hbase _).trans
    (Nat.add_le_add (Nat.mul_le_mul_left 2 hlen)
      (Nat.mul_le_mul (Nat.mul_le_mul hnext hlen) hnext))

/-- Conditional pairing reduction with the bad-event hypothesis made
explicit. There is no global hash-injectivity premise: failure still returns
the concrete colliding inputs. A random-oracle theorem must bound the chance
that this fresh-answer avoidance condition fails over the adaptive execution. -/
def loggedPairOrHashCollision (m : Model V K G)
    (program : OracleComp (Input V G) V (Frame V G × Frame V G)) (table : Input V G → V)
    (epoch : ℕ) (hl : Valid m table (program.run table).1) (hr : Valid m table (program.run table).2)
    (hdigest : table (.digest (program.run table).1.descriptor) =
      table (.digest (program.run table).2.descriptor))
    (havoid : ∀ i : Fin (history program table).length,
      (history program table)[i.val].2 ∉ badWords m ((history program table).take i.val)) :
    ((program.run table).1.tachygrams m epoch = (program.run table).2.tachygrams m epoch) ⊕'
      Authorization.Collision table :=
  match loggedPairOrBreak m program table epoch hl hr hdigest with
  | .inl heq => .inl heq
  | .inr failure =>
    match failure.hashOrBadWord m table _ with
    | .inl collision => .inr collision
    | .inr witness => False.elim (havoid witness.position witness.hit)

end Counting

namespace Examples

def model : Model ℚ ℚ ℚ := ⟨1, id, fun note => note.value, fun note pak epoch => note.psi + pak.nk + epoch⟩
def note : Authorization.NoteInput ℚ := ⟨1, 0, 2, 0⟩
def pak : Authorization.PaymentInput ℚ ℚ := ⟨3, 5⟩
def spend : Frame ℚ ℚ := ⟨note, some pak, 0, 7, 2, 4⟩
def output : Frame ℚ ℚ := ⟨note, none, 0, 7, 2, 4⟩
def table : Input ℚ ℚ → ℚ
  | .payment _ => 0
  | .note _ => 7
  | .nonce .spend _ _ => 1
  | .nonce .output _ _ => 4
  | .digest _ => 0

theorem spend_valid : Valid model table spend := by
  refine ⟨rfl, ?_, ?_⟩
  · intro p hp
    have : p = pak := Option.some.inj hp.symm
    subst p; rfl
  · norm_num [Frame.offset, Frame.nonceInput, Frame.effect, spend, pak, model, table]

theorem output_valid : Valid model table output := by
  refine ⟨rfl, ?_, ?_⟩
  · intro p hp; cases hp
  · norm_num [Frame.offset, Frame.nonceInput, Frame.effect, output, model, table]

def causalProgram (pair : Frame ℚ ℚ × Frame ℚ ℚ) : OracleComp (Input ℚ ℚ) ℚ (Frame ℚ ℚ × Frame ℚ ℚ) :=
  .query (.payment pak) (fun _ => .query (.note note) (fun _ =>
    .query spend.nonceInput (fun _ => .query output.nonceInput (fun _ => .pure pair))))

def mixedResult := loggedPairOrBreak model (causalProgram (spend, output)) table 0
  spend_valid output_valid rfl
def reversedResult := loggedPairOrBreak model (causalProgram (output, spend)) table 0
  output_valid spend_valid rfl
def sameResult := loggedPairOrBreak model (.pure (spend, spend)) table 0 spend_valid spend_valid rfl
def paymentGuessResult := loggedPairOrBreak model (.pure (spend, output)) table 0
  spend_valid output_valid rfl
def lateNote : OracleComp (Input ℚ ℚ) ℚ (Frame ℚ ℚ × Frame ℚ ℚ) :=
  .query (.payment pak) (fun _ => .query spend.nonceInput (fun _ => .pure (spend, output)))
def noteGuessResult := loggedPairOrBreak model lateNote table 0 spend_valid output_valid rfl

#guard spend.nonceInput != output.nonceInput
#guard match sameResult with | .inl _ => true | .inr _ => false
#guard match mixedResult with | .inr (.nonce hit) => hit.position.val == 3 | _ => false
#guard match reversedResult with | .inr (.nonce hit) => hit.position.val == 3 | _ => false
#guard match paymentGuessResult with | .inr (.paymentPrediction hit) => hit.position.val == 1 | _ => false
#guard match noteGuessResult with | .inr (.commitmentPrediction hit) => hit.position.val == 2 | _ => false
#guard (history (causalProgram (spend, output)) table).length == 5

def secondSpend : Frame ℚ ℚ := { spend with theta := 1 }
theorem secondSpend_valid : Valid model table secondSpend := by
  refine ⟨rfl, spend_valid.payment, ?_⟩
  norm_num [Frame.offset, Frame.nonceInput, Frame.effect, secondSpend, spend, pak, model, table]
def spendProgram : OracleComp (Input ℚ ℚ) ℚ (Frame ℚ ℚ × Frame ℚ ℚ) :=
  .query (.payment pak) (fun _ => .query (.note note) (fun _ => .pure (spend, secondSpend)))
def spendSpendResult := loggedPairOrBreak model spendProgram table 0 spend_valid secondSpend_valid rfl
#guard match spendSpendResult with | .inr (.nonce hit) => hit.position.val == 4 | _ => false

def changedCV : Frame ℚ ℚ := { spend with cv := 3 }
def changedNote : Frame ℚ ℚ := { spend with note := { note with psi := 1 } }
def changedPak : Frame ℚ ℚ := { spend with pak := some ⟨3, 6⟩ }

theorem changedCV_valid : Valid model table changedCV :=
  ⟨spend_valid.note, spend_valid.payment, spend_valid.key⟩
theorem changedNote_valid : Valid model table changedNote := by
  refine ⟨rfl, ?_, ?_⟩
  · intro p hp; rfl
  · exact spend_valid.key
theorem changedPak_valid : Valid model table changedPak := by
  refine ⟨rfl, ?_, ?_⟩
  · intro p hp; rfl
  · norm_num [Frame.offset, Frame.nonceInput, Frame.effect, changedPak, spend, model, table]

def digestCollision := loggedPairOrBreak model (.pure (spend, changedCV)) table 0
  spend_valid changedCV_valid rfl
def noteCollision := loggedPairOrBreak model (.pure (spend, changedNote)) table 0
  spend_valid changedNote_valid rfl
def paymentCollision := loggedPairOrBreak model (.pure (spend, changedPak)) table 0
  spend_valid changedPak_valid rfl

#guard match digestCollision with
  | .inr (.hash witness) => match witness.left with | .digest _ => true | _ => false
  | _ => false
#guard match noteCollision with
  | .inr (.hash witness) => match witness.left with | .note _ => true | _ => false
  | _ => false
#guard match paymentCollision with
  | .inr (.hash witness) => match witness.left with | .payment _ => true | _ => false
  | _ => false

#guard match loggedPairOrBreak model (.pure (output, output)) table 0 output_valid output_valid rfl with
  | .inl _ => true
  | .inr _ => false
#guard match seedPairOrCollision model table spend spend_valid pak pak rfl rfl 0 with
  | .inl _ => true
  | .inr _ => false
#guard match seedPairOrCollision model table spend spend_valid ⟨3, 6⟩ pak rfl rfl 0 with
  | .inr _ => true
  | .inl _ => false

def finiteModel : Model Bool ℚ ℚ :=
  ⟨1, fun word => if word then 1 else 0, fun n => n.psi, fun _ _ _ => false⟩
def finitePrior : List (Input Bool ℚ × Bool) := [(.note ⟨false, false, false, false⟩, true)]

#guard (badWords finiteModel []).card == 0
#guard (badWords finiteModel finitePrior).card == 2
#guard decide (false ∈ badWords finiteModel finitePrior)
#guard decide (true ∈ badWords finiteModel finitePrior)

end Examples

end Tachyon.SpendPairing

namespace Tachyon.ScalarEncodings

variable {G : Type*} [AddCommGroup G] [Fact scalarModulus.Prime]
  [Module (ZMod scalarModulus) G] [DecidableEq G]

local instance : NeZero noteModulus := ⟨by decide⟩

/-- Canonical Pasta word lifting discharges the embedding premise of the
spend-pairing bad-word count. Primality remains an explicit input. -/
theorem pasta_spend_badWords_card_le
    (m : SpendPairing.Model (ZMod noteModulus) (ZMod scalarModulus) G)
    (hembed : m.embed = noteWordLift) (hbase : m.base ≠ 0)
    (prior : List (SpendPairing.Input (ZMod noteModulus) G × ZMod noteModulus)) :
    (SpendPairing.badWords m prior).card ≤
      2 * prior.length + (prior.length + 1) * prior.length * (prior.length + 1) :=
  SpendPairing.badWords_card_le m (hembed ▸ noteWordLift_injective) hbase prior

end Tachyon.ScalarEncodings
