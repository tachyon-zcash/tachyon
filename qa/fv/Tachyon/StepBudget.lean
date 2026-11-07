import Tachyon.FixedBase
import Tachyon.Value
import Tachyon.SpendBinding
import Tachyon.ProvenanceTraces
import Tachyon.Consensus.Bundle
import Tachyon.Idealization

/-!
# Accepted-path refinement for the six budgeted steps

The old predicates retain finite-export requirements (unlike permissive mock-only
identity outputs). Hashes are functions with their original typed inputs, not
injectivity axioms. `Certified` is an actual Start/Middle/End derivation.
Polynomial checks retain the existing idealization as polynomial identities.
-/

namespace Tachyon.StepBudget

open FixedBase

variable {F A K G : Type*} [Field F] [Field K] [AddCommGroup G] [Module K G]

inductive PrivateHeader
  | r24 | r54 | r85 | g24 | g54 | g85 | prepared | feeOpening | ready
  deriving DecidableEq

def privateSuffix : PrivateHeader → ℕ
  | .r24 => 17 | .r54 => 18 | .r85 => 19 | .g24 => 20 | .g54 => 21 | .g85 => 22
  | .prepared => 23 | .feeOpening => 24 | .ready => 25

theorem privateSuffix_injective : Function.Injective privateSuffix := by
  intro a b h
  cases a <;> cases b <;> simp_all [privateSuffix]

/-- No new private header can be confused with any pre-existing suffix 0..16,
including Actions (15) and Stamp (6). These are actual serialization tags. -/
theorem privateSuffix_not_terminal (h : PrivateHeader) : 16 < privateSuffix h := by
  cases h <;> decide

structure Note (F : Type*) where
  pk : F
  psi : F
  rcm : F
  amount : ℕ

structure Pak (F G : Type*) where
  ak : G
  nk : F

structure Model (F G : Type*) where
  valueBase : G
  blindBase : G
  keyBase : G
  sentinel : G
  scalarModulus : ℕ
  money : ℕ
  epochLimit : ℕ
  commitment : Note F → F
  pad : Note F → F
  payment : Pak F G → F
  master : F → F → F
  nullifier : F → ℕ → F
  outputAlpha : F → F → ℕ
  spendAlpha : F → F → ℕ
  feeBlind : F → F → F → ℕ
  actionDigest : G → G → F
  feeDigest : G → ℕ → F

def Model.bases (m : Model F G) : Base → G | .blind => m.blindBase | .action => m.keyBase

def Certified (m : Model F G) (b : Base) (s : Limbs) (consume : G → Prop) : Prop :=
  ∃ point, Accepted m.bases m.sentinel m.scalarModulus b .finish ⟨s, point⟩ ∧ consume point.decode

omit [Field F] in
theorem certified_iff [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (b : Base) (s : Limbs) (hc : s.canonical m.scalarModulus) (consume : G → Prop) :
    Certified m b s consume ↔ consume (s.value • m.bases b) :=
  consumer_refinement hJ b s hc consume

structure Output (F G : Type*) where
  cm : F
  pad : F
  cv : G

def OutputChecks (m : Model F G) (n : Note F) (o : Output F G) : Prop :=
  n.amount ≤ m.money ∧ o.cm = m.commitment n ∧ o.pad = m.pad n ∧
    o.cm ≠ 0 ∧ o.pad ≠ 0 ∧ o.cv ≠ 0

def OldOutputBind (m : Model F G) (n : Note F) (s : Limbs) (o : Output F G) : Prop :=
  OutputChecks m n o ∧ o.cv = valueCommit m.valueBase m.blindBase (-(n.amount : K)) (s.value : K)

def NewOutputBind (m : Model F G) (n : Note F) (s : Limbs) (o : Output F G) : Prop :=
  OutputChecks m n o ∧ Certified m .blind s (fun p => o.cv = (-(n.amount : K)) • m.valueBase + p)

theorem outputBind_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (n : Note F) (s : Limbs) (hc : s.canonical m.scalarModulus) (o : Output F G) :
    NewOutputBind (K := K) m n s o ↔ OldOutputBind (K := K) m n s o := by
  simp only [NewOutputBind, OldOutputBind, certified_iff m hJ _ _ hc,
    Model.bases, valueCommit, Nat.cast_smul_eq_nsmul]

structure Secret (F : Type*) where
  cm : F
  note : Note F
  masterKey : F

/-- NoteSeed is the unique producer: pk and mk use the same pak/nk and psi. -/
def SecretAccepted (m : Model F G) (s : Secret F) : Prop :=
  ∃ pak : Pak F G, pak.ak ≠ 0 ∧ s.note.pk = m.payment pak ∧
    s.masterKey = m.master pak.nk s.note.psi ∧ s.cm = m.commitment s.note

structure Prepared (F A : Type*) where
  header : SpendHeader F A
  pk : F
  amount : ℕ

def prepare (m : Model F G) (sp : NoteSpendable F A) (secret : Secret F) : Prepared F A :=
  ⟨⟨sp.cm, m.nullifier secret.masterKey sp.epoch_current,
    m.nullifier secret.masterKey (sp.epoch_current + 1), sp.anchor⟩, secret.note.pk, secret.note.amount⟩

def PrepareChecks (m : Model F G) (sp : NoteSpendable F A) (secret : Secret F) : Prop :=
  secret.cm = sp.cm ∧ secret.note.amount ≤ m.money ∧ sp.epoch_current + 1 < m.epochLimit ∧
    m.nullifier secret.masterKey sp.epoch_current ≠ 0 ∧ m.nullifier secret.masterKey (sp.epoch_current + 1) ≠ 0

/-- The only producer of SpendPrepared. Validity of the current epoch is inherited
from ValidSpendable; only its successor is locally bounded. -/
inductive PreparedAccepted (m : Model F G) (ValidSpendable : NoteSpendable F A → Prop) :
    Prepared F A → Prop
  | produce (sp : NoteSpendable F A) (secret : Secret F) :
      ValidSpendable sp → SecretAccepted m secret → PrepareChecks m sp secret →
      PreparedAccepted m ValidSpendable (prepare m sp secret)

theorem PreparedAccepted.provenance {m : Model F G} {ValidSpendable : NoteSpendable F A → Prop}
    {p : Prepared F A} (h : PreparedAccepted m ValidSpendable p) :
    ∃ sp secret, ValidSpendable sp ∧ SecretAccepted m secret ∧ PrepareChecks m sp secret ∧
      p = prepare m sp secret := by
  cases h with
  | produce sp secret hv hs hc => exact ⟨sp, secret, hv, hs, hc, rfl⟩

structure Spend (F A G : Type*) where
  prepared : Prepared F A
  cv : G

def OldSpendBind (m : Model F G) (ValidSpendable : NoteSpendable F A → Prop)
    (s : Limbs) (out : Spend F A G) : Prop :=
  (∃ sp secret, ValidSpendable sp ∧ SecretAccepted m secret ∧ PrepareChecks m sp secret ∧
    out.prepared = prepare m sp secret) ∧ out.cv ≠ 0 ∧
    out.cv = valueCommit m.valueBase m.blindBase (out.prepared.amount : K) (s.value : K)

def NewSpendBind (m : Model F G) (ValidSpendable : NoteSpendable F A → Prop)
    (s : Limbs) (out : Spend F A G) : Prop :=
  PreparedAccepted m ValidSpendable out.prepared ∧ out.prepared.amount ≤ m.money ∧ out.cv ≠ 0 ∧
    Certified m .blind s (fun p => out.cv = (out.prepared.amount : K) • m.valueBase + p)

theorem spendBind_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (valid : NoteSpendable F A → Prop) (s : Limbs) (hc : s.canonical m.scalarModulus)
    (out : Spend F A G) :
    NewSpendBind (K := K) m valid s out ↔ OldSpendBind (K := K) m valid s out := by
  simp only [NewSpendBind, OldSpendBind, certified_iff m hJ _ _ hc,
    Model.bases, valueCommit, Nat.cast_smul_eq_nsmul]
  constructor
  · rintro ⟨hp, _, hn, he⟩; exact ⟨hp.provenance, hn, he⟩
  · rintro ⟨⟨sp, secret, hv, hs, hchecks, heq⟩, hn, he⟩
    refine ⟨heq ▸ PreparedAccepted.produce sp secret hv hs hchecks, ?_, hn, he⟩
    simpa [heq, prepare] using hchecks.2.1

structure Action (F A G : Type*) [Field F] where
  rk : G
  digest : F
  stagedDigest : F
  stamp : Stamp F A

def ActionChecks (m : Model F G) (cv : G) (roots : Multiset F) (a : Action F A G) : Prop :=
  a.rk ≠ 0 ∧ a.digest = m.actionDigest cv a.rk ∧ a.stagedDigest = a.digest ∧
    a.stamp.actions = setPoly {a.stagedDigest} ∧ a.stamp.tachygrams = setPoly roots

def OldOutputAction (m : Model F G) (o : Output F G) (theta : F) (a : Action F A G) : Prop :=
  ActionChecks m o.cv {o.cm, o.pad} a ∧ a.rk = (m.outputAlpha theta o.cm : K) • m.keyBase

def NewOutputAction (m : Model F G) (o : Output F G) (theta : F) (a : Action F A G) : Prop :=
  ActionChecks m o.cv {o.cm, o.pad} a ∧
    Certified m .action (split (m.outputAlpha theta o.cm)) (fun p => a.rk = p)

theorem outputAction_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (o : Output F G) (theta : F)
    (hc : (split (m.outputAlpha theta o.cm)).canonical m.scalarModulus) (a : Action F A G) :
    NewOutputAction m o theta a ↔ OldOutputAction (K := K) m o theta a := by
  simp only [NewOutputAction, OldOutputAction, certified_iff m hJ _ _ hc, split_value,
    Model.bases, Nat.cast_smul_eq_nsmul]

def SpendActionChecks (m : Model F G) (s : Spend F A G) (pak : Pak F G)
    (a : Action F A G) : Prop :=
  pak.ak ≠ 0 ∧ m.payment pak = s.prepared.pk ∧ a.stamp.anchor = s.prepared.header.anchor ∧
    ActionChecks m s.cv {s.prepared.header.nf_current, s.prepared.header.nf_next} a

def OldSpendAction (m : Model F G) (s : Spend F A G) (pak : Pak F G) (theta : F)
    (a : Action F A G) : Prop :=
  SpendActionChecks m s pak a ∧ a.rk = pak.ak + (m.spendAlpha theta s.prepared.header.cm : K) • m.keyBase

def NewSpendAction (m : Model F G) (s : Spend F A G) (pak : Pak F G) (theta : F)
    (a : Action F A G) : Prop :=
  SpendActionChecks m s pak a ∧
    Certified m .action (split (m.spendAlpha theta s.prepared.header.cm)) (fun p => a.rk = pak.ak + p)

theorem spendAction_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (s : Spend F A G) (pak : Pak F G) (theta : F)
    (hc : (split (m.spendAlpha theta s.prepared.header.cm)).canonical m.scalarModulus)
    (a : Action F A G) :
    NewSpendAction m s pak theta a ↔ OldSpendAction (K := K) m s pak theta a := by
  simp only [NewSpendAction, OldSpendAction, certified_iff m hJ _ _ hc, split_value,
    Model.bases, Nat.cast_smul_eq_nsmul]

structure FeeOpening (G : Type*) where
  maximum : ℕ
  scalar : Limbs
  cv : G

structure Ready (F : Type*) where
  maximum : ℕ
  fee : ℕ
  digest : F
  change : F

def feeScalar (m : Model F G) (n : Note F) : Limbs := split (m.feeBlind n.pk n.psi n.rcm)

def FeeValueAccepted (m : Model F G) (o : FeeOpening G) : Prop :=
  o.maximum ≤ m.money ∧ o.cv ≠ 0 ∧
    Certified m .blind o.scalar (fun p => o.cv = (-(o.maximum : K)) • m.valueBase + p)

def FeeChecks (m : Model F G) (n : Note F) (fee : ℕ) (cv : G) (r : Ready F) : Prop :=
  n.amount ≤ m.money ∧ fee ≤ m.money ∧ fee ≤ n.amount ∧ n.amount - fee ≤ m.money ∧
    cv ≠ 0 ∧ r.maximum = n.amount ∧ r.fee = fee ∧ r.digest = m.feeDigest cv fee ∧
    r.change = m.commitment {n with amount := n.amount - fee} ∧ r.change ≠ 0

def OldFee (m : Model F G) (n : Note F) (fee : ℕ) (cv : G) (r : Ready F) : Prop :=
  FeeChecks m n fee cv r ∧
    cv = valueCommit m.valueBase m.blindBase (-(n.amount : K)) ((feeScalar m n).value : K)

/-- FeeBind is the sole producer. Maximum and both scalar limbs are linked to
the same fee opening before deriving the digest and change commitment. -/
def ReadyAccepted (m : Model F G) (n : Note F) (fee : ℕ) (cv : G) (r : Ready F) : Prop :=
  ∃ o : FeeOpening G, FeeValueAccepted (K := K) m o ∧ o.maximum = n.amount ∧
    o.scalar = feeScalar m n ∧ o.cv = cv ∧ FeeChecks m n fee cv r

theorem ready_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (n : Note F) (fee : ℕ) (hc : (feeScalar m n).canonical m.scalarModulus)
    (cv : G) (r : Ready F) :
    ReadyAccepted (K := K) m n fee cv r ↔ OldFee (K := K) m n fee cv r := by
  constructor
  · rintro ⟨o, ⟨_, _, hp⟩, hm, hs, hv, checks⟩
    have he := (certified_iff m hJ .blind (feeScalar m n) hc _).mp (hs ▸ hp)
    exact ⟨checks, by simpa [hm, hv, Model.bases, valueCommit, Nat.cast_smul_eq_nsmul] using he⟩
  · rintro ⟨checks, he⟩
    refine ⟨⟨n.amount, feeScalar m n, cv⟩, ⟨checks.1, checks.2.2.2.2.1, ?_⟩, rfl, rfl, rfl, checks⟩
    apply (certified_iff m hJ .blind _ hc _).mpr
    simpa [Model.bases, valueCommit, Nat.cast_smul_eq_nsmul] using he

theorem ReadyAccepted.provenance [DecidableEq G] {m : Model F G} (hJ : m.sentinel ≠ 0)
    {n : Note F} {fee : ℕ} {cv : G} {r : Ready F}
    (hc : (feeScalar m n).canonical m.scalarModulus) (h : ReadyAccepted (K := K) m n fee cv r) :
    FeeChecks m n fee cv r ∧
      cv = valueCommit m.valueBase m.blindBase (-(n.amount : K)) ((feeScalar m n).value : K) :=
  (ready_refinement m hJ n fee hc cv r).mp h

def FuseRoots (left out : Stamp F A) (r : Ready F) : Prop :=
  out.anchor = left.anchor ∧ out.actions = left.actions * setPoly {r.digest} ∧
    out.tachygrams = left.tachygrams * setPoly {r.change}

/-- Both roots are fields of the authenticated right input, fixed before z.
This predicate has no final-stage witnessed root that can solve for a residual. -/
def FuseAt (left out : Stamp F A) (right : Ready F) (z : F) : Prop :=
  out.actions.eval z = left.actions.eval z * (z - right.digest) ∧
    out.tachygrams.eval z = left.tachygrams.eval z * (z - right.change)

theorem FuseRoots.at {left out : Stamp F A} {right : Ready F}
    (h : FuseRoots left out right) (z : F) : FuseAt left out right z := by
  rcases h with ⟨_, ha, ht⟩
  simp [FuseAt, ha, ht, setPoly]

/-- The existing polynomial-identity error bound applies with the right input
fixed before the challenge. It is not a claim that arbitrary output fields
were fixed early, nor a new opening/Fiat-Shamir assumption. -/
theorem fee_bad_challenges [Fintype F] [DecidableEq F] (left out : Stamp F A) (right : Ready F)
    {n : ℕ} (hn : 1 ≤ n) (hl : left.actions.natDegree ≤ n) (ho : out.actions.natDegree ≤ n)
    (hbad : out.actions ≠ left.actions * setPoly {right.digest}) :
    (Finset.univ.filter fun z => out.actions.eval z = left.actions.eval z *
      (setPoly {right.digest}).eval z).card ≤ 2 * n := by
  apply card_product_check_le hbad hl _ ho
  simpa [setPoly] using hn

def OldFeeFuse (m : Model F G) (n : Note F) (fee : ℕ) (cv : G) (r : Ready F)
    (left out : Stamp F A) : Prop := OldFee (K := K) m n fee cv r ∧ FuseRoots left out r

def NewFeeFuse (m : Model F G) (n : Note F) (fee : ℕ) (cv : G) (r : Ready F)
    (left out : Stamp F A) : Prop := ReadyAccepted (K := K) m n fee cv r ∧ FuseRoots left out r

theorem feeFuse_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (n : Note F) (fee : ℕ) (hc : (feeScalar m n).canonical m.scalarModulus)
    (cv : G) (r : Ready F) (left out : Stamp F A) :
    NewFeeFuse (K := K) m n fee cv r left out ↔ OldFeeFuse (K := K) m n fee cv r left out := by
  simp only [NewFeeFuse, OldFeeFuse, ready_refinement m hJ n fee hc]

/-- FeeSeed's owner fields are staged; an input R certificate alone does not
authenticate newly witnessed pk/psi/rcm before the challenge. -/
def SeedChecks (m : Model F G) (n staged : Note F) (cv : G) (r : Ready F)
    (out : Stamp F A) : Prop :=
  n.amount = 0 ∧ n.pk = staged.pk ∧ n.psi = staged.psi ∧ n.rcm = staged.rcm ∧
    FeeChecks m n 0 cv r ∧ out.actions = setPoly {r.digest} ∧ out.tachygrams = setPoly {r.change}

def OldFeeSeed (m : Model F G) (n staged : Note F) (cv : G) (r : Ready F)
    (out : Stamp F A) : Prop :=
  SeedChecks m n staged cv r out ∧ cv = ((feeScalar m n).value : K) • m.blindBase

def NewFeeSeed (m : Model F G) (n staged : Note F) (cv : G) (r : Ready F)
    (out : Stamp F A) : Prop :=
  SeedChecks m n staged cv r out ∧ Certified m .blind (feeScalar m n) (fun p => cv = p)

theorem feeSeed_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (n staged : Note F) (hc : (feeScalar m n).canonical m.scalarModulus)
    (cv : G) (r : Ready F) (out : Stamp F A) :
    NewFeeSeed m n staged cv r out ↔ OldFeeSeed (K := K) m n staged cv r out := by
  simp only [NewFeeSeed, OldFeeSeed, certified_iff m hJ _ _ hc,
    Model.bases, Nat.cast_smul_eq_nsmul]

omit [Field F] [AddCommGroup G] in
/-- Erasure to the existing spend-nullifier abstraction is conditional on the
same cm-to-master-key interpretation that `SpendBinding` already uses. The
new preparation step preserves that interpretation and the lineage anchor. -/
theorem prepare_header_eq (m : Model F G) (sp : NoteSpendable F A) (secret : Secret F)
    (nf : F → ℕ → F) (hcm : secret.cm = sp.cm)
    (hnf : ∀ e, m.nullifier secret.masterKey e = nf secret.cm e) :
    (prepare m sp secret).header = spendBind nf sp := by
  simp [prepare, spendBind, hnf, hcm]

/-- A witness retains its semantic inputs when its private helper subgraphs
are erased or reconstructed. The terminal digest and anchor do not change. -/
inductive Witness (F A G : Type*) [Field F]
  | output (note : Note F) (blind : Limbs) (header : Output F G) (theta : F) (action : Action F A G)
  | spend (blind : Limbs) (header : Spend F A G) (pak : Pak F G) (theta : F) (action : Action F A G)
  | fuse (note : Note F) (fee : ℕ) (cv : G) (ready : Ready F) (left out : Stamp F A)
  | seed (note staged : Note F) (cv : G) (ready : Ready F) (out : Stamp F A)

def Witness.digest : Witness F A G → F
  | .output _ _ _ _ a | .spend _ _ _ _ a => a.digest
  | .fuse _ _ _ r _ _ | .seed _ _ _ r _ => r.digest

def Witness.anchor : Witness F A G → A
  | .output _ _ _ _ a | .spend _ _ _ _ a => a.stamp.anchor
  | .fuse _ _ _ _ left _ => left.anchor
  | .seed _ _ _ _ out => out.anchor

def OldAccepted (m : Model F G) (valid : NoteSpendable F A → Prop) : Witness F A G → Prop
  | .output n s o theta a => s.canonical m.scalarModulus ∧
      (split (m.outputAlpha theta o.cm)).canonical m.scalarModulus ∧
      OldOutputBind (K := K) m n s o ∧ OldOutputAction (K := K) m o theta a
  | .spend s out pak theta a => s.canonical m.scalarModulus ∧
      (split (m.spendAlpha theta out.prepared.header.cm)).canonical m.scalarModulus ∧
      OldSpendBind (K := K) m valid s out ∧ OldSpendAction (K := K) m out pak theta a
  | .fuse n fee cv r left out => (feeScalar m n).canonical m.scalarModulus ∧
      OldFeeFuse (K := K) m n fee cv r left out
  | .seed n staged cv r out => (feeScalar m n).canonical m.scalarModulus ∧
      OldFeeSeed (K := K) m n staged cv r out

def NewAccepted (m : Model F G) (valid : NoteSpendable F A → Prop) : Witness F A G → Prop
  | .output n s o theta a => s.canonical m.scalarModulus ∧
      (split (m.outputAlpha theta o.cm)).canonical m.scalarModulus ∧
      NewOutputBind (K := K) m n s o ∧ NewOutputAction m o theta a
  | .spend s out pak theta a => s.canonical m.scalarModulus ∧
      (split (m.spendAlpha theta out.prepared.header.cm)).canonical m.scalarModulus ∧
      NewSpendBind (K := K) m valid s out ∧ NewSpendAction m out pak theta a
  | .fuse n fee cv r left out => (feeScalar m n).canonical m.scalarModulus ∧
      NewFeeFuse (K := K) m n fee cv r left out
  | .seed n staged cv r out => (feeScalar m n).canonical m.scalarModulus ∧
      NewFeeSeed m n staged cv r out

theorem accepted_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (valid : NoteSpendable F A → Prop) (w : Witness F A G) :
    NewAccepted (K := K) m valid w ↔ OldAccepted (K := K) m valid w := by
  cases w with
  | output n s o theta a =>
      constructor
      · rintro ⟨hs, ha, hb, hk⟩
        exact ⟨hs, ha, (outputBind_refinement m hJ n s hs o).mp hb,
          (outputAction_refinement m hJ o theta ha a).mp hk⟩
      · rintro ⟨hs, ha, hb, hk⟩
        exact ⟨hs, ha, (outputBind_refinement m hJ n s hs o).mpr hb,
          (outputAction_refinement m hJ o theta ha a).mpr hk⟩
  | spend s out pak theta a =>
      constructor
      · rintro ⟨hs, ha, hb, hk⟩
        exact ⟨hs, ha, (spendBind_refinement m hJ valid s hs out).mp hb,
          (spendAction_refinement m hJ out pak theta ha a).mp hk⟩
      · rintro ⟨hs, ha, hb, hk⟩
        exact ⟨hs, ha, (spendBind_refinement m hJ valid s hs out).mpr hb,
          (spendAction_refinement m hJ out pak theta ha a).mpr hk⟩
  | fuse n fee cv r left out =>
      exact and_congr_right fun hc => feeFuse_refinement m hJ n fee hc cv r left out
  | seed n staged cv r out =>
      exact and_congr_right fun hc => feeSeed_refinement m hJ n staged hc cv r out

def Leaf (accepted : Witness F A G → Prop) (d : F) (a : A) :=
  {w : Witness F A G // accepted w ∧ w.digest = d ∧ w.anchor = a}

def eraseLeaf [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (valid : NoteSpendable F A → Prop) (d : F) (a : A)
    (leaf : Leaf (NewAccepted (K := K) m valid) d a) : Leaf (OldAccepted (K := K) m valid) d a :=
  ⟨leaf.val, (accepted_refinement m hJ valid leaf.val).mp leaf.property.1, leaf.property.2⟩

def reconstructLeaf [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (valid : NoteSpendable F A → Prop) (d : F) (a : A)
    (leaf : Leaf (OldAccepted (K := K) m valid) d a) : Leaf (NewAccepted (K := K) m valid) d a :=
  ⟨leaf.val, (accepted_refinement m hJ valid leaf.val).mpr leaf.property.1, leaf.property.2⟩

variable {Lift : Stamp F A → A → Type*}

/-- Both directions extend to every complete stamp path, including unmerges.
All existing bundle checks use the same terminal header and covered digests. -/
theorem stamp_refinement [DecidableEq G] (m : Model F G) (hJ : m.sentinel ≠ 0)
    (valid : NoteSpendable F A → Prop) (IsFee : F → Prop) (epoch : A → ℕ)
    (R : ℕ → F → Multiset F) (s : Stamp F A) :
    Nonempty (StampTrace IsFee epoch R (Leaf (NewAccepted (K := K) m valid)) Lift s) ↔
      Nonempty (StampTrace IsFee epoch R (Leaf (OldAccepted (K := K) m valid)) Lift s) :=
  StampTrace.refinement_iff (eraseLeaf m hJ valid) (reconstructLeaf m hJ valid)

theorem published_through_refinement [DecidableEq F] [DecidableEq G]
    (m : Model F G) (hJ : m.sentinel ≠ 0) (valid : NoteSpendable F A → Prop)
    {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F} {s : Stamp F A}
    (t : StampTrace IsFee epoch R (Leaf (NewAccepted (K := K) m valid)) Lift s)
    {covered : Multiset F} (hc : s.actions = setPoly covered) :
    s.tachygrams = setPoly (covered.bind (R (epoch s.anchor))) :=
  (t.mapLeaf (eraseLeaf m hJ valid)).forget.published hc

theorem bundle_through_refinement [DecidableEq F] [DecidableEq G]
    (m : Model F G) (hJ : m.sentinel ≠ 0) (valid : NoteSpendable F A → Prop)
    {Δ Φ : Type*} {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F}
    {actionDigest : Δ → F} {feeDigest : Φ → F} {descs : List Δ} {fee : Φ} {adjunctFees : List Φ}
    {stamp : PublishedStamp F A}
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp)
    (t : StampTrace IsFee epoch R (Leaf (NewAccepted (K := K) m valid)) Lift
      ⟨setPoly (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)),
        stamp.tachygramSet, stamp.anchor⟩) :
    (stamp.tachygrams : Multiset F) =
      (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)).bind (R (epoch stamp.anchor)) ∧
    R (epoch stamp.anchor) (feeDigest fee) ≤ (stamp.tachygrams : Multiset F) := by
  let erased : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp :=
    {h with proof := (t.mapLeaf (eraseLeaf m hJ valid)).forget}
  exact ⟨erased.tachygrams_eq, erased.fee_published⟩

end Tachyon.StepBudget
