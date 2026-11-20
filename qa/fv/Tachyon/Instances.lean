import Mathlib.Algebra.Field.ZMod
import Tachyon.Consensus.Spends

/-!
# A concrete instance

ragu's fv-preflight §4 asks for a concrete input satisfying every hypothesis, so that no theorem
holds for nothing. This module gives one at `ZMod 7`. It is a chain of two stamps in epoch 0. The
first publishes a note commitment. The second is a bundle with one spend of that note and its fee
change, proven by a `FeeFuse` over a `SpendAction` leaf whose spendable lineage is a
`SpendableInit` on the first stamp. The hash functions are concrete, and the call sets hold exactly
the calls the chain and the derivations make, so every scoped law holds on them.

* `covered_spends_hypotheses` discharges every hypothesis of `no_double_spend_of_covered_spends`
  except the second spend (`p₂`, `hsplit`, `hs₂`, `hfresh`), which is what it rules out, and
  `in_stamp_hypotheses` every hypothesis of `no_double_spend_in_stamp` except the second spend and
  `hindex`. Two examples apply both theorems to the instance with only the second spend left open.
  The same hypotheses discharge `CoveredSpend.pair_le`, `SpendDerivable.pair` and
  `SpendDerivable.lineage`.
* `bundle_verified` is a `BundleVerified` bundle, for the `BundleVerified` results, and its proof
  field is a `StampDerivable` header whose `IsFee` holds of the bundle's fee digest.
* `bucket_onChain_hypotheses` is a sealed QR bucket over the epoch's two stamps, for
  `QrBucketDerivable.covers` and `QrBucket.Covers.onChain`.
* `lift_hypotheses` is a span lift onto the chain, for `StampLiftStep.epoch_eq`.

`NoteUnspentDerivable.lineage` has no instance here. A `NoteNullifiers` derivation needs
`epoch_start + 15 ≤ emax`, so `MemberLaw` at sixteen epoch indices, and over `ZMod 7` no linear
`member` has that many non-associate primes. The production encoding `(m + (i + 1) X) ^ 3 - c`
satisfies `MemberLaw` only over a field with a non-cube `c` and no cube root of unity among the
index ratios, such as the Pallas base field, whose arithmetic is not available here.
-/

namespace Tachyon.Instances

open Polynomial Chain

instance : Fact (Nat.Prime 7) := ⟨by decide⟩

/-- `Tachyon-AnchorSt`. -/
def nextStamp (a : ZMod 7) (_ : ℕ) (_ : (ZMod 7)[X]) : ZMod 7 := a + 2

/-- `Tachyon-AnchorEp`. -/
def nextEpoch (a : ZMod 7) (e : ℕ) : ZMod 7 := a + e

/-- `Tachyon-ActionDg` over `(cv, rk)` folded into one field element. -/
def actionDigest (g t₁ t₂ : ZMod 7) : ZMod 7 := g + t₁ + t₂

/-- `Tachyon-FeeDg`. -/
def feeDigest (φ c : ZMod 7) : ZMod 7 := φ + c

def noteCommit (_ : Unit) (pk psi : ZMod 7) : ZMod 7 := pk + psi

def paymentKey (_ : Unit) (nk : ZMod 7) : ZMod 7 := nk

def nfMaster (psi nk : ZMod 7) : ZMod 7 := psi * nk

/-- `nullifier_group`. -/
def group (mk : ZMod 7) (g j : ℕ) : ZMod 7 := mk + g + j + 2

def stamp₀ : Chain.Stamp (ZMod 7) (ZMod 7) := ⟨0, [3], 0⟩

def stamp₁ : Chain.Stamp (ZMod 7) (ZMod 7) := ⟨2, [4, 5, 6], 0⟩

def chain : List (Chain.Stamp (ZMod 7) (ZMod 7)) := [stamp₀, stamp₁]

noncomputable def c₀ : (ZMod 7)[X] := setPoly (stamp₀.tachygrams : Multiset (ZMod 7))

noncomputable def c₁ : (ZMod 7)[X] := setPoly (stamp₁.tachygrams : Multiset (ZMod 7))

/-- The anchor-fold calls of the chain up to epoch 1, of the spend's `SpendableInit`, and of the
QR bucket's summary and seal. -/
noncomputable def q : AnchorQueries (ZMod 7) (ZMod 7) ℕ where
  stamp a e c := (a = 0 ∧ e = 0 ∧ c = c₀) ∨ (a = 2 ∧ e = 0 ∧ c = c₁)
  boundary a e := (a = 0 ∧ e = 0) ∨ (a = 4 ∧ e = 1)

def epoch (a : ZMod 7) : ℕ := if a = 5 then 1 else 0

def actions : List (ZMod 7 × ZMod 7 × ZMod 7) := [(0, 4, 5)]

def fee : ZMod 7 × ZMod 7 := (0, 6)

def IsFee (d : ZMod 7) : Prop := d = 6

def R (_ : ℕ) (d : ZMod 7) : Multiset (ZMod 7) := if d = 2 then {4, 5} else if d = 6 then {6} else 0

def Q (g t₁ t₂ : ZMod 7) : Prop := g = 0 ∧ t₁ = 4 ∧ t₂ = 5

def n : NoteQueries (ZMod 7) Unit Unit where
  commit _ pk psi := pk = 2 ∧ psi = 1
  key _ nk := nk = 2

def r : EvidenceQueries (ZMod 7) (ZMod 7) Unit where
  leaf _ := False
  node _ _ _ _ := False

noncomputable def member (_ : ℕ) (m : ZMod 7) : (ZMod 7)[X] := X - C m

theorem epochStamps_zero : epochStamps chain 0 = [c₀, c₁] := by
  simp [epochStamps, chain, stamp₀, stamp₁, c₀, c₁]

theorem epochStamps_succ (e : ℕ) : epochStamps chain (e + 1) = [] := by
  simp [epochStamps, chain, stamp₀, stamp₁]

theorem entry_zero : entry nextStamp nextEpoch 0 chain 0 = 0 := by
  simp [entry, nextEpoch]

theorem final_zero :
    foldBlock nextStamp 0 (entry nextStamp nextEpoch 0 chain 0) (epochStamps chain 0) = 4 := by
  rw [entry_zero, epochStamps_zero]
  simp only [foldBlock, List.foldl_cons, List.foldl_nil, nextStamp]
  decide

theorem c₀_ne_one : c₀ ≠ 1 := by
  intro h
  have := congrArg Polynomial.roots h
  simp [c₀, stamp₀] at this

theorem hashLaw : HashLaw q (nextEpoch 0 0) 0 nextStamp nextEpoch where
  nextStamp_inj h₁ h₂ h := by
    simp only [nextStamp] at h
    rcases h₁ with ⟨rfl, rfl, rfl⟩ | ⟨rfl, rfl, rfl⟩ <;>
      rcases h₂ with ⟨rfl, rfl, rfl⟩ | ⟨rfl, rfl, rfl⟩ <;>
      first | exact ⟨rfl, rfl, rfl⟩ | exact absurd h (by decide)
  nextEpoch_inj h₁ h₂ h := by
    simp only [nextEpoch] at h
    rcases h₁ with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> rcases h₂ with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
      first | exact ⟨rfl, rfl⟩ | exact absurd h (by decide)
  stamp_ne_epoch h₁ h₂ := by
    simp only [nextStamp, nextEpoch]
    rcases h₁ with ⟨rfl, -, -⟩ | ⟨rfl, -, -⟩ <;> rcases h₂ with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> decide
  stamp_ne_genesis h := by
    simp only [nextStamp, nextEpoch]
    rcases h with ⟨rfl, -, -⟩ | ⟨rfl, -, -⟩ <;> decide
  epoch_ne_genesis h he := by
    simp only [nextEpoch]
    rcases h with ⟨-, rfl⟩ | ⟨rfl, rfl⟩
    · exact absurd rfl he
    · decide

theorem chainQueried {N : ℕ} (hN : N ≤ 1) : ChainQueried q nextStamp nextEpoch 0 chain N where
  genesis := Or.inl ⟨rfl, rfl⟩
  boundary e he := by
    obtain rfl : e = 0 := by omega
    exact Or.inr ⟨final_zero, rfl⟩
  stamp e he := by
    rcases (by omega : e = 0 ∨ e = 1) with rfl | rfl
    · rw [epochStamps_zero, entry_zero]
      rintro (_ | ⟨x, _ | ⟨y, P⟩⟩) c S h
      · obtain ⟨rfl, -⟩ := List.cons.inj h
        exact Or.inl ⟨rfl, rfl, rfl⟩
      · obtain ⟨-, h⟩ := List.cons.inj h
        obtain ⟨rfl, -⟩ := List.cons.inj h
        refine Or.inr ⟨?_, rfl, rfl⟩
        simp only [foldBlock, List.foldl_cons, List.foldl_nil, nextStamp]
        decide
      · simp at h
    · rw [epochStamps_succ]
      intro P c S h
      simp at h

theorem onChain_zero : OnChain nextStamp nextEpoch 0 chain 0 0 :=
  ⟨[], [c₀, c₁], epochStamps_zero.symm, entry_zero.symm⟩

theorem onChain_two : OnChain nextStamp nextEpoch 0 chain 0 2 := by
  refine ⟨[c₀], [c₁], epochStamps_zero.symm, ?_⟩
  rw [entry_zero]
  simp only [foldBlock, List.foldl_cons, List.foldl_nil, nextStamp]
  decide

theorem valid : Chain.Valid epoch (OnChain nextStamp nextEpoch 0 chain) chain where
  accepted s hs := by
    simp only [chain, List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl
    · have h : epoch stamp₀.anchor = 0 := by simp [epoch, stamp₀]; decide
      refine ⟨by simp [stamp₀], by simp [stamp₀], ?_, ?_⟩
      · rw [h]
        exact onChain_zero
      · rw [h]
        exact ⟨le_rfl, Nat.zero_le 1⟩
    · have h : epoch stamp₁.anchor = 0 := by simp [epoch, stamp₁]; decide
      refine ⟨by simp [stamp₁], by simp [stamp₁]; decide, ?_, ?_⟩
      · rw [h]
        exact onChain_two
      · rw [h]
        exact ⟨le_rfl, Nat.zero_le 1⟩
  ordered := by simp [chain, stamp₀, stamp₁]
  window_disjoint := by
    refine List.Pairwise.cons ?_ (List.Pairwise.cons (by simp) List.Pairwise.nil)
    intro s hs _ a ha hb
    simp only [List.mem_singleton] at hs
    subst hs
    simp only [stamp₀, List.mem_singleton] at ha
    subst ha
    simp only [stamp₁] at hb
    revert hb
    decide

theorem hepoch {e : ℕ} {a : ZMod 7} (h : Node q (nextEpoch 0 0) 0 nextStamp nextEpoch e a) :
    epoch a = e := by
  induction h with
  | genesis => simp [epoch, nextEpoch]; decide
  | stamp c hprev _ hq ih =>
    rcases hq with ⟨rfl, rfl, -⟩ | ⟨rfl, rfl, -⟩ <;> simp [epoch, nextStamp] <;> decide
  | epoch hprev he hq ih =>
    rcases hq with ⟨-, rfl⟩ | ⟨rfl, rfl⟩
    · exact absurd rfl he
    · simp [epoch, nextEpoch]; decide

theorem digestLaw : DigestLaw IsFee R actionDigest Q where
  pair e g t₁ t₂ h := by
    obtain ⟨rfl, rfl, rfl⟩ := h
    simp [R, actionDigest]
    decide
  not_fee h := by
    obtain ⟨rfl, rfl, rfl⟩ := h
    simp [IsFee, actionDigest]
    decide

theorem noteLaw : NoteLaw n noteCommit paymentKey where
  commit_binds h₁ h₂ _ := ⟨h₁.1.trans h₂.1.symm, h₁.2.trans h₂.2.symm⟩
  paymentKey_binds h₁ h₂ _ := h₁.trans h₂.symm

theorem evidenceLaw : EvidenceLaw r (fun _ => ()) fun _ _ _ _ => () where
  leaf_inj h := h.elim
  node_inj h := h.elim
  leaf_ne_node h := h.elim

theorem qnr : ¬ IsSquare (3 : ZMod 7) := by
  unfold IsSquare
  decide

theorem memberLaw : MemberLaw member 0 where
  prime _ := prime_X_sub_C _
  dvd_inj hi hj h := by
    refine ⟨by omega, ?_⟩
    have := (dvd_iff_isRoot.mp h)
    simpa [member, sub_eq_zero] using this

/-- The note secret: `NoteSeed` with value `()`, `ak = ()`, `psi = 1` and `nk = 2`. -/
theorem secret : NoteSecretDerivable n noteCommit paymentKey nfMaster
    ⟨noteCommit () (paymentKey () 2) 1, nfMaster 1 2⟩ :=
  .seed () () 1 2 ⟨rfl, rfl⟩ rfl

/-- The spend's predicate in the headline theorems. -/
abbrev Spend : SpendHeader (ZMod 7) → Prop :=
  SpendDerivable q nextStamp (QrBucketDerivable q r nextStamp nextEpoch 3 (fun _ => ())
      fun _ _ _ _ => ())
    (NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch 3 (fun _ => ())
      fun _ _ _ _ => ()) 3 member (NoteSecretDerivable n noteCommit paymentKey nfMaster) group 0)
    (NoteSecretDerivable n noteCommit paymentKey nfMaster) (groupNullifier group)

/-- The spend's header, as `SpendBind` emits it. -/
noncomputable def header : SpendHeader (ZMod 7) :=
  ⟨noteCommit () (paymentKey () 2) 1, groupNullifier group (nfMaster 1 2) 0,
    groupNullifier group (nfMaster 1 2) (0 + 1), nextStamp 0 0 c₀⟩

theorem spend : Spend header :=
  SpendDerivable.bind (.init _ 0 c₀ 0 (by simp [c₀, stamp₀, setPoly, paymentKey]; decide)
    (Or.inl ⟨rfl, rfl, rfl⟩)) secret rfl

theorem header_nf_current : header.nf_current = 4 := by decide

theorem header_nf_next : header.nf_next = 5 := by decide

theorem header_anchor : header.anchor = 2 := by decide

theorem bundleCovered : BundleCovered actions fee []
    (⟨stamp₁.tachygrams, setPoly (stamp₁.tachygrams : Multiset (ZMod 7)), stamp₁.anchor⟩ :
      PublishedStamp (ZMod 7) (ZMod 7)) where
  descs_nodup := by simp [actions]
  fees_nodup := by simp [fee]
  tachygrams_nodup := by simp [stamp₁]; decide
  tachygrams_covered := by simp [stamp₁, coveredTachygrams, actions, fee]
  tachygram_set := rfl

theorem stamp_eq :
    (⟨setPoly {actionDigest 0 header.nf_current header.nf_next} * setPoly {6},
      setPoly ({header.nf_current, header.nf_next} : Multiset (ZMod 7)) *
        setPoly (R (epoch header.anchor) 6), header.anchor⟩ : Tachyon.Stamp (ZMod 7) (ZMod 7)) =
      ⟨setPoly (coveredDigests actionDigest feeDigest actions [fee]),
        setPoly (stamp₁.tachygrams : Multiset (ZMod 7)), stamp₁.anchor⟩ := by
  rw [header_nf_current, header_nf_next, header_anchor, ← setPoly_add, ← setPoly_add]
  have hR : R (epoch 2) 6 = {6} := by simp [R]; decide
  rw [hR]
  congr 2

/-- The stamp proof: `FeeFuse` of the bundle's fee over the spend's `SpendAction` leaf. -/
noncomputable def tree : StampTree IsFee epoch R q nextStamp actionDigest Q Spend
    ⟨setPoly (coveredDigests actionDigest feeDigest actions [fee]),
      setPoly (stamp₁.tachygrams : Multiset (ZMod 7)), stamp₁.anchor⟩ :=
  stamp_eq ▸ StampTree.feeFuse 6 (.spend header spend 0 ⟨rfl, header_nf_current, header_nf_next⟩)
    rfl

theorem leaves_cast {X Y : Tachyon.Stamp (ZMod 7) (ZMod 7)} (h : X = Y)
    (t : StampTree IsFee epoch R q nextStamp actionDigest Q Spend X) : (h ▸ t).leaves = t.leaves := by
  subst h
  rfl

noncomputable def coveredSpend : CoveredSpend IsFee epoch R q nextStamp actionDigest Q Spend
    feeDigest actions fee [] stamp₁ (noteCommit () (paymentKey () 2) 1) where
  covered := bundleCovered
  actions_queried a ha := by
    simp only [actions, List.mem_singleton] at ha
    subst ha
    exact ⟨rfl, rfl, rfl⟩
  tree := tree
  index := ⟨0, by simp [actions]⟩
  header := header
  spend := spend
  witness := 0
  leaf := by
    rw [tree, leaves_cast]
    simp [StampTree.leaves, ActionsTree.leaves]
  cm_eq := rfl
  digest_eq := by simp [actions, actionDigest, header_nf_current, header_nf_next]

theorem hne : ∀ s ∈ chain, s.tachygrams ≠ [] := fun s hs => (valid.accepted s hs).tachygrams_ne_nil

/-- Every hypothesis of `no_double_spend_of_covered_spends` except the second spend (`p₂`, `hsplit`,
`hs₂`, `hfresh`), and of `no_double_spend_in_stamp` except the second spend and `hindex`: the laws,
a valid chain whose calls up to epoch 1 lie in `q`, a covered spend in one of its stamps, and the
note's secret. -/
theorem headline_hypotheses :
    HashLaw q (nextEpoch 0 0) 0 nextStamp nextEpoch ∧ ¬ IsSquare (3 : ZMod 7) ∧
      MemberLaw member 0 ∧ EvidenceLaw r (fun _ => ()) (fun _ _ _ _ => ()) ∧
      NoteLaw n noteCommit paymentKey ∧ DigestLaw IsFee R actionDigest Q ∧
      Chain.Valid epoch (OnChain nextStamp nextEpoch 0 chain) chain ∧
      (∀ N ≤ 1, ChainQueried q nextStamp nextEpoch 0 chain N) ∧ stamp₁ ∈ chain ∧
      Nonempty (CoveredSpend IsFee epoch R q nextStamp actionDigest Q Spend feeDigest actions fee []
        stamp₁ (noteCommit () (paymentKey () 2) 1)) ∧
      NoteSecretDerivable n noteCommit paymentKey nfMaster
        ⟨noteCommit () (paymentKey () 2) 1, nfMaster 1 2⟩ :=
  ⟨hashLaw, qnr, memberLaw, evidenceLaw, noteLaw, digestLaw, valid, fun _ hN => chainQueried hN,
    by simp [chain], ⟨coveredSpend⟩, secret⟩

/-- The instance fits `no_double_spend_of_covered_spends`: only the second spend is left open. -/
example {l₁ l₂ : List (Chain.Stamp (ZMod 7) (ZMod 7))} {s₂ : Chain.Stamp (ZMod 7) (ZMod 7)}
    {actions₂ : List (ZMod 7 × ZMod 7 × ZMod 7)} {fee₂ : ZMod 7 × ZMod 7}
    {adjunctFees₂ : List (ZMod 7 × ZMod 7)} (hsplit : chain = l₁ ++ stamp₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (hN : s₂.epoch ≤ 1)
    (p₂ : CoveredSpend IsFee epoch R q nextStamp actionDigest Q Spend feeDigest actions₂ fee₂
      adjunctFees₂ s₂ (noteCommit () (paymentKey () 2) 1))
    (hfresh : ∀ e, stamp₁.epoch < e → e ≤ epoch s₂.anchor →
      ¬ Chain.published chain e (noteCommit () (paymentKey () 2) 1)) : False :=
  no_double_spend_of_covered_spends hashLaw qnr memberLaw evidenceLaw noteLaw digestLaw valid
    (chainQueried hN) hsplit hs₂ coveredSpend p₂ secret hfresh

/-- The instance fits `no_double_spend_in_stamp`: only the second spend is left open. -/
example (p₂ : CoveredSpend IsFee epoch R q nextStamp actionDigest Q Spend feeDigest actions fee []
      stamp₁ (noteCommit () (paymentKey () 2) 1))
    (hindex : coveredSpend.index ≠ p₂.index) : False :=
  no_double_spend_in_stamp hashLaw qnr evidenceLaw noteLaw digestLaw valid (by simp [chain])
    (chainQueried (by simp [stamp₁])) coveredSpend p₂ secret hindex

/-- A `BundleVerified` bundle whose `IsFee` holds of its fee digest, with `hepoch` for the
`StampTree.derivable` that proves it. -/
theorem bundle_verified :
    BundleVerified IsFee epoch R actionDigest feeDigest actions fee []
        ⟨stamp₁.tachygrams, setPoly (stamp₁.tachygrams : Multiset (ZMod 7)), stamp₁.anchor⟩ ∧
      IsFee (feeDigest fee.1 fee.2) ∧
      ∀ {e : ℕ} {a : ZMod 7}, Node q (nextEpoch 0 0) 0 nextStamp nextEpoch e a → epoch a = e :=
  ⟨{ toBundleCovered := bundleCovered
     proof := tree.derivable hashLaw hepoch digestLaw
       (onChain_two.toNode hne (chainQueried le_rfl) (Nat.zero_le 1)) },
    by simp [IsFee, feeDigest, fee], hepoch⟩

/-- A sealed QR bucket over epoch 0's two stamps that ends on the entry anchor of epoch 1. -/
theorem bucket_onChain_hypotheses :
    ∃ b, QrBucketDerivable q r nextStamp nextEpoch 3 (fun _ => ()) (fun _ _ _ _ => ()) b ∧
      b.epoch + 1 ≤ 1 ∧ b.anchor_next = entry nextStamp nextEpoch 0 chain (b.epoch + 1) := by
  refine ⟨_, .seal 0 (.summary 0 (.advance c₁ (.seed 0 0 c₀ (Or.inl ⟨rfl, rfl, rfl⟩))
    (Or.inr ⟨by decide, rfl, rfl⟩))) (by simp [nextEpoch]) (Or.inl ⟨rfl, rfl⟩)
    (Or.inr ⟨by decide, rfl⟩), le_rfl, ?_⟩
  show nextEpoch _ (0 + 1) = nextEpoch
    (foldBlock nextStamp 0 (entry nextStamp nextEpoch 0 chain 0) (epochStamps chain 0)) (0 + 1)
  rw [final_zero]
  decide

/-- A derivable span and a `StampLiftStep` from the epoch's entry anchor onto the chain node after
its first stamp. -/
theorem lift_hypotheses :
    ∃ (span : AnchorSpan (ZMod 7)) (s s' : Tachyon.Stamp (ZMod 7) (ZMod 7)),
      SpanDerivable q nextStamp span ∧ StampLiftStep s span s' ∧
      Node q (nextEpoch 0 0) 0 nextStamp nextEpoch 0 s'.anchor :=
  ⟨_, ⟨1, 1, 0⟩, _, .seed 0 0 c₀ c₀_ne_one (Or.inl ⟨rfl, rfl, rfl⟩), ⟨by simp, rfl⟩,
    onChain_two.toNode hne (chainQueried le_rfl) (Nat.zero_le 1)⟩

end Tachyon.Instances
