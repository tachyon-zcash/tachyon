import Mathlib.Algebra.Field.ZMod
import Mathlib.Algebra.Polynomial.SpecificDegree
import Mathlib.Tactic.IntervalCases
import Mathlib.Tactic.LinearCombination
import Tachyon.Consensus.Spends
import Tachyon.CubicMember

/-!
# A concrete instance

ragu's fv-preflight §4 asks for a concrete input satisfying every hypothesis, so that no theorem
holds for nothing. This module gives one at `ZMod 37`. It is a chain of two stamps. Epoch 0's stamp
publishes a note commitment `cm` and one other tachygram. Epoch 1's stamp is a bundle with one spend
of that note and its fee change, proven by a `FeeFuse` over a `SpendAction` leaf. The spend's
lineage is a `QrSpendableInit` on a `NoteUnspent` segment over epoch 0. That segment is a
`NullifierDerive` window of sixteen members bound to a `QrUnspentInit` test against a QR bucket of
epoch 0. The bucket's intake descends once, splitting epoch 0's tachygrams into both sides, and the
bucket is replayed through an evidence tree and `EvidenceTreeOpen`. The hash functions are
concrete, and each call set holds exactly the calls the chain and the derivations make, so every
scoped law holds on them.

* `headline_hypotheses` discharges every hypothesis of `no_double_spend_of_covered_spends` except
  the second spend (`p₂`, `hsplit`, `hs₂`, `hfresh`), which is what it rules out, and of
  `no_double_spend_in_stamp` except the second spend and `hindex`. Two examples apply both theorems
  to the instance with only the second spend left open.
* `lineage_hypotheses` inhabits `SpendDerivable.lineage` and `NoteUnspentDerivable.lineage` with a
  lineage that covers an epoch.
* `bundle_verified` is a `BundleVerified` bundle. Its proof field is a `StampDerivable` header whose
  `IsFee` holds of the bundle's fee digest.
* `bucket_onChain_hypotheses` inhabits `QrBucketDerivable.covers` and `QrBucket.Covers.onChain` with
  the bucket above.
* `lift_hypotheses` is a span lift onto the chain, for `StampLiftStep.epoch_eq`.

The chain instance's `member` is not Rust's encoding `(m + (i + 1) X) ^ 3 - c`. It is a family of
monic irreducible quadratics, enough to show `MemberLaw` at sixteen epoch indices is satisfiable
together with the rest. Rust's encoding (`cubicMember`) satisfies `MemberLaw` at sixteen indices
over `ZMod 307` with `c = 5` (`rust_memberLaw`, from `cubicMember_law`). At the Pallas field
`cubicMember_law`'s hypotheses are facts about its prime that this module doesn't check. `qnr` is a
non-residue of `ZMod 37`, not Rust's `NON_RESIDUE`.
-/

namespace Tachyon.Instances

open Polynomial Chain

instance : Fact (Nat.Prime 37) := ⟨by decide⟩

/-- `Tachyon-AnchorSt`. -/
def nextStamp (a : ZMod 37) (_ : ℕ) (_ : (ZMod 37)[X]) : ZMod 37 := a + 2

/-- `Tachyon-AnchorEp`. -/
def nextEpoch (a : ZMod 37) (e : ℕ) : ZMod 37 := a + e

/-- `Tachyon-ActionDg` with `(cv, rk)` folded into one field element. -/
def actionDigest (g t₁ t₂ : ZMod 37) : ZMod 37 := g + t₁ + t₂

/-- `Tachyon-FeeDg`. -/
def feeDigest (φ c : ZMod 37) : ZMod 37 := φ + c

def noteCommit (_ : Unit) (pk psi : ZMod 37) : ZMod 37 := pk + psi

def paymentKey (_ : Unit) (nk : ZMod 37) : ZMod 37 := nk

def nfMaster (psi nk : ZMod 37) : ZMod 37 := psi * nk

/-- `nullifier_group`. -/
def group (mk : ZMod 37) (g j : ℕ) : ZMod 37 := mk + g + j + 2

def stamp₀ : Chain.Stamp (ZMod 37) (ZMod 37) := ⟨0, [3, 2], 0⟩

def stamp₁ : Chain.Stamp (ZMod 37) (ZMod 37) := ⟨3, [5, 6, 8], 1⟩

def chain : List (Chain.Stamp (ZMod 37) (ZMod 37)) := [stamp₀, stamp₁]

noncomputable def c₀ : (ZMod 37)[X] := setPoly (stamp₀.tachygrams : Multiset (ZMod 37))

noncomputable def c₁ : (ZMod 37)[X] := setPoly (stamp₁.tachygrams : Multiset (ZMod 37))

/-- The anchor-fold calls of the chain up to epoch 2 and of the QR bucket's summary and seal. -/
noncomputable def q : AnchorQueries (ZMod 37) (ZMod 37) ℕ where
  stamp a e c := (a = 0 ∧ e = 0 ∧ c = c₀) ∨ (a = 3 ∧ e = 1 ∧ c = c₁)
  boundary a e := (a = 0 ∧ e = 0) ∨ (a = 2 ∧ e = 1) ∨ (a = 5 ∧ e = 2)

def epoch (a : ZMod 37) : ℕ := if a = 3 ∨ a = 5 then 1 else if a = 7 then 2 else 0

def actions : List (ZMod 37 × ZMod 37 × ZMod 37) := [(0, 5, 6)]

def fee : ZMod 37 × ZMod 37 := (0, 8)

def IsFee (d : ZMod 37) : Prop := d = 8

def R (_ : ℕ) (d : ZMod 37) : Multiset (ZMod 37) :=
  if d = 11 then {5, 6} else if d = 8 then {8} else 0

def Q (g t₁ t₂ : ZMod 37) : Prop := g = 0 ∧ t₁ = 5 ∧ t₂ = 6

def n : NoteQueries (ZMod 37) Unit Unit where
  commit _ pk psi := pk = 2 ∧ psi = 1
  key _ nk := nk = 2

/-- Sixteen non-squares of `ZMod 37`, one per epoch index. -/
def nonSquares : List (ZMod 37) := [2, 5, 6, 8, 13, 14, 15, 17, 18, 19, 20, 22, 23, 24, 29, 31]

def s (i : ℕ) : ZMod 37 := nonSquares.getD i 2

/-- `X ^ 2 + m X + (m ^ 2 - s i) / 4`, irreducible because its discriminant `s i` is a
non-square. `28` is `4⁻¹`. -/
noncomputable def member (i : ℕ) (m : ZMod 37) : (ZMod 37)[X] :=
  C 1 * X ^ 2 + C m * X + C ((m ^ 2 - s i) * 28)

theorem s_nonsquare {i : ℕ} (hi : i ≤ 15) : ¬ IsSquare (s i) := by
  unfold IsSquare
  interval_cases i <;> decide

theorem s_inj : ∀ i < 16, ∀ j < 16, s i = s j → i = j := by decide

theorem member_natDegree (i : ℕ) (m : ZMod 37) : (member i m).natDegree = 2 :=
  natDegree_quadratic one_ne_zero

theorem member_leadingCoeff (i : ℕ) (m : ZMod 37) : (member i m).leadingCoeff = 1 :=
  leadingCoeff_quadratic one_ne_zero

theorem memberLaw : MemberLaw member 15 where
  prime {i m} hi := by
    refine (irreducible_of_degree_le_three_of_not_isRoot (by simp [member_natDegree])
      fun x hx => s_nonsquare hi ⟨2 * x + m, ?_⟩).prime
    have h' : (4 : ZMod 37) * 28 - 1 = 0 := by decide
    simp only [member, IsRoot.def, eval_add, eval_mul, eval_C, eval_pow, eval_X] at hx
    linear_combination -4 * hx + (m ^ 2 - s i) * h'
  dvd_inj {i j m w} hi hj h := by
    have heq := eq_of_dvd_of_natDegree_le_of_leadingCoeff h
      (by rw [member_natDegree, member_natDegree]) (by rw [member_leadingCoeff, member_leadingCoeff])
    have h1 := congrArg (coeff · 1) heq
    have h0 := congrArg (eval 0) heq
    simp [member, coeff_C] at h1
    rw [← C_pow, ← C_pow, coeff_C, coeff_C] at h1
    simp at h1
    simp only [member, eval_add, eval_mul, eval_C, eval_pow, eval_X] at h0
    subst h1
    refine ⟨s_inj i (by omega) j (by omega) ?_, rfl⟩
    have h28 : (28 : ZMod 37) ≠ 0 := by decide
    have := mul_right_cancel₀ h28 (by linear_combination h0 :
      (m ^ 2 - s i) * 28 = (m ^ 2 - s j) * 28)
    linear_combination -this

theorem qnr : ¬ IsSquare (2 : ZMod 37) := by
  unfold IsSquare
  decide

/-- The note secret: `NoteSeed` with value `()`, `ak = ()`, `psi = 1` and `nk = 2`. -/
theorem secret : NoteSecretDerivable n noteCommit paymentKey nfMaster
    ⟨noteCommit () (paymentKey () 2) 1, nfMaster 1 2⟩ :=
  .seed () () 1 2 ⟨rfl, rfl⟩ rfl

/-- Epoch 0's QR bucket: a summary of its stamp, one descent with `cm` on the residue side and `2`
on the non-residue side, and the seal. -/
noncomputable def bucket : QrBucket (ZMod 37) (ZMod 37) :=
  ⟨0, 0, nextEpoch (nextStamp 0 0 c₀) (0 + 1), 0, [] ++ [true], X - C 3⟩

/-- The evidence digests: a bucket leaf is `false` and a node `true`. -/
def leaf (_ : QrBucket (ZMod 37) (ZMod 37)) : Bool := false

def node (_ _ _ _ : Bool) : Bool := true

/-- The evidence calls: the bucket's leaf and the node over four copies of it. -/
noncomputable def r : EvidenceQueries (ZMod 37) (ZMod 37) Bool where
  leaf b := b = bucket
  node a₀ a₁ a₂ a₃ := a₀ = false ∧ a₁ = false ∧ a₂ = false ∧ a₃ = false

theorem evidenceLaw : EvidenceLaw r leaf node where
  leaf_inj h₁ h₂ _ := h₁.trans h₂.symm
  node_inj h₁ h₂ _ := by
    obtain ⟨rfl, rfl, rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl, rfl, rfl⟩ := h₂
    exact ⟨rfl, rfl, rfl, rfl⟩
  leaf_ne_node _ _ := Bool.false_ne_true

theorem sealed : QrEvidenceDerivable q r nextStamp nextEpoch 2 leaf node (.bucket bucket) :=
  .seal 0 (.descend (X - C 3) (X - C 2) (C 2) (C (-2)) true
      (.summary 0 (.seed 0 0 c₀ (Or.inl ⟨rfl, rfl, rfl⟩)))
      (by simp [c₀, stamp₀, setPoly])
      (by simp; decide)
      (by simp; ring))
    (by simp [nextEpoch]) (Or.inl ⟨rfl, rfl⟩) (Or.inr (Or.inl ⟨by decide, rfl⟩))

theorem opened : QrBucketDerivable q r nextStamp nextEpoch 2 leaf node bucket :=
  have hpair := QrEvidenceDerivable.leafPair sealed sealed rfl rfl
  .open (.descend 0 (.fuse hpair hpair ⟨rfl, rfl, rfl, rfl⟩) ⟨rfl, rfl, rfl, rfl⟩) rfl

/-- The tested value: the note's nullifier at epoch 0. -/
def nf₀ : ZMod 37 := groupNullifier group (nfMaster 1 2) 0

theorem unspentTest : UnspentTest 2 bucket nf₀ := by
  refine ⟨fun j hj => ?_, by simp [bucket, nf₀, groupNullifier, group, nfMaster]; decide⟩
  obtain rfl : j = 0 := by simpa [bucket] using hj
  exact ⟨2, by simp [bucket, nf₀, groupNullifier, group, nfMaster]; decide, by simp [bucket]⟩

/-- The `UnspentBind` complement: the window's members after epoch 0. -/
noncomputable def complement : (ZMod 37)[X] :=
  (((List.range 16).drop 1).map fun k =>
    member (0 + k) (group (nfMaster 1 2) (0 + k / 4 * 4) (k % 4))).prod

/-- The note's `NoteUnspent` segment over epoch 0. -/
theorem unspent : NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch 2 leaf node) 2
    member (NoteSecretDerivable n noteCommit paymentKey nfMaster) group 15
    ⟨noteCommit () (paymentKey () 2) 1, bucket.anchor_start, bucket.epoch, bucket.epoch + 1,
      bucket.anchor_next⟩ :=
  .bind complement (.init nf₀ opened (by simp [bucket]) unspentTest)
    (.derive 0 secret rfl le_rfl) rfl

/-- The spend's predicate in the headline theorems. -/
abbrev Spend : SpendHeader (ZMod 37) → Prop :=
  SpendDerivable q nextStamp (QrBucketDerivable q r nextStamp nextEpoch 2 leaf node)
    (NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch 2 leaf node) 2 member
      (NoteSecretDerivable n noteCommit paymentKey nfMaster) group 15)
    (NoteSecretDerivable n noteCommit paymentKey nfMaster) (groupNullifier group)

/-- The spend's header, as `SpendBind` emits it. -/
noncomputable def header : SpendHeader (ZMod 37) :=
  ⟨noteCommit () (paymentKey () 2) 1, groupNullifier group (nfMaster 1 2) (bucket.epoch + 1),
    groupNullifier group (nfMaster 1 2) (bucket.epoch + 1 + 1), bucket.anchor_next⟩

theorem spend : Spend header :=
  SpendDerivable.bind (.qrInit unspent opened rfl rfl rfl
    (by simp [bucket, noteCommit, paymentKey]; decide)) secret rfl

theorem header_nf_current : header.nf_current = 5 := by decide

theorem header_nf_next : header.nf_next = 6 := by decide

theorem header_anchor : header.anchor = 3 := by decide

theorem epochStamps_zero : epochStamps chain 0 = [c₀] := by
  simp [epochStamps, chain, stamp₀, stamp₁, c₀]

theorem epochStamps_one : epochStamps chain 1 = [c₁] := by
  simp [epochStamps, chain, stamp₀, stamp₁, c₁]

theorem epochStamps_two : epochStamps chain 2 = [] := by
  simp [epochStamps, chain, stamp₀, stamp₁]

theorem entry_zero : entry nextStamp nextEpoch 0 chain 0 = 0 := by
  simp [entry, nextEpoch]

theorem final_zero :
    foldBlock nextStamp 0 (entry nextStamp nextEpoch 0 chain 0) (epochStamps chain 0) = 2 := by
  rw [entry_zero, epochStamps_zero]
  simp only [foldBlock, List.foldl_cons, List.foldl_nil, nextStamp]
  decide

theorem entry_one : entry nextStamp nextEpoch 0 chain 1 = 3 := by
  show nextEpoch (foldBlock nextStamp 0 (entry nextStamp nextEpoch 0 chain 0)
    (epochStamps chain 0)) (0 + 1) = 3
  rw [final_zero]
  decide

theorem final_one :
    foldBlock nextStamp 1 (entry nextStamp nextEpoch 0 chain 1) (epochStamps chain 1) = 5 := by
  rw [entry_one, epochStamps_one]
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
    rcases h₁ with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
      rcases h₂ with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
      first | exact ⟨rfl, rfl⟩ | exact absurd h (by decide)
  stamp_ne_epoch h₁ h₂ := by
    simp only [nextStamp, nextEpoch]
    rcases h₁ with ⟨rfl, -, -⟩ | ⟨rfl, -, -⟩ <;>
      rcases h₂ with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> decide
  stamp_ne_genesis h := by
    simp only [nextStamp, nextEpoch]
    rcases h with ⟨rfl, -, -⟩ | ⟨rfl, -, -⟩ <;> decide
  epoch_ne_genesis h he := by
    simp only [nextEpoch]
    rcases h with ⟨-, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · exact absurd rfl he
    · decide
    · decide

theorem chainQueried {N : ℕ} (hN : N ≤ 2) : ChainQueried q nextStamp nextEpoch 0 chain N where
  genesis := Or.inl ⟨rfl, rfl⟩
  boundary e he := by
    rcases (by omega : e = 0 ∨ e = 1) with rfl | rfl
    · exact Or.inr (Or.inl ⟨final_zero, rfl⟩)
    · exact Or.inr (Or.inr ⟨final_one, rfl⟩)
  stamp e he := by
    rcases (by omega : e = 0 ∨ e = 1 ∨ e = 2) with rfl | rfl | rfl
    · rw [epochStamps_zero, entry_zero]
      rintro (_ | ⟨x, P⟩) c S h
      · obtain ⟨rfl, -⟩ := List.cons.inj h
        exact Or.inl ⟨rfl, rfl, rfl⟩
      · simp at h
    · rw [epochStamps_one, entry_one]
      rintro (_ | ⟨x, P⟩) c S h
      · obtain ⟨rfl, -⟩ := List.cons.inj h
        exact Or.inr ⟨rfl, rfl, rfl⟩
      · simp at h
    · rw [epochStamps_two]
      intro P c S h
      simp at h

theorem onChain_zero : OnChain nextStamp nextEpoch 0 chain 0 0 :=
  ⟨[], [c₀], epochStamps_zero.symm, entry_zero.symm⟩

theorem onChain_two : OnChain nextStamp nextEpoch 0 chain 0 2 := by
  refine ⟨[c₀], [], by rw [epochStamps_zero]; rfl, ?_⟩
  rw [entry_zero]
  simp only [foldBlock, List.foldl_cons, List.foldl_nil, nextStamp]
  decide

theorem onChain_three : OnChain nextStamp nextEpoch 0 chain 1 3 :=
  ⟨[], [c₁], epochStamps_one.symm, entry_one.symm⟩

theorem valid : Chain.Valid epoch (OnChain nextStamp nextEpoch 0 chain) chain where
  accepted s hs := by
    simp only [chain, List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl
    · have h : epoch stamp₀.anchor = 0 := by simp [epoch, stamp₀]; decide
      refine ⟨by simp [stamp₀], by simp [stamp₀]; decide, ?_, ?_⟩
      · rw [h]
        exact onChain_zero
      · rw [h]
        exact ⟨le_rfl, Nat.zero_le 1⟩
    · have h : epoch stamp₁.anchor = 1 := by simp [epoch, stamp₁]
      refine ⟨by simp [stamp₁], by simp [stamp₁]; decide, ?_, ?_⟩
      · rw [h]
        exact onChain_three
      · rw [h]
        exact ⟨le_rfl, Nat.le_succ 1⟩
  ordered := by simp [chain, stamp₀, stamp₁]
  window_disjoint := by
    refine List.Pairwise.cons ?_ (List.Pairwise.cons (by simp) List.Pairwise.nil)
    intro s hs _ a ha hb
    simp only [List.mem_singleton] at hs
    subst hs
    simp only [stamp₀, stamp₁] at ha hb
    revert a
    decide

theorem hepoch {e : ℕ} {a : ZMod 37} (h : Node q (nextEpoch 0 0) 0 nextStamp nextEpoch e a) :
    epoch a = e := by
  induction h with
  | genesis => simp [epoch, nextEpoch]; decide
  | stamp c hprev _ hq ih =>
    rcases hq with ⟨rfl, rfl, -⟩ | ⟨rfl, rfl, -⟩ <;> simp only [nextStamp] <;> decide
  | epoch hprev he hq ih =>
    rcases hq with ⟨-, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · exact absurd rfl he
    · simp [epoch, nextEpoch]; decide
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

theorem bundleCovered : BundleCovered actions fee []
    (⟨stamp₁.tachygrams, setPoly (stamp₁.tachygrams : Multiset (ZMod 37)), stamp₁.anchor⟩ :
      PublishedStamp (ZMod 37) (ZMod 37)) where
  descs_nodup := by simp [actions]
  fees_nodup := by simp [fee]
  tachygrams_nodup := by simp [stamp₁]; decide
  tachygrams_covered := by simp [stamp₁, coveredTachygrams, actions, fee]
  tachygram_set := rfl

theorem stamp_eq :
    (⟨setPoly {actionDigest 0 header.nf_current header.nf_next} * setPoly {8},
      setPoly ({header.nf_current, header.nf_next} : Multiset (ZMod 37)) *
        setPoly (R (epoch header.anchor) 8), header.anchor⟩ : Tachyon.Stamp (ZMod 37) (ZMod 37)) =
      ⟨setPoly (coveredDigests actionDigest feeDigest actions [fee]),
        setPoly (stamp₁.tachygrams : Multiset (ZMod 37)), stamp₁.anchor⟩ := by
  rw [header_nf_current, header_nf_next, header_anchor, ← setPoly_add, ← setPoly_add]
  have hR : R (epoch 3) 8 = {8} := by simp [R]; decide
  rw [hR]
  congr 2

/-- The stamp proof: `FeeFuse` of the bundle's fee over the spend's `SpendAction` leaf. -/
noncomputable def tree : StampTree IsFee epoch R q nextStamp actionDigest Q Spend
    ⟨setPoly (coveredDigests actionDigest feeDigest actions [fee]),
      setPoly (stamp₁.tachygrams : Multiset (ZMod 37)), stamp₁.anchor⟩ :=
  stamp_eq ▸ StampTree.feeFuse 8 (.spend header spend 0 ⟨rfl, header_nf_current, header_nf_next⟩)
    rfl

theorem leaves_cast {X Y : Tachyon.Stamp (ZMod 37) (ZMod 37)} (h : X = Y)
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
a valid chain whose calls up to epoch 2 lie in `q`, a covered spend in one of its stamps, and the
note's secret. -/
theorem headline_hypotheses :
    HashLaw q (nextEpoch 0 0) 0 nextStamp nextEpoch ∧ ¬ IsSquare (2 : ZMod 37) ∧
      MemberLaw member 15 ∧ EvidenceLaw r leaf node ∧ NoteLaw n noteCommit paymentKey ∧
      DigestLaw IsFee R actionDigest Q ∧ Chain.Valid epoch (OnChain nextStamp nextEpoch 0 chain) chain ∧
      (∀ N ≤ 2, ChainQueried q nextStamp nextEpoch 0 chain N) ∧ stamp₁ ∈ chain ∧
      Nonempty (CoveredSpend IsFee epoch R q nextStamp actionDigest Q Spend feeDigest actions fee []
        stamp₁ (noteCommit () (paymentKey () 2) 1)) ∧
      NoteSecretDerivable n noteCommit paymentKey nfMaster
        ⟨noteCommit () (paymentKey () 2) 1, nfMaster 1 2⟩ :=
  ⟨hashLaw, qnr, memberLaw, evidenceLaw, noteLaw, digestLaw, valid, fun _ hN => chainQueried hN,
    by simp [chain], ⟨coveredSpend⟩, secret⟩

/-- The instance fits `no_double_spend_of_covered_spends`: only the second spend is left open. -/
example {l₁ l₂ : List (Chain.Stamp (ZMod 37) (ZMod 37))} {s₂ : Chain.Stamp (ZMod 37) (ZMod 37)}
    {actions₂ : List (ZMod 37 × ZMod 37 × ZMod 37)} {fee₂ : ZMod 37 × ZMod 37}
    {adjunctFees₂ : List (ZMod 37 × ZMod 37)} (hsplit : chain = l₁ ++ stamp₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (hN : s₂.epoch ≤ 2)
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

/-- The spend's lineage covers epoch 0: the spend's anchor is reached in epoch 1, and its
`NoteUnspent` segment ends on the entry anchor of epoch 1. -/
theorem lineage_hypotheses :
    OnChain nextStamp nextEpoch 0 chain 1 header.anchor ∧
      bucket.anchor_next = entry nextStamp nextEpoch 0 chain (bucket.epoch + 1) := by
  have h : header.anchor = entry nextStamp nextEpoch 0 chain 1 := by rw [header_anchor, entry_one]
  refine ⟨h ▸ entry_onChain 1, ?_⟩
  show header.anchor = _
  exact h

/-- A `BundleVerified` bundle whose `IsFee` holds of its fee digest, with `hepoch` for the
`StampTree.derivable` that proves it. -/
theorem bundle_verified :
    BundleVerified IsFee epoch R actionDigest feeDigest actions fee []
        ⟨stamp₁.tachygrams, setPoly (stamp₁.tachygrams : Multiset (ZMod 37)), stamp₁.anchor⟩ ∧
      IsFee (feeDigest fee.1 fee.2) ∧
      ∀ {e : ℕ} {a : ZMod 37}, Node q (nextEpoch 0 0) 0 nextStamp nextEpoch e a → epoch a = e :=
  ⟨{ toBundleCovered := bundleCovered
     proof := tree.derivable hashLaw hepoch digestLaw
       (onChain_three.toNode hne (chainQueried (N := 1) (by omega)) le_rfl) },
    by simp [IsFee, feeDigest, fee], hepoch⟩

/-- The QR bucket ends on the entry anchor of epoch 1, for `QrBucket.Covers.onChain`. -/
theorem bucket_onChain_hypotheses :
    QrBucketDerivable q r nextStamp nextEpoch 2 leaf node bucket ∧ bucket.epoch + 1 ≤ 1 ∧
      bucket.anchor_next = entry nextStamp nextEpoch 0 chain (bucket.epoch + 1) :=
  ⟨opened, le_rfl, lineage_hypotheses.2⟩

instance : Fact (Nat.Prime 307) := ⟨by decide +kernel⟩

/-- Rust's encoding `(m + (i + 1) X) ^ 3 - 5` satisfies `MemberLaw` at sixteen epoch indices over
`ZMod 307`: `5` is not a cube, and the cubes of `1, …, 16` are distinct. -/
theorem rust_memberLaw : MemberLaw (cubicMember (5 : ZMod 307)) 15 :=
  cubicMember_law (by decide +kernel) (by decide) (by decide +kernel) (by decide +kernel)

/-- A derivable span and a `StampLiftStep` from the entry anchor of epoch 0 onto the chain node after
its stamp. -/
theorem lift_hypotheses :
    ∃ (span : AnchorSpan (ZMod 37)) (s s' : Tachyon.Stamp (ZMod 37) (ZMod 37)),
      SpanDerivable q nextStamp span ∧ StampLiftStep s span s' ∧
      Node q (nextEpoch 0 0) 0 nextStamp nextEpoch 0 s'.anchor :=
  ⟨_, ⟨1, 1, 0⟩, _, .seed 0 0 c₀ c₀_ne_one (Or.inl ⟨rfl, rfl, rfl⟩), ⟨by simp, rfl⟩,
    onChain_two.toNode hne (chainQueried (N := 0) (by omega)) le_rfl⟩

end Tachyon.Instances
