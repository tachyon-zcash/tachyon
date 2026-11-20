import Tachyon.Consensus
import Tachyon.SpendTree
import Tachyon.Unspent

/-!
# No double spend from covered spend leaves

`no_double_spend_of_valid` takes each stamp's nullifier pair and the second spend's lineage as
hypotheses. Here the pairs follow from the spend leaves the stamps cover, and the lineage from the
second spend's `NoteUnspent` segments.

A `CoveredSpend` of note `cm` in a published stamp `s` is what `Bundle::verify_covered` and the
stamp proof supply for one covered action: the bundle's covered actions and fees, accepted by
`BundleCovered` with `s`'s tachygrams as the published ones, the action digests consensus computed,
a derivation of the verified header `(setPoly (coveredDigests …), setPoly s.tachygrams, s.anchor)`,
and a `SpendAction` leaf of that derivation whose header carries `cm` and whose action digest is the
covered action's.

Consensus makes `s.anchor` an anchor the chain reaches in its epoch `e`, so a chain node at `e`
once the chain's anchor-fold calls up to `e` lie in `q` (`ChainQueried`). Every leaf of the
derivation is then anchored on an anchor the chain reaches in `e` (`StampTree.leaves_node`), so the
spend's lineage is at epoch `e` and the spend carries the note's nullifiers at `e` and `e + 1`
(`SpendDerivable.pair`). The leaf's digest is the covered action's, so `DigestLaw` makes the
action's carried pair that nullifier pair (`CoveredSpend.carried_pair`), and `verify_covered`
publishes the carried pair.

The spend's lineage starts at an epoch that published `cm` and proves the note's nullifier
unpublished in every epoch from there up to `e` (`SpendDerivable.lineage`). A `SpendableInit`
lineage starts at its creation stamp's epoch and covers no epoch. A `QrSpendableInit` lineage
starts at its bucket's epoch, which holds `cm`, and each `NoteUnspent` segment ends on the entry
anchor of the next segment's epoch, so `NoteUnspentDerivable.lineage` covers it.

"Same note" is equal `cm` and one creation. Every header from the spend back to its lineage start
threads `cm`, `SpendBind` ties the note secret to the lineage by `cm`, and `NoteSeed` makes `cm`
determine the master key (`NoteSecretDerivable.master_eq`), so the nullifier sequence is the
note's. A lineage that starts after the first spend's publication starts at a later epoch in which
the value `cm` is published. `no_double_spend_of_covered_spends` takes `cm` unpublished, as any
tachygram, between the first spend's publication and the second spend's anchor; it does not say why
`cm` would be published again.

`no_double_spend_of_covered_spends` covers spends in two stamps. Two spends at distinct covered
actions of one bundle share its stamp's anchor epoch, so both actions carry one nullifier pair,
which `verify_covered`'s tachygram uniqueness rejects (`no_double_spend_in_stamp`).
-/

namespace Tachyon

open Polynomial Chain

universe u v

variable {F : Type u} {Γ : Type v} [Field F]

/-- A spend of note `cm` at the covered action `index` of a bundle with covered `actions`, `fee` and
`adjunctFees`, whose stamp is published as `s`. `actions_queried` records the action digests
`verify_covered` computes. -/
structure CoveredSpend {Φ : Type*} (IsFee : F → Prop) (epoch : F → ℕ) (R : ℕ → F → Multiset F)
    (q : AnchorQueries F F ℕ) (nextStamp : F → ℕ → F[X] → F) (actionDigest : Γ → F → F → F)
    (Q : Γ → F → F → Prop) (Spend : SpendHeader F → Prop) (feeDigest : Φ → F → F)
    (actions : List (Γ × F × F)) (fee : Φ × F) (adjunctFees : List (Φ × F)) (s : Chain.Stamp F F)
    (cm : F) : Type (max u v) where
  covered : BundleCovered actions fee adjunctFees
    (⟨s.tachygrams, setPoly (s.tachygrams : Multiset F), s.anchor⟩ : PublishedStamp F F)
  actions_queried : ∀ a ∈ actions, Q a.1 a.2.1 a.2.2
  tree : StampTree IsFee epoch R q nextStamp actionDigest Q Spend
    ⟨setPoly (coveredDigests actionDigest feeDigest actions (fee :: adjunctFees)),
      setPoly (s.tachygrams : Multiset F), s.anchor⟩
  index : Fin actions.length
  header : SpendHeader F
  spend : Spend header
  witness : Γ
  leaf : (TreeLeaf.spend header spend witness : TreeLeaf F Γ Spend) ∈ tree.leaves
  cm_eq : header.cm = cm
  digest_eq : actionDigest witness header.nf_current header.nf_next =
    actionDigest actions[index].1 actions[index].2.1 actions[index].2.2

variable {D W P Φ : Type*} {IsFee : F → Prop} {epoch : F → ℕ}
  {R : ℕ → F → Multiset F} {q : AnchorQueries F F ℕ} {actionDigest : Γ → F → F → F}
  {Q : Γ → F → F → Prop} {genesis : F} {e₀ : ℕ}
  {nextStamp : F → ℕ → F[X] → F} {nextEpoch : F → ℕ → F} {zero : F}
  {Bucket : QrBucket F F → Prop} {Unspent : NoteUnspent F → Prop}
  {n : NoteQueries F W P} {noteCommit : W → F → F → F} {paymentKey : P → F → F}
  {nfMaster : F → F → F} {nullifier : F → ℕ → F} {qnr : F} {member : ℕ → F → F[X]} {emax : ℕ}
  {Secret : NoteSecret F → Prop} {r : EvidenceQueries F F D} {leaf : QrBucket F F → D}
  {node : D → D → D → D → D} {chain : List (Chain.Stamp F F)} {N : ℕ} {feeDigest : Φ → F → F}
  {actions : List (Γ × F × F)} {fee : Φ × F} {adjunctFees : List (Φ × F)}

/-- A covered spend of note `cm`, in a stamp anchored on a chain node, is at a covered action whose
carried pair is the note's nullifiers at the anchor's epoch and the next. -/
theorem CoveredSpend.carried_pair (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hunspent : UnspentSpec q nextEpoch Unspent) (hnote : NoteLaw n noteCommit paymentKey)
    (hdigest : DigestLaw IsFee R actionDigest Q) {s : Chain.Stamp F F} {cm master : F}
    (p : CoveredSpend IsFee epoch R q nextStamp actionDigest Q
      (SpendDerivable q nextStamp Bucket Unspent (NoteSecretDerivable n noteCommit paymentKey nfMaster)
        nullifier) feeDigest actions fee adjunctFees s cm)
    (hsecret : NoteSecretDerivable n noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hs : Chain.Node q genesis e₀ nextStamp nextEpoch (epoch s.anchor) s.anchor) :
    ({actions[p.index].2.1, actions[p.index].2.2} : Multiset F) =
      {nullifier master (epoch s.anchor), nullifier master (epoch s.anchor + 1)} := by
  obtain ⟨k, hk, hkcm, hcurrent, hnext⟩ :=
    p.spend.pair hlaw hunspent (p.tree.leaves_node (Chain.Node.stampClosed hlaw) hs _ p.leaf)
  obtain rfl : k.master = master := hk.master_eq hnote hsecret (hkcm.trans p.cm_eq)
  have ha : actions[p.index] ∈ actions := by simp
  rw [← hdigest.pair (epoch s.anchor) (p.actions_queried _ ha), ← p.digest_eq,
    hdigest.pair _ (p.tree.spend_queried p.leaf), hcurrent, hnext]

/-- A covered spend of note `cm`, in a stamp anchored on a chain node, publishes the note's
nullifiers at the anchor's epoch and the next. -/
theorem CoveredSpend.pair_le
    (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hunspent : UnspentSpec q nextEpoch Unspent) (hnote : NoteLaw n noteCommit paymentKey)
    (hdigest : DigestLaw IsFee R actionDigest Q) {s : Chain.Stamp F F} {cm master : F}
    (p : CoveredSpend IsFee epoch R q nextStamp actionDigest Q
      (SpendDerivable q nextStamp Bucket Unspent (NoteSecretDerivable n noteCommit paymentKey nfMaster)
        nullifier) feeDigest actions fee adjunctFees s cm)
    (hsecret : NoteSecretDerivable n noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hs : Chain.Node q genesis e₀ nextStamp nextEpoch (epoch s.anchor) s.anchor) :
    ({nullifier master (epoch s.anchor), nullifier master (epoch s.anchor + 1)} : Multiset F) ≤
      (s.tachygrams : Multiset F) := by
  have hcovered : (s.tachygrams : Multiset F) = _ := p.covered.tachygrams_covered
  rw [← p.carried_pair hlaw hunspent hnote hdigest hsecret hs, hcovered]
  exact pair_le_coveredTachygrams (a := actions[p.index]) (by simp) _

/-- A spendable lineage whose anchor the chain reaches in epoch `e ≤ N` is at epoch `e`. It starts
at an epoch that published its `cm`, and for every note secret of that `cm`, the nullifier at each
epoch from the start up to `e` is unpublished in that epoch. -/
theorem SpendableDerivable.lineage (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax)
    (hmaster : ∀ {k₁ k₂ : NoteSecret F}, Secret k₁ → Secret k₂ → k₁.cm = k₂.cm →
      k₁.master = k₂.master)
    (hbucket : ∀ b, Bucket b → b.Covers q nextStamp nextEpoch)
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {s : NoteSpendable F}
    (hs : SpendableDerivable q nextStamp Bucket
      (NoteUnspentDerivable Bucket qnr member Secret nullifier emax) s)
    {e : ℕ} (hN : e ≤ N) (hon : OnChain nextStamp nextEpoch zero chain e s.anchor) :
    s.epoch_current = e ∧ ∃ start, start ≤ e ∧ published chain start s.cm ∧
      ∀ k, Secret k → k.cm = s.cm →
        ∀ x, start ≤ x → x < e → ¬ published chain x (nullifier k.master x) := by
  have hentry : ∀ {e : ℕ} {u : NoteUnspent F},
      NoteUnspentDerivable Bucket qnr member Secret nullifier emax u → e ≤ N →
      OnChain nextStamp nextEpoch zero chain e u.anchor_next →
        u.anchor_next = entry nextStamp nextEpoch zero chain u.epoch_next ∧ u.epoch_next = e :=
    fun hu he hon => by
      obtain ⟨a, ha, hq⟩ := (NoteUnspentDerivable.spec hbucket).anchor_next_entry hu
      rw [ha] at hon ⊢
      obtain ⟨hentry, rfl⟩ := hon.of_nextEpoch hlaw hchain he hq
      exact ⟨hentry, rfl⟩
  induction hs generalizing e with
  | init cm prev creation e' hroot hq =>
    obtain ⟨rfl, -, hcreation⟩ := hon.of_nextStamp hlaw hchain hN hq
    refine ⟨rfl, e', le_rfl, ?_, fun _ _ _ x hx hx' => absurd hx' (by omega)⟩
    exact published_of_root_prod ((show creation.IsRoot cm from hroot).dvd
      (List.dvd_prod hcreation))
  | @qrInit u b hu hb hepoch hnext hsucc hroot =>
    obtain ⟨hunext, rfl⟩ := hentry hu hN hon
    obtain ⟨-, -, hincl⟩ :=
      (hbucket b hb).onChain hlaw hchain (by omega) (by rw [hnext, hunext, hsucc])
    obtain ⟨-, hlin⟩ := hu.lineage hlaw hqnr hmember hmaster hbucket hchain hN hunext
    refine ⟨rfl, u.epoch_start, hu.epoch_lt.le, ?_, hlin⟩
    exact hepoch ▸ hincl _ hroot
  | @lift s' u _ hu hcm hepoch hstart ih =>
    obtain ⟨hunext, rfl⟩ := hentry hu hN hon
    obtain ⟨hustart, hlin⟩ := hu.lineage hlaw hqnr hmember hmaster hbucket hchain hN hunext
    have hlt := hu.epoch_lt
    obtain ⟨-, start, hle, hpub, hlin'⟩ := ih (e := s'.epoch_current) (by omega)
      (by rw [hstart, hustart, hepoch]; exact entry_onChain _)
    refine ⟨rfl, start, hle.trans (hepoch ▸ hlt.le), hpub,
      fun k hk hkcm x hx hx' => ?_⟩
    by_cases hlt' : x < s'.epoch_current
    · exact hlin' k hk hkcm x hx hlt'
    · exact hlin k hk (hkcm.trans hcm) x (by omega) hx'

/-- A spend whose anchor the chain reaches in epoch `e ≤ N` has a lineage that starts at an epoch
that published its `cm`, and for every note secret of that `cm`, the nullifier at each epoch from
the start up to `e` is unpublished in that epoch. -/
theorem SpendDerivable.lineage (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax)
    (hmaster : ∀ {k₁ k₂ : NoteSecret F}, Secret k₁ → Secret k₂ → k₁.cm = k₂.cm →
      k₁.master = k₂.master)
    (hbucket : ∀ b, Bucket b → b.Covers q nextStamp nextEpoch)
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {h : SpendHeader F}
    (hspend : SpendDerivable q nextStamp Bucket
      (NoteUnspentDerivable Bucket qnr member Secret nullifier emax) Secret nullifier h)
    {e : ℕ} (hN : e ≤ N) (hon : OnChain nextStamp nextEpoch zero chain e h.anchor) :
    ∃ start, start ≤ e ∧ published chain start h.cm ∧
      ∀ k, Secret k → k.cm = h.cm →
        ∀ x, start ≤ x → x < e → ¬ published chain x (nullifier k.master x) := by
  cases hspend with
  | bind hs _ _ => exact (hs.lineage hlaw hqnr hmember hmaster hbucket hchain hN hon).2

/-- **No double spend across stamps.** On a valid chain whose anchor-fold calls up to the second
stamp's epoch lie in `q`, two stamps that each cover a spend of note `cm`, the first earlier in
chain order, contradict each other unless `cm` is published again after the first spend's
publication and no later than the second spend's anchor epoch. -/
theorem no_double_spend_of_covered_spends
    (hlaw : Chain.HashLaw q (nextEpoch zero 0) 0 nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax) (hevidence : EvidenceLaw r leaf node)
    (hnote : NoteLaw n noteCommit paymentKey) (hdigest : DigestLaw IsFee R actionDigest Q)
    {l₁ l₂ : List (Chain.Stamp F F)} {s₁ s₂ : Chain.Stamp F F} {cm master : F}
    {actions₁ actions₂ : List (Γ × F × F)} {fee₁ fee₂ : Φ × F} {adjunctFees₁ adjunctFees₂ : List (Φ × F)}
    (hchain : Chain.Valid epoch (OnChain nextStamp nextEpoch zero chain) chain)
    (hqueried : ChainQueried q nextStamp nextEpoch zero chain s₂.epoch)
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (p₁ : CoveredSpend IsFee epoch R q nextStamp actionDigest Q
      (SpendDerivable q nextStamp (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier)
      feeDigest actions₁ fee₁ adjunctFees₁ s₁ cm)
    (p₂ : CoveredSpend IsFee epoch R q nextStamp actionDigest Q
      (SpendDerivable q nextStamp (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier)
      feeDigest actions₂ fee₂ adjunctFees₂ s₂ cm)
    (hsecret : NoteSecretDerivable n noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hfresh : ∀ e, s₁.epoch < e → e ≤ epoch s₂.anchor → ¬ Chain.published chain e cm) :
    False := by
  have hbucket : ∀ b, QrBucketDerivable q r nextStamp nextEpoch qnr leaf node b →
      b.Covers q nextStamp nextEpoch := fun _ hb => hb.covers hqnr hevidence
  have hmaster : ∀ {k₁ k₂ : NoteSecret F}, NoteSecretDerivable n noteCommit paymentKey nfMaster k₁ →
      NoteSecretDerivable n noteCommit paymentKey nfMaster k₂ → k₁.cm = k₂.cm →
        k₁.master = k₂.master := fun h₁ h₂ hcm => h₁.master_eq hnote h₂ hcm
  have hunspent := NoteUnspentDerivable.spec (qnr := qnr) (member := member)
    (Secret := NoteSecretDerivable n noteCommit paymentKey nfMaster) (nullifier := nullifier)
    (emax := emax) hbucket
  have hne : ∀ s ∈ chain, s.tachygrams ≠ [] := fun s hs => (hchain.accepted s hs).tachygrams_ne_nil
  have hon : ∀ s ∈ chain, OnChain nextStamp nextEpoch zero chain (epoch s.anchor) s.anchor :=
    fun s hs => (hchain.accepted s hs).anchor_accepted
  have hs₁ : s₁ ∈ chain := by simp [hsplit]
  have hs₂' : s₂ ∈ chain := by simp [hsplit, hs₂]
  have he₁ : epoch s₁.anchor ≤ s₂.epoch :=
    (hchain.accepted s₁ hs₁).recency.1.trans (hchain.disjoint_of_window hsplit hs₂).1
  have he₂ : epoch s₂.anchor ≤ s₂.epoch := (hchain.accepted s₂ hs₂').recency.1
  obtain ⟨hle₂, hleaf₂⟩ :=
    p₂.tree.leaves_node (Good := fun e a => e ≤ s₂.epoch ∧ OnChain nextStamp nextEpoch zero chain e a)
      (OnChain.stampClosed hlaw hqueried) ⟨he₂, hon s₂ hs₂'⟩ _ p₂.leaf
  obtain ⟨start, hle, hpub, hlineage⟩ :=
    p₂.spend.lineage hlaw hqnr hmember hmaster hbucket hqueried hle₂ hleaf₂
  rw [p₂.cm_eq] at hpub hlineage
  have hstart : start ≤ s₁.epoch := by
    by_contra hlt
    exact hfresh start (by omega) hle hpub
  exact no_double_spend_of_valid (nf := nullifier master) hchain hsplit hs₂
    (p₁.pair_le hlaw hunspent hnote hdigest hsecret ((hon s₁ hs₁).toNode hne hqueried he₁))
    (p₂.pair_le hlaw hunspent hnote hdigest hsecret ((hon s₂ hs₂').toNode hne hqueried he₂))
    (hlineage _ hsecret rfl) hstart

/-- **No double spend within a stamp.** On a valid chain whose anchor-fold calls up to the stamp's
epoch lie in `q`, no bundle covers spends of note `cm` at two distinct covered actions. -/
theorem no_double_spend_in_stamp
    (hlaw : Chain.HashLaw q (nextEpoch zero 0) 0 nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hevidence : EvidenceLaw r leaf node)
    (hnote : NoteLaw n noteCommit paymentKey) (hdigest : DigestLaw IsFee R actionDigest Q)
    {s : Chain.Stamp F F} {cm master : F}
    (hchain : Chain.Valid epoch (OnChain nextStamp nextEpoch zero chain) chain) (hs : s ∈ chain)
    (hqueried : ChainQueried q nextStamp nextEpoch zero chain s.epoch)
    (p₁ p₂ : CoveredSpend IsFee epoch R q nextStamp actionDigest Q
      (SpendDerivable q nextStamp (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier)
      feeDigest actions fee adjunctFees s cm)
    (hsecret : NoteSecretDerivable n noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hindex : p₁.index ≠ p₂.index) :
    False := by
  have hbucket : ∀ b, QrBucketDerivable q r nextStamp nextEpoch qnr leaf node b →
      b.Covers q nextStamp nextEpoch := fun _ hb => hb.covers hqnr hevidence
  have hunspent := NoteUnspentDerivable.spec (qnr := qnr) (member := member)
    (Secret := NoteSecretDerivable n noteCommit paymentKey nfMaster) (nullifier := nullifier)
    (emax := emax) hbucket
  have hon : OnChain nextStamp nextEpoch zero chain (epoch s.anchor) s.anchor :=
    (hchain.accepted s hs).anchor_accepted
  have hnode := hon.toNode (fun s hs => (hchain.accepted s hs).tachygrams_ne_nil) hqueried
    (hchain.accepted s hs).recency.1
  have hmem : ∀ p : CoveredSpend IsFee epoch R q nextStamp actionDigest Q
      (SpendDerivable q nextStamp (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable q r nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable n noteCommit paymentKey nfMaster) nullifier)
      feeDigest actions fee adjunctFees s cm,
      nullifier master (epoch s.anchor) ∈ [actions[p.index].2.1, actions[p.index].2.2] := by
    intro p
    have h := p.carried_pair hlaw hunspent hnote hdigest hsecret hnode
    have hnf : nullifier master (epoch s.anchor) ∈
        ({actions[p.index].2.1, actions[p.index].2.2} : Multiset F) := by
      rw [h]
      simp
    simpa using hnf
  have hcovered : (s.tachygrams : Multiset F) = _ := p₁.covered.tachygrams_covered
  have hnodup : (coveredTachygrams actions (fee :: adjunctFees)).Nodup :=
    Multiset.coe_nodup.mp (hcovered ▸ Multiset.coe_nodup.mpr p₁.covered.tachygrams_nodup)
  have hpairwise := List.pairwise_iff_getElem.mp
    (List.nodup_flatMap.mp (List.nodup_append.mp hnodup).1).2
  rcases Nat.lt_or_gt_of_ne (Fin.val_ne_of_ne hindex) with h | h
  · exact hpairwise _ _ p₁.index.isLt p₂.index.isLt h (hmem p₁) (hmem p₂)
  · exact hpairwise _ _ p₂.index.isLt p₁.index.isLt h (hmem p₂) (hmem p₁)

end Tachyon
