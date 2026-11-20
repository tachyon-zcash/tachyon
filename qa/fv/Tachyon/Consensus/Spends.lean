import Tachyon.Consensus
import Tachyon.SpendTree
import Tachyon.Unspent

/-!
# No double spend from covered spend leaves

`no_double_spend_of_valid` takes each stamp's nullifier pair and the second spend's lineage as
hypotheses. Here the pairs follow from the spend leaves the stamps cover, and the lineage from the
second spend's `NoteUnspent` segments.

A `CoveredSpend` of note `cm` in a published stamp `s` is what `Bundle::verify` and the stamp proof
supply: the action set consensus rebuilt from the covered digests, a derivation of the verified
header `(setPoly covered, setPoly s.tachygrams, s.anchor)`, and a `SpendAction` leaf of that
derivation whose header carries `cm` and whose action digest is covered.

Consensus makes `s.anchor` an anchor the chain reaches in its epoch `e`, so a chain node at `e`.
Every leaf of the derivation is then anchored on an anchor the chain reaches in `e`
(`StampTree.leaves_node`), so the spend's lineage is at epoch `e` and the spend carries the note's
nullifiers at `e` and `e + 1` (`SpendDerivable.pair`). The derivation is `StampDerivable`
(`StampTree.derivable`), so the stamp publishes the covered leaf's tachygrams, which `DigestLaw`
makes that pair.

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

`no_double_spend_of_covered_spends` covers spends in two stamps. Two spends in one stamp share its
anchor epoch and so publish one nullifier pair twice, which the stamp's duplicate-free tachygram
list rejects (`no_double_spend_in_stamp`). Each `CoveredSpend` carries its own covered multiset,
and the model does not tie two spends' covered multisets together. `CoveredSpend.digest_covered` is
membership, so two covered spends can name one covered digest. That theorem takes both spends'
digests as two occurrences in the first spend's covered multiset.
-/

namespace Tachyon

open Polynomial Chain

universe u v

variable {F : Type u} {Γ : Type v} [Field F]

/-- A spend of note `cm` covered by the published stamp `s`. -/
structure CoveredSpend (IsFee : F → Prop) (epoch : F → ℕ) (R : ℕ → F → Multiset F)
    (nextStamp : F → ℕ → F[X] → F) (actionDigest : Γ → F → F → F)
    (Spend : SpendHeader F → Prop) (s : Chain.Stamp F F) (cm : F) : Type (max u v) where
  covered : Multiset F
  tree : StampTree IsFee epoch R nextStamp actionDigest Spend
    ⟨setPoly covered, setPoly (s.tachygrams : Multiset F), s.anchor⟩
  header : SpendHeader F
  spend : Spend header
  witness : Γ
  leaf : (TreeLeaf.spend header spend witness : TreeLeaf F Γ Spend) ∈ tree.leaves
  cm_eq : header.cm = cm
  digest_covered : actionDigest witness header.nf_current header.nf_next ∈ covered

variable {D W P : Type*} {IsFee : F → Prop} {epoch : F → ℕ}
  {R : ℕ → F → Multiset F} {actionDigest : Γ → F → F → F} {genesis : F} {e₀ : ℕ}
  {nextStamp : F → ℕ → F[X] → F} {nextEpoch : F → ℕ → F} {zero : F}
  {Bucket : QrBucket F F → Prop} {Unspent : NoteUnspent F → Prop}
  {noteCommit : W → F → F → F} {paymentKey : P → F → F} {nfMaster : F → F → F}
  {nullifier : F → ℕ → F} {qnr : F} {member : ℕ → F → F[X]} {emax : ℕ}
  {Secret : NoteSecret F → Prop} {leaf : QrBucket F F → D} {node : D → D → D → D → D}
  {chain : List (Chain.Stamp F F)}

/-- A covered spend of note `cm`, in a stamp anchored on a chain node, publishes the note's
nullifiers at the anchor's epoch and the next. -/
theorem CoveredSpend.pair_le [DecidableEq F] (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hunspent : UnspentSpec nextEpoch Unspent) (hnote : NoteLaw noteCommit paymentKey)
    (hdigest : DigestLaw IsFee R actionDigest) {s : Chain.Stamp F F} {cm master : F}
    (p : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp Bucket Unspent (NoteSecretDerivable noteCommit paymentKey nfMaster)
        nullifier) s cm)
    (hsecret : NoteSecretDerivable noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hs : Chain.Node genesis e₀ nextStamp nextEpoch (epoch s.anchor) s.anchor) :
    ({nullifier master (epoch s.anchor), nullifier master (epoch s.anchor + 1)} : Multiset F) ≤
      (s.tachygrams : Multiset F) := by
  have htachygrams : (s.tachygrams : Multiset F) = p.covered.bind (R (epoch s.anchor)) :=
    setPoly_injective ((p.tree.derivable hlaw hepoch hdigest hs).published rfl)
  obtain ⟨k, hk, hkcm, hcurrent, hnext⟩ :=
    p.spend.pair hlaw hunspent (p.tree.leaves_node (Chain.Node.stampClosed hlaw) hs _ p.leaf)
  obtain rfl : k.master = master := hk.master_eq hnote hsecret (hkcm.trans p.cm_eq)
  rw [htachygrams, ← hcurrent, ← hnext,
    ← hdigest.pair (epoch s.anchor) p.witness p.header.nf_current p.header.nf_next]
  exact Multiset.le_bind _ p.digest_covered

/-- A spendable lineage whose anchor the chain reaches in epoch `e` is at epoch `e`. It starts at an
epoch that published its `cm`, and for every note secret of that `cm`, the nullifier at each epoch
from the start up to `e` is unpublished in that epoch. -/
theorem SpendableDerivable.lineage (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax)
    (hmaster : ∀ {k₁ k₂ : NoteSecret F}, Secret k₁ → Secret k₂ → k₁.cm = k₂.cm →
      k₁.master = k₂.master)
    (hbucket : ∀ b, Bucket b → b.Covers nextStamp nextEpoch) {s : NoteSpendable F}
    (hs : SpendableDerivable nextStamp Bucket
      (NoteUnspentDerivable Bucket qnr member Secret nullifier emax) s)
    {e : ℕ} (hon : OnChain nextStamp nextEpoch zero chain e s.anchor) :
    s.epoch_current = e ∧ ∃ start, start ≤ e ∧ published chain start s.cm ∧
      ∀ k, Secret k → k.cm = s.cm →
        ∀ x, start ≤ x → x < e → ¬ published chain x (nullifier k.master x) := by
  have hentry : ∀ {e : ℕ} {u : NoteUnspent F},
      NoteUnspentDerivable Bucket qnr member Secret nullifier emax u →
      OnChain nextStamp nextEpoch zero chain e u.anchor_next →
        u.anchor_next = entry nextStamp nextEpoch zero chain u.epoch_next ∧ u.epoch_next = e :=
    fun hu hon => by
      obtain ⟨a, ha⟩ := (NoteUnspentDerivable.spec hbucket).anchor_next_entry hu
      rw [ha] at hon ⊢
      obtain ⟨hentry, rfl⟩ := hon.of_nextEpoch hlaw
      exact ⟨hentry, rfl⟩
  induction hs generalizing e with
  | init cm prev creation e' hroot =>
    obtain ⟨rfl, -, hcreation⟩ := hon.of_nextStamp hlaw
    refine ⟨rfl, e', le_rfl, ?_, fun _ _ _ x hx hx' => absurd hx' (by omega)⟩
    exact published_of_root_prod ((show creation.IsRoot cm from hroot).dvd
      (List.dvd_prod hcreation))
  | @qrInit u b hu hb hepoch hnext hsucc hroot =>
    obtain ⟨hunext, rfl⟩ := hentry hu hon
    obtain ⟨-, -, hincl⟩ := (hbucket b hb).onChain hlaw (by rw [hnext, hunext, hsucc])
    obtain ⟨-, hlin⟩ := hu.lineage hlaw hqnr hmember hmaster hbucket hunext
    refine ⟨rfl, u.epoch_start, hu.epoch_lt.le, ?_, hlin⟩
    exact hepoch ▸ hincl _ hroot
  | @lift s' u _ hu hcm hepoch hstart ih =>
    obtain ⟨hunext, rfl⟩ := hentry hu hon
    obtain ⟨hustart, hlin⟩ := hu.lineage hlaw hqnr hmember hmaster hbucket hunext
    obtain ⟨-, start, hle, hpub, hlin'⟩ :=
      ih (e := s'.epoch_current) (by rw [hstart, hustart, hepoch]; exact entry_onChain _)
    refine ⟨rfl, start, hle.trans (hepoch ▸ hu.epoch_lt.le), hpub,
      fun k hk hkcm x hx hx' => ?_⟩
    by_cases hlt : x < s'.epoch_current
    · exact hlin' k hk hkcm x hx hlt
    · exact hlin k hk (hkcm.trans hcm) x (by omega) hx'

/-- A spend whose anchor the chain reaches in epoch `e` has a lineage that starts at an epoch that
published its `cm`, and for every note secret of that `cm`, the nullifier at each epoch from the
start up to `e` is unpublished in that epoch. -/
theorem SpendDerivable.lineage (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax)
    (hmaster : ∀ {k₁ k₂ : NoteSecret F}, Secret k₁ → Secret k₂ → k₁.cm = k₂.cm →
      k₁.master = k₂.master)
    (hbucket : ∀ b, Bucket b → b.Covers nextStamp nextEpoch) {h : SpendHeader F}
    (hspend : SpendDerivable nextStamp Bucket
      (NoteUnspentDerivable Bucket qnr member Secret nullifier emax) Secret nullifier h)
    {e : ℕ} (hon : OnChain nextStamp nextEpoch zero chain e h.anchor) :
    ∃ start, start ≤ e ∧ published chain start h.cm ∧
      ∀ k, Secret k → k.cm = h.cm →
        ∀ x, start ≤ x → x < e → ¬ published chain x (nullifier k.master x) := by
  cases hspend with
  | bind hs _ _ => exact (hs.lineage hlaw hqnr hmember hmaster hbucket hon).2

/-- **No double spend across stamps.** On a valid chain, two stamps that each cover a spend of note
`cm`, the first earlier in chain order, contradict each other unless `cm` is published again after
the first spend's publication and no later than the second spend's anchor epoch. -/
theorem no_double_spend_of_covered_spends [DecidableEq F]
    (hlaw : Chain.HashLaw (nextEpoch zero 0) 0 nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node (nextEpoch zero 0) 0 nextStamp nextEpoch e a →
      epoch a = e)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax) (hevidence : EvidenceLaw leaf node)
    (hnote : NoteLaw noteCommit paymentKey) (hdigest : DigestLaw IsFee R actionDigest)
    {l₁ l₂ : List (Chain.Stamp F F)} {s₁ s₂ : Chain.Stamp F F} {cm master : F}
    (hchain : Chain.Valid epoch (OnChain nextStamp nextEpoch zero chain) chain)
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (p₁ : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp (QrBucketDerivable nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier) s₁ cm)
    (p₂ : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp (QrBucketDerivable nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier) s₂ cm)
    (hsecret : NoteSecretDerivable noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hfresh : ∀ e, s₁.epoch < e → e ≤ epoch s₂.anchor → ¬ Chain.published chain e cm) :
    False := by
  have hbucket : ∀ b, QrBucketDerivable nextStamp nextEpoch qnr leaf node b →
      b.Covers nextStamp nextEpoch := fun _ hb => hb.covers hqnr hevidence
  have hmaster : ∀ {k₁ k₂ : NoteSecret F}, NoteSecretDerivable noteCommit paymentKey nfMaster k₁ →
      NoteSecretDerivable noteCommit paymentKey nfMaster k₂ → k₁.cm = k₂.cm →
        k₁.master = k₂.master := fun h₁ h₂ hcm => h₁.master_eq hnote h₂ hcm
  have hunspent := NoteUnspentDerivable.spec (qnr := qnr) (member := member)
    (Secret := NoteSecretDerivable noteCommit paymentKey nfMaster) (nullifier := nullifier)
    (emax := emax) hbucket
  have hne : ∀ s ∈ chain, s.tachygrams ≠ [] := fun s hs => (hchain.accepted s hs).tachygrams_ne_nil
  have hon : ∀ s ∈ chain, OnChain nextStamp nextEpoch zero chain (epoch s.anchor) s.anchor :=
    fun s hs => (hchain.accepted s hs).anchor_accepted
  have hs₁ : s₁ ∈ chain := by simp [hsplit]
  have hs₂' : s₂ ∈ chain := by simp [hsplit, hs₂]
  obtain ⟨start, hle, hpub, hlineage⟩ := p₂.spend.lineage hlaw hqnr hmember hmaster hbucket
    (p₂.tree.leaves_node (OnChain.stampClosed hlaw) (hon s₂ hs₂') _ p₂.leaf)
  rw [p₂.cm_eq] at hpub hlineage
  have hstart : start ≤ s₁.epoch := by
    by_contra hlt
    exact hfresh start (by omega) hle hpub
  exact no_double_spend_of_valid (nf := nullifier master) hchain hsplit hs₂
    (p₁.pair_le hlaw hepoch hunspent hnote hdigest hsecret ((hon s₁ hs₁).toNode hne))
    (p₂.pair_le hlaw hepoch hunspent hnote hdigest hsecret ((hon s₂ hs₂').toNode hne))
    (hlineage _ hsecret rfl) hstart

/-- **No double spend within a stamp.** On a valid chain, no stamp covers two spends of note `cm`
whose action digests are two occurrences in the first spend's covered multiset. -/
theorem no_double_spend_in_stamp [DecidableEq F]
    (hlaw : Chain.HashLaw (nextEpoch zero 0) 0 nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node (nextEpoch zero 0) 0 nextStamp nextEpoch e a →
      epoch a = e)
    (hqnr : ¬ IsSquare qnr) (hevidence : EvidenceLaw leaf node)
    (hnote : NoteLaw noteCommit paymentKey) (hdigest : DigestLaw IsFee R actionDigest)
    {s : Chain.Stamp F F} {cm master : F}
    (hchain : Chain.Valid epoch (OnChain nextStamp nextEpoch zero chain) chain) (hs : s ∈ chain)
    (p₁ p₂ : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp (QrBucketDerivable nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier) s cm)
    (hsecret : NoteSecretDerivable noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hoccurrences : ({actionDigest p₁.witness p₁.header.nf_current p₁.header.nf_next,
      actionDigest p₂.witness p₂.header.nf_current p₂.header.nf_next} : Multiset F) ≤
        p₁.covered) :
    False := by
  have hbucket : ∀ b, QrBucketDerivable nextStamp nextEpoch qnr leaf node b →
      b.Covers nextStamp nextEpoch := fun _ hb => hb.covers hqnr hevidence
  have hunspent := NoteUnspentDerivable.spec (qnr := qnr) (member := member)
    (Secret := NoteSecretDerivable noteCommit paymentKey nfMaster) (nullifier := nullifier)
    (emax := emax) hbucket
  have hon : OnChain nextStamp nextEpoch zero chain (epoch s.anchor) s.anchor :=
    (hchain.accepted s hs).anchor_accepted
  have hnode := hon.toNode fun s hs => (hchain.accepted s hs).tachygrams_ne_nil
  have hR : ∀ p : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp (QrBucketDerivable nextStamp nextEpoch qnr leaf node)
        (NoteUnspentDerivable (QrBucketDerivable nextStamp nextEpoch qnr leaf node) qnr member
          (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier emax)
        (NoteSecretDerivable noteCommit paymentKey nfMaster) nullifier) s cm,
      R (epoch s.anchor) (actionDigest p.witness p.header.nf_current p.header.nf_next) =
        {nullifier master (epoch s.anchor), nullifier master (epoch s.anchor + 1)} := by
    intro p
    obtain ⟨k, hk, hkcm, hcurrent, hnext⟩ :=
      p.spend.pair hlaw hunspent (p.tree.leaves_node (Chain.Node.stampClosed hlaw) hnode _ p.leaf)
    obtain rfl : k.master = master := hk.master_eq hnote hsecret (hkcm.trans p.cm_eq)
    rw [hdigest.pair, hcurrent, hnext]
  have htachygrams : (s.tachygrams : Multiset F) = p₁.covered.bind (R (epoch s.anchor)) :=
    setPoly_injective ((p₁.tree.derivable hlaw hepoch hdigest hnode).published rfl)
  obtain ⟨rest, hrest⟩ := Multiset.le_iff_exists_add.mp hoccurrences
  have hnodup : (s.tachygrams : Multiset F).Nodup :=
    Multiset.coe_nodup.mpr (hchain.accepted s hs).tachygrams_nodup
  rw [htachygrams, hrest, Multiset.add_bind, Multiset.insert_eq_cons, Multiset.cons_bind,
    Multiset.singleton_bind, hR p₁, hR p₂] at hnodup
  have := (Multiset.nodup_add.mp (Multiset.nodup_add.mp hnodup).1).2.2
  have hmem : nullifier master (epoch s.anchor) ∈
      ({nullifier master (epoch s.anchor), nullifier master (epoch s.anchor + 1)} : Multiset F) := by
    simp
  exact Multiset.disjoint_left.mp this hmem hmem

end Tachyon
