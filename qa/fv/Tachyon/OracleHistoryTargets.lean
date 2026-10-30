import Tachyon.OraclePrefixes

/-!
# Candidate key-collision targets from a recorded oracle prefix

Record each queried input with its actual table answer. A fresh-point update
does not change this prefix history. Public key candidates and nonce words
extracted from it therefore form a fixed target set before the fresh answer.

For a history of length `Q`, one optional key per input and the observed word
per answer give at most `Q(Q+1)^2` randomized-key collision targets; zero is
included as the output-action offset. Any new key equalling a key built from
those prior candidates must hit this set. Lossless scalar embedding and a
nonzero generator bound the eligible fresh words by that set's size.

This does not assert that real spend-frame key/nonce dependencies are ordered
that way. The protocol-specific proof must either establish the relevant
history memberships or expose a guessed note/payment-hash output. Concrete
Poseidon uniformity and random-oracle security remain separate assumptions.
-/

namespace Tachyon.Foundation.Oracle.OracleComp

variable {T W α : Type*}

def observations (program : OracleComp T W α) (table : T → W) : List (T × W) :=
  (program.queries table).map fun input => (input, table input)

theorem observations_update [DecidableEq T] (program : OracleComp T W α)
    (table : T → W) (input : T) (word : W) (hfresh : input ∉ program.queries table) :
    program.observations (Function.update table input word) = program.observations table := by
  have hagree : ∀ q ∈ program.queries table, table q = (Function.update table input word) q := by
    intro q hq
    have hqt : q ≠ input := fun heq => hfresh (heq ▸ hq)
    rw [Function.update_apply, if_neg hqt]
  have hlog := (run_congr_of_agree program table (Function.update table input word) hagree).2.symm
  unfold observations
  rw [hlog]
  apply List.map_congr_left
  intro q hq
  exact congrArg (fun value => (q, value)) (hagree q hq).symm

def before (n : ℕ) (program : OracleComp T W α) (table : T → W) : List (T × W) :=
  (stopAfter n program).observations table

theorem before_update [DecidableEq T] (n : ℕ) (program : OracleComp T W α)
    (table : T → W) (input : T) (word : W) (hfresh : input ∉ (program.queries table).take n) :
    before n program (Function.update table input word) = before n program table :=
  observations_update (stopAfter n program) table input word (by rwa [queries_stopAfter])

theorem before_length_le (n : ℕ) (program : OracleComp T W α) (table : T → W) :
    (before n program table).length ≤ n := by
  simp only [before, observations, List.length_map, queries_stopAfter, List.length_take]
  exact Nat.min_le_left _ _

end Tachyon.Foundation.Oracle.OracleComp

namespace Tachyon.PairingTargets

open Foundation.Oracle Foundation.Oracle.OracleComp

variable {T V G : Type*} [DecidableEq V] [DecidableEq G]

def keys (keyOf : T → Option G) (history : List (T × V)) : Finset G :=
  (history.filterMap fun row => keyOf row.1).toFinset

def words (history : List (T × V)) : Finset V := (history.map Prod.snd).toFinset

omit [DecidableEq V] in
theorem mem_keys_iff (keyOf : T → Option G) (history : List (T × V)) (key : G) :
    key ∈ keys keyOf history ↔ ∃ row ∈ history, keyOf row.1 = some key := by
  simp [keys]

theorem mem_words_iff (history : List (T × V)) (word : V) :
    word ∈ words history ↔ ∃ row ∈ history, row.2 = word := by
  simp [words]

omit [DecidableEq V] in
theorem keys_card_le (keyOf : T → Option G) (history : List (T × V)) :
    (keys keyOf history).card ≤ history.length := by
  calc
    _ ≤ (history.filterMap fun row => keyOf row.1).length := List.toFinset_card_le _
    _ ≤ history.length := by apply List.length_filterMap_le

theorem words_card_le (history : List (T × V)) : (words history).card ≤ history.length := by
  calc
    _ ≤ (history.map Prod.snd).length := List.toFinset_card_le _
    _ = history.length := List.length_map _

variable {K : Type*} [Field K] [AddCommGroup G] [Module K G]

def targets (embed : V → K) (base : G) (keyOf : T → Option G) (history : List (T × V)) : Finset G :=
  (((insert 0 (keys keyOf history)).product (words history)).product (insert 0 (keys keyOf history))).image
    fun entry => entry.1.1 + embed entry.1.2 • base - entry.2

theorem targets_card_le (embed : V → K) (base : G) (keyOf : T → Option G) (history : List (T × V)) :
    (targets embed base keyOf history).card ≤ (history.length + 1) * history.length * (history.length + 1) := by
  have hk : (insert 0 (keys keyOf history)).card ≤ history.length + 1 :=
    (Finset.card_insert_le _ _).trans (Nat.add_le_add_right (keys_card_le keyOf history) 1)
  calc
    _ ≤ (((insert 0 (keys keyOf history)).product (words history)).product
        (insert 0 (keys keyOf history))).card := Finset.card_image_le
    _ = ((insert 0 (keys keyOf history)).card * (words history).card) *
        (insert 0 (keys keyOf history)).card :=
      (Finset.card_product ((insert 0 (keys keyOf history)).product (words history))
        (insert 0 (keys keyOf history))).trans
          (congrArg (fun count => count * (insert 0 (keys keyOf history)).card)
            (Finset.card_product (insert 0 (keys keyOf history)) (words history)))
    _ ≤ _ := Nat.mul_le_mul (Nat.mul_le_mul hk (words_card_le history)) hk

/-- Key equality forces the new nonce into the fixed target set when the
other word and both offsets are actually present in the prior history. -/
theorem collision_mem_targets (embed : V → K) (base : G) (keyOf : T → Option G)
    (history : List (T × V)) {oldKey newKey : G} {oldWord newWord : V}
    (holdKey : oldKey ∈ insert 0 (keys keyOf history))
    (hnewKey : newKey ∈ insert 0 (keys keyOf history)) (holdWord : oldWord ∈ words history)
    (heq : newKey + embed newWord • base = oldKey + embed oldWord • base) :
    embed newWord • base ∈ targets embed base keyOf history := by
  apply Finset.mem_image.mpr
  refine ⟨((oldKey, oldWord), newKey), Finset.mem_product.mpr
    ⟨Finset.mem_product.mpr ⟨holdKey, holdWord⟩, hnewKey⟩, ?_⟩
  change oldKey + embed oldWord • base - newKey = embed newWord • base
  rw [← heq]
  exact add_sub_cancel_left newKey (embed newWord • base)

theorem prefix_targets_update {α : Type*} [DecidableEq T]
    (n : ℕ) (program : OracleComp T V α) (table : T → V) (input : T) (word : V)
    (hfresh : input ∉ (program.queries table).take n)
    (embed : V → K) (base : G) (keyOf : T → Option G) :
    targets embed base keyOf (before n program (Function.update table input word)) =
      targets embed base keyOf (before n program table) :=
  congrArg (targets embed base keyOf) (before_update n program table input word hfresh)

variable [DecidableEq K] [Fintype V]

theorem eligible_words_card_le (embed : V → K) (hembed : Function.Injective embed)
    (base : G) (hbase : base ≠ 0) (keyOf : T → Option G) (history : List (T × V)) :
    (Finset.univ.filter fun word => embed word • base ∈ targets embed base keyOf history).card ≤
      (history.length + 1) * history.length * (history.length + 1) := by
  calc
    _ ≤ (targets embed base keyOf history).card := by
      simpa [NonceChallengeBounds.randomizedKey] using
        NonceChallengeBounds.card_fixed_targets_le embed hembed base 0 (targets embed base keyOf history) hbase
    _ ≤ _ := targets_card_le embed base keyOf history

/-- The candidate set is genuinely determined by the recorded prefix, so
reprogramming the fresh word does not introduce answer-dependent targets. -/
theorem prefix_eligible_words_card_le {α : Type*} [DecidableEq T]
    (n : ℕ) (program : OracleComp T V α) (table : T → V) (input : T)
    (hfresh : input ∉ (program.queries table).take n)
    (embed : V → K) (hembed : Function.Injective embed) (base : G) (hbase : base ≠ 0)
    (keyOf : T → Option G) :
    (Finset.univ.filter fun word => embed word • base ∈
      targets embed base keyOf (before n program (Function.update table input word))).card ≤
        (n + 1) * n * (n + 1) := by
  have hhistory : ∀ word, before n program (Function.update table input word) = before n program table :=
    fun word => before_update n program table input word hfresh
  simp_rw [hhistory]
  have hlen := before_length_le n program table
  calc
    _ ≤ ((before n program table).length + 1) * (before n program table).length *
        ((before n program table).length + 1) :=
      eligible_words_card_le embed hembed base hbase keyOf _
    _ ≤ _ := Nat.mul_le_mul (Nat.mul_le_mul (Nat.add_le_add_right hlen 1) hlen)
      (Nat.add_le_add_right hlen 1)

namespace Examples

def program : OracleComp ℕ Bool Unit := .query 0 (fun _ => .query 1 (fun _ => .pure ()))
def table (input : ℕ) : Bool := decide (input = 0)
def keyOf (input : ℕ) : Option ℚ := if input = 0 then some 2 else none
def embed (word : Bool) : ℚ := if word then 1 else 0
def history := before 1 program table
def candidates : Finset ℚ := targets embed 1 keyOf history

#guard history == [(0, true)]
#guard (keys keyOf history).card == 1
#guard (words history).card == 1
#guard candidates.card == 3
#guard decide ((-1 : ℚ) ∈ candidates)
#guard !decide ((5 : ℚ) ∈ candidates)
#guard (Finset.univ.filter fun word : Bool => embed word • (1 : ℚ) ∈ candidates).card == 1
#guard before 1 program (Function.update table 1 true) == history

end Examples

end Tachyon.PairingTargets
