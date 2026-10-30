import Mathlib.Data.List.Basic

/-!
# Adaptive oracle computations, query logs and fresh-query normalization

Ported and adapted from ragu `qa/fv/Ragu/Foundation/Oracle/OracleComp.lean`
at `ea0bf839`, itself ported from `zcash/ironwood` at
`3c056cbebf2880b54f801c348cb67ce7dc9f2a05`.

We retain the structural computation, table execution, query bound, cache
normalization and sequencing fragment. The probability import and later
measure/escape reductions are deliberately omitted: this phase establishes
operational causality only, and does not claim that concrete Poseidon is a
random oracle or that fixed-target counting applies to an adaptive target.
This restricted port avoids introducing unused probability dependencies or
an unsupported Fiat-Shamir security claim.

The whole-table semantics is deterministic for any supplied function. A
future random-oracle layer must separately justify uniform fresh answers.
-/

namespace Tachyon.Foundation.Oracle

inductive OracleComp (T W α : Type*) where
  | pure (value : α)
  | query (input : T) (continuation : W → OracleComp T W α)

namespace OracleComp

variable {T W α β : Type*}

def run : OracleComp T W α → (T → W) → α
  | .pure value, _ => value
  | .query input next, table => (next (table input)).run table

def queries : OracleComp T W α → (T → W) → List T
  | .pure _, _ => []
  | .query input next, table => input :: (next (table input)).queries table

theorem run_update_of_not_mem_queries [DecidableEq T]
    (program : OracleComp T W α) (table : T → W) (input : T) (word : W)
    (hfresh : input ∉ program.queries table) :
    program.run (Function.update table input word) = program.run table := by
  induction program with
  | pure value => rfl
  | query q next ih =>
    simp only [queries, List.mem_cons, not_or] at hfresh
    have hqt : q ≠ input := Ne.symm hfresh.1
    rw [run, run, Function.update_apply, if_neg hqt]
    exact ih (table q) hfresh.2

theorem run_congr_of_agree (program : OracleComp T W α) (table other : T → W)
    (h : ∀ input ∈ program.queries table, table input = other input) :
    program.run table = program.run other ∧ program.queries table = program.queries other := by
  induction program with
  | pure value => exact ⟨rfl, rfl⟩
  | query input next ih =>
    have hword : table input = other input := h input List.mem_cons_self
    obtain ⟨hrun, hlog⟩ := ih (table input)
      (fun q hq => h q (List.mem_cons_of_mem input hq))
    exact ⟨by simpa only [run, ← hword] using hrun,
      by simpa only [queries, ← hword] using congrArg (List.cons input) hlog⟩

inductive QueryBound : OracleComp T W α → ℕ → Prop
  | pure (value : α) (Q : ℕ) : QueryBound (.pure value) Q
  | query {input : T} {next : W → OracleComp T W α} {Q : ℕ}
      (h : ∀ word, QueryBound (next word) Q) : QueryBound (.query input next) (Q + 1)

theorem QueryBound.mono {program : OracleComp T W α} {Q Q' : ℕ}
    (h : QueryBound program Q) (hle : Q ≤ Q') : QueryBound program Q' := by
  induction h generalizing Q' with
  | pure value _ => exact .pure value Q'
  | @query input next Q h ih =>
    cases Q' with
    | zero => exact False.elim (Nat.not_succ_le_zero _ hle)
    | succ Q' => exact .query (fun word => ih word (Nat.le_of_succ_le_succ hle))

theorem queries_length_le {program : OracleComp T W α} {Q : ℕ}
    (h : QueryBound program Q) (table : T → W) : (program.queries table).length ≤ Q := by
  induction h with
  | pure => exact Nat.zero_le _
  | query h ih => exact Nat.succ_le_succ (ih _)

inductive AvoidsCache [DecidableEq T] : List (T × W) → OracleComp T W α → Prop
  | pure (cache : List (T × W)) (value : α) : AvoidsCache cache (.pure value)
  | query {cache : List (T × W)} {input : T} {next : W → OracleComp T W α}
      (hfresh : input ∉ cache.map Prod.fst)
      (h : ∀ word, AvoidsCache ((input, word) :: cache) (next word)) :
      AvoidsCache cache (.query input next)

/-- Cached queries are answered without another oracle call. -/
def dedup [DecidableEq T] (cache : List (T × W)) : OracleComp T W α → OracleComp T W α
  | .pure value => .pure value
  | .query input next =>
    match cache.find? (fun pair => pair.1 = input) with
    | some pair => dedup cache (next pair.2)
    | none => .query input (fun word => dedup ((input, word) :: cache) (next word))

theorem run_dedup [DecidableEq T] (program : OracleComp T W α) (table : T → W)
    (cache : List (T × W)) (hconsistent : ∀ pair ∈ cache, table pair.1 = pair.2) :
    (dedup cache program).run table = program.run table := by
  induction program generalizing cache with
  | pure value => rfl
  | query input next ih =>
    rw [dedup]
    cases hfind : cache.find? (fun pair => pair.1 = input) with
    | some pair =>
      have hp := List.find?_some hfind
      have hmem := List.mem_of_find?_eq_some hfind
      have hinput : pair.1 = input := by simpa using hp
      have hword : table input = pair.2 := hinput ▸ hconsistent pair hmem
      rw [run, ih pair.2 cache hconsistent, hword]
    | none =>
      rw [run, run]
      apply ih (table input) ((input, table input) :: cache)
      intro pair hpair
      rcases List.mem_cons.mp hpair with rfl | hpair
      · rfl
      · exact hconsistent pair hpair

theorem dedup_avoidsCache [DecidableEq T] (cache : List (T × W)) (program : OracleComp T W α) :
    AvoidsCache cache (dedup cache program) := by
  induction program generalizing cache with
  | pure value => exact .pure cache value
  | query input next ih =>
    rw [dedup]
    cases hfind : cache.find? (fun pair => pair.1 = input) with
    | some pair => exact ih pair.2 cache
    | none =>
      refine .query ?_ (fun word => ih word ((input, word) :: cache))
      intro hmem
      obtain ⟨pair, hpair, heq⟩ := List.mem_map.mp hmem
      have hnone := List.find?_eq_none.mp hfind pair hpair
      simp [heq] at hnone

theorem dedup_queryBound [DecidableEq T] {program : OracleComp T W α} {Q : ℕ}
    (h : QueryBound program Q) (cache : List (T × W)) : QueryBound (dedup cache program) Q := by
  induction h generalizing cache with
  | pure value Q => exact .pure value Q
  | @query input next Q h ih =>
    rw [dedup]
    cases hfind : cache.find? (fun pair => pair.1 = input) with
    | some pair => exact (ih pair.2 cache).mono (Nat.le_succ Q)
    | none => exact .query (fun word => ih word ((input, word) :: cache))

/-- Every issued query is fresh relative to the existing cache. -/
theorem AvoidsCache.not_mem_cache [DecidableEq T] {cache : List (T × W)}
    {program : OracleComp T W α} (h : AvoidsCache cache program) (table : T → W) :
    ∀ input ∈ program.queries table, input ∉ cache.map Prod.fst := by
  induction h with
  | pure => intro input hinput; cases hinput
  | @query cache current next hfresh hnext ih =>
    intro input hinput hcache
    rcases List.mem_cons.mp hinput with rfl | hinput
    · exact hfresh hcache
    · exact ih (table current) input hinput (List.mem_cons_of_mem current hcache)

/-- The normalized execution contains no repeated query, on every oracle
table, not merely in the executable example's particular branch. -/
theorem AvoidsCache.queries_nodup [DecidableEq T] {cache : List (T × W)}
    {program : OracleComp T W α} (h : AvoidsCache cache program) (table : T → W) :
    (program.queries table).Nodup := by
  induction h with
  | pure => exact .nil
  | @query cache current next hfresh hnext ih =>
    apply List.nodup_cons.mpr
    refine ⟨?_, ih (table current)⟩
    intro hmem
    exact (hnext (table current)).not_mem_cache table current hmem List.mem_cons_self

theorem dedup_queries_nodup [DecidableEq T] (cache : List (T × W))
    (program : OracleComp T W α) (table : T → W) : ((dedup cache program).queries table).Nodup :=
  (dedup_avoidsCache cache program).queries_nodup table

def bind : OracleComp T W α → (α → OracleComp T W β) → OracleComp T W β
  | .pure value, f => f value
  | .query input next, f => .query input (fun word => (next word).bind f)

theorem run_bind (program : OracleComp T W α) (f : α → OracleComp T W β) (table : T → W) :
    (program.bind f).run table = (f (program.run table)).run table := by
  induction program with
  | pure => rfl
  | query input next ih => exact ih (table input)

namespace Examples

def table (input : ℕ) : Bool := decide (input = 0)
def adaptive : OracleComp ℕ Bool ℕ :=
  .query 0 (fun word => .query (if word then 1 else 2) (fun _ => .pure (if word then 10 else 20)))
def repeated : OracleComp ℕ Bool (Bool × Bool) := .query 0 (fun a => .query 0 (fun b => .pure (a, b)))

#guard adaptive.run table == 10
#guard adaptive.queries table == [0, 1]
#guard adaptive.run (Function.update table 2 true) == 10
#guard repeated.queries table == [0, 0]
#guard (dedup [] repeated).queries table == [0]
#guard (dedup [] repeated).run table == (true, true)

end Examples

end OracleComp
end Tachyon.Foundation.Oracle
