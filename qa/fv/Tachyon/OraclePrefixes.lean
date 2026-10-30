import Tachyon.Foundation.AdaptiveOracle
import Tachyon.NonceChallengeBounds

/-!
# Prepared oracle prefixes, deterministic forks and fixed-target bounds

`stopAfter n` executes at most the first `n` oracle calls and returns the
remaining program as data. Reprogramming a point absent from that prefix
leaves the prepared state unchanged. If that state is a query at the fresh
point, the reprogrammed execution resumes its same continuation with the new
answer (`run_fork_at_prepared_query`).

Any target selector of that prepared state is therefore blind to the fresh
answer. `card_prepared_targets_le` connects this operational fact to the nonce
counting bound. It does not prove that actual spend/payment/note targets are
selectors of that prefix, nor that concrete Poseidon is uniform. The adversary
program is held fixed while the table is reprogrammed; the random-oracle game
must separately sample its table independently of that program.
-/

namespace Tachyon.Foundation.Oracle.OracleComp

variable {T W α β : Type*}

def stopAfter : ℕ → OracleComp T W α → OracleComp T W (OracleComp T W α)
  | 0, program => .pure program
  | _ + 1, .pure value => .pure (.pure value)
  | n + 1, .query input next => .query input (fun word => stopAfter n (next word))

theorem queries_stopAfter (n : ℕ) (program : OracleComp T W α) (table : T → W) :
    (stopAfter n program).queries table = (program.queries table).take n := by
  induction n generalizing program with
  | zero => rfl
  | succ n ih =>
    cases program with
    | pure value => rfl
    | query input next => simpa [stopAfter, queries] using congrArg (List.cons input) (ih (next (table input)))

theorem run_resume (n : ℕ) (program : OracleComp T W α) (table : T → W) :
    ((stopAfter n program).run table).run table = program.run table := by
  induction n generalizing program with
  | zero => rfl
  | succ n ih =>
    cases program with
    | pure value => rfl
    | query input next => exact ih (next (table input))

theorem stopAfter_update [DecidableEq T] (n : ℕ) (program : OracleComp T W α)
    (table : T → W) (input : T) (word : W)
    (hfresh : input ∉ (program.queries table).take n) :
    (stopAfter n program).run (Function.update table input word) = (stopAfter n program).run table :=
  run_update_of_not_mem_queries (stopAfter n program) table input word (by rwa [queries_stopAfter])

theorem prepared_update [DecidableEq T] (n : ℕ) (program : OracleComp T W α)
    (table : T → W) (input : T) (word : W) (prepare : OracleComp T W α → β)
    (hfresh : input ∉ (program.queries table).take n) :
    prepare ((stopAfter n program).run (Function.update table input word)) =
      prepare ((stopAfter n program).run table) :=
  congrArg prepare (stopAfter_update n program table input word hfresh)

/-- The nonce point, randomized key or other values in the prepared query
input stay fixed across this fork; acceptance of the two continuations is a
separate property, not asserted here. -/
theorem run_fork_at_prepared_query [DecidableEq T] (n : ℕ) (program : OracleComp T W α)
    (table : T → W) (input : T) (word : W) (next : W → OracleComp T W α)
    (hfresh : input ∉ (program.queries table).take n)
    (hprepared : (stopAfter n program).run table = .query input next) :
    program.run (Function.update table input word) = (next word).run (Function.update table input word) := by
  calc
    _ = ((stopAfter n program).run (Function.update table input word)).run
        (Function.update table input word) := (run_resume n program _).symm
    _ = (OracleComp.query input next).run (Function.update table input word) := by
      rw [stopAfter_update n program table input word hfresh, hprepared]
    _ = _ := by simp [run]

end Tachyon.Foundation.Oracle.OracleComp

namespace Tachyon.OraclePrefixes

open Foundation.Oracle Foundation.Oracle.OracleComp

variable {T V α K G : Type*} [DecidableEq T] [Field K] [AddCommGroup G] [Module K G]
  [DecidableEq K] [DecidableEq G] [Fintype V]

/-- Counting applies when the target set is actually computed from the
pre-query state. Replacing that state by an answer-dependent target would
invalidate this step; no such replacement is made. -/
theorem card_prepared_targets_le (n : ℕ) (program : OracleComp T V α) (table : T → V)
    (input : T) (prepare : OracleComp T V α → G × Finset G)
    (hfresh : input ∉ (program.queries table).take n)
    (embed : V → K) (hembed : Function.Injective embed) (base : G) (hbase : base ≠ 0) :
    (Finset.univ.filter fun word =>
      let prepared := prepare ((stopAfter n program).run (Function.update table input word))
      NonceChallengeBounds.randomizedKey embed base prepared.1 word ∈ prepared.2).card ≤
        (prepare ((stopAfter n program).run table)).2.card := by
  have hprepared : ∀ word,
      prepare ((stopAfter n program).run (Function.update table input word)) =
        prepare ((stopAfter n program).run table) :=
    fun word => prepared_update n program table input word prepare hfresh
  simp_rw [hprepared]
  exact NonceChallengeBounds.card_fixed_targets_le embed hembed base _ _ hbase

namespace Examples

def program : OracleComp ℕ Bool (Bool × Bool) := .query 0 (fun first => .query 1 (fun second => .pure (first, second)))
def table (input : ℕ) : Bool := decide (input = 0)

#guard program.run table == (true, false)
#guard ((stopAfter 1 program).run table).queries table == [1]
#guard program.run (Function.update table 1 true) == (true, true)
#guard (stopAfter 1 program).queries table == [0]

end Examples

end Tachyon.OraclePrefixes
