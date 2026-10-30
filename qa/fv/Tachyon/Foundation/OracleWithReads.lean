import Tachyon.Foundation.AdaptiveOracle
import Mathlib.Data.Fin.Tuple.Basic

/-!
# Complete output-dependent oracle reads

Ported and adapted from ragu `Foundation/Oracle/WithReads.lean` and the
sequencing/query-log lemmas in `Foundation/Oracle/OracleComp.lean`, local
`ea0bf839` checkout, themselves ported from ironwood `3c056cbe`.

Run the adversary, then query the finite family of hash inputs needed by the
output's verification. The result retains the exact table answers. This avoids
assuming that an adversary already queried a hash whose output it guessed.
The additional query budget is the family size, and every designated input
appears in the resulting log. Cache normalization can subsequently remove
repeats using `AdaptiveOracle`'s proved semantics.

This is a security-model wrapper, not a new protocol message. No probability
or concrete Poseidon pseudorandomness theorem is supplied here.
-/

namespace Tachyon.Foundation.Oracle.OracleComp

variable {T W α β : Type*}

theorem queryBound_bind {program : OracleComp T W α} {next : α → OracleComp T W β} {Q Q' : ℕ}
    (hprogram : QueryBound program Q) (hnext : ∀ value, QueryBound (next value) Q') :
    QueryBound (program.bind next) (Q + Q') := by
  induction hprogram with
  | pure value Q => exact (hnext value).mono (Nat.le_add_left _ _)
  | @query input continuation Q h ih =>
    change QueryBound (.query input (fun word => (continuation word).bind next)) (Q + 1 + Q')
    rw [Nat.succ_add]
    exact .query fun word => ih word

theorem queries_bind (program : OracleComp T W α) (next : α → OracleComp T W β) (table : T → W) :
    (program.bind next).queries table = program.queries table ++ (next (program.run table)).queries table := by
  induction program with
  | pure value => rfl
  | query input continuation ih => exact congrArg (List.cons input) (ih (table input))

def readFin : ∀ {n : ℕ}, (Fin n → T) → OracleComp T W (Fin n → W)
  | 0, _ => .pure Fin.elim0
  | _ + 1, points => .query (points 0) fun word =>
      (readFin fun i => points i.succ).bind fun words => .pure (Fin.cons word words)

theorem run_readFin : ∀ {n : ℕ} (points : Fin n → T) (table : T → W),
    (readFin (W := W) points).run table = fun i => table (points i)
  | 0, _, _ => funext fun i => i.elim0
  | n + 1, points, table => by
    simp only [readFin, run, run_bind, run_readFin (fun i => points i.succ) table]
    funext i
    refine Fin.cases ?_ (fun j => ?_) i
    · rw [Fin.cons_zero]
    · rw [Fin.cons_succ]

theorem queries_readFin : ∀ {n : ℕ} (points : Fin n → T) (table : T → W),
    (readFin (W := W) points).queries table = List.ofFn points
  | 0, _, _ => rfl
  | n + 1, points, table => by
    simp only [readFin, queries, queries_bind, queries_readFin, List.append_nil]
    rw [List.ofFn_succ]

theorem queryBound_readFin : ∀ {n : ℕ} (points : Fin n → T), QueryBound (readFin (W := W) points) n
  | 0, _ => .pure _ _
  | n + 1, points => by
    have hnext : ∀ word : W,
        ((readFin fun i : Fin n => points i.succ).bind fun words =>
          (.pure (Fin.cons word words) : OracleComp T W (Fin (n + 1) → W))).QueryBound n := by
      intro word
      exact queryBound_bind (queryBound_readFin fun i : Fin n => points i.succ)
        (fun words => QueryBound.pure _ 0)
    exact QueryBound.query hnext

def withReads {n : ℕ} (points : α → Fin n → T) (program : OracleComp T W α) :
    OracleComp T W (α × (Fin n → W)) :=
  program.bind fun output => (readFin (points output)).bind fun words => .pure (output, words)

theorem run_withReads {n : ℕ} (points : α → Fin n → T) (program : OracleComp T W α) (table : T → W) :
    (withReads points program).run table = (program.run table, fun i => table (points (program.run table) i)) := by
  rw [withReads, run_bind, run_bind, run_readFin, run]

theorem queries_withReads {n : ℕ} (points : α → Fin n → T) (program : OracleComp T W α) (table : T → W) :
    (withReads points program).queries table = program.queries table ++ List.ofFn (points (program.run table)) := by
  simp only [withReads, queries_bind, queries_readFin, queries, List.append_nil]

theorem queryBound_withReads {n : ℕ} (points : α → Fin n → T) {program : OracleComp T W α} {Q : ℕ}
    (hprogram : QueryBound program Q) : QueryBound (withReads points program) (Q + n) := by
  apply queryBound_bind hprogram
  intro output
  simpa only [Nat.add_zero] using queryBound_bind (queryBound_readFin (W := W) (points output))
    (fun words => QueryBound.pure (output, words) 0)

theorem designated_mem_queries {n : ℕ} (points : α → Fin n → T) (program : OracleComp T W α)
    (table : T → W) (i : Fin n) : points (program.run table) i ∈ (withReads points program).queries table := by
  rw [queries_withReads]
  exact List.mem_append_right _ (List.mem_ofFn.mpr ⟨i, rfl⟩)

namespace ReadExamples

def guess : OracleComp ℕ Bool ℕ := .pure 7
def points (output : ℕ) (i : Fin 2) : ℕ := output + i.val
def table (input : ℕ) : Bool := decide (input = 7)

#guard (withReads points guess).queries table == [7, 8]
#guard ((withReads points guess).run table).1 == 7
#guard ((withReads points guess).run table).2 0
#guard !((withReads points guess).run table).2 1

end ReadExamples

end Tachyon.Foundation.Oracle.OracleComp
