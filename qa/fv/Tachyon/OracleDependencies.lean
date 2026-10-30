import Tachyon.OracleHistoryTargets

/-!
# A recorded hash dependency is causal or predicts a fresh answer

If a consumer's input carries a producer's answer, and their inputs are
distinct, then the producer query came first or that answer was already
guessed in an earlier input. The latter branch returns the actual fresh
query position and membership in a prefix-determined set of guesses.

This is a deterministic reduction over recorded observations, not a
probability bound. Freshness follows from normalization, rather than an
assumption that a malicious prover follows a preferred query order.

The caller still supplies the producer/consumer positions, their distinct
inputs, and the projection exposing the dependency. Applying this to actual
spend frames requires the protocol's typed input encodings and verifier-read
membership proofs. No concrete Poseidon or full H5 claim is made here.
-/

namespace Tachyon.OracleDependencies

open Foundation.Oracle Foundation.Oracle.OracleComp

variable {T V : Type*}

theorem row_mem_take (history : List (T × V)) (i : Fin history.length)
    (n : ℕ) (hi : i.val < n) : history[i.val] ∈ history.take n := by
  rw [List.getElem_take' i.isLt hi]
  exact List.getElem_mem (by simp only [List.length_take]; omega)

/-- Every position in an input-normalized history is a genuinely fresh query. -/
theorem input_fresh (history : List (T × V)) (hnodup : (history.map Prod.fst).Nodup)
    (i : Fin history.length) : history[i.val].1 ∉ (history.take i.val).map Prod.fst := by
  intro hmem
  obtain ⟨j, hj, heq⟩ := List.mem_iff_getElem.mp hmem
  have hjlt : j < i.val := by
    simp only [List.length_map, List.length_take] at hj
    omega
  have hjfull : j < (history.map Prod.fst).length := by
    simp only [List.length_map]
    exact hjlt.trans i.isLt
  have hifull : i.val < (history.map Prod.fst).length := by
    simpa only [List.length_map] using i.isLt
  have heq' : (history.map Prod.fst)[j] = (history.map Prod.fst)[i.val] := by
    simpa only [List.getElem_map, List.getElem_take] using heq
  have hij := hnodup.getElem_inj_iff.mp heq'
  omega

variable [DecidableEq V]

/-- A concrete bad-event witness: the answer to this fresh query was guessed
in an earlier input. The set is parsed from prior inputs, not prior answers. -/
structure PredictionHit (project : T → Option V) (history : List (T × V)) where
  position : Fin history.length
  fresh : history[position.val].1 ∉ (history.take position.val).map Prod.fst
  hit : history[position.val].2 ∈ PairingTargets.keys project (history.take position.val)

/-- This reducer inspects query positions; it does not extract witnesses
from a proposition asserting their existence. Distinct inputs exclude the
same-position case, e.g. for domain-separated note and nonce inputs. -/
def dependencyOrPrediction (project : T → Option V) (history : List (T × V))
    (hnodup : (history.map Prod.fst).Nodup) (producer consumer : Fin history.length)
    (hdistinct : history[producer.val].1 ≠ history[consumer.val].1)
    (hdependency : project history[consumer.val].1 = some history[producer.val].2) :
    (producer.val < consumer.val) ⊕' PredictionHit project history :=
  if hbefore : producer.val < consumer.val then .inl hbefore
  else
    have hne : producer.val ≠ consumer.val := by
      intro heq
      apply hdistinct
      simp only [heq]
    have hafter : consumer.val < producer.val := by omega
    .inr ⟨producer, input_fresh history hnodup producer,
      (PairingTargets.mem_keys_iff project _ _).mpr
        ⟨history[consumer.val], row_mem_take history consumer producer.val hafter, hdependency⟩⟩

theorem prediction_targets_card_le (project : T → Option V) (history : List (T × V))
    (i : Fin history.length) :
    (PairingTargets.keys project (history.take i.val)).card ≤ i.val :=
  (PairingTargets.keys_card_le project _).trans (by simp only [List.length_take]; omega)

/-- Replacing the fresh answer cannot change the guess set. In particular,
the bad-event target is not chosen using that answer. -/
theorem prefix_prediction_targets_update {α : Type*} [DecidableEq T]
    (project : T → Option V) (n : ℕ) (program : OracleComp T V α)
    (table : T → V) (input : T) (word : V)
    (hfresh : input ∉ (program.queries table).take n) :
    PairingTargets.keys project (before n program (Function.update table input word)) =
      PairingTargets.keys project (before n program table) :=
  congrArg (PairingTargets.keys project) (before_update n program table input word hfresh)

theorem prefix_prediction_targets_card_le {α : Type*}
    (project : T → Option V) (n : ℕ) (program : OracleComp T V α) (table : T → V) :
    (PairingTargets.keys project (before n program table)).card ≤ n :=
  (PairingTargets.keys_card_le project _).trans (before_length_le n program table)

omit [DecidableEq V] in
/-- Actual observations are consistent with the supplied table, so a
prediction witness refers to an actual oracle answer. -/
theorem observations_consistent {α : Type*} (program : OracleComp T V α)
    (table : T → V) (row : T × V) (hrow : row ∈ program.observations table) :
    table row.1 = row.2 := by
  obtain ⟨input, _, heq⟩ := List.mem_map.mp hrow
  cases heq
  rfl

omit [DecidableEq V] in
theorem normalized_inputs_nodup {α : Type*} [DecidableEq T]
    (program : OracleComp T V α) (table : T → V) :
    (((dedup [] program).observations table).map Prod.fst).Nodup := by
  simpa [observations, List.map_map, Function.comp_def] using
    dedup_queries_nodup [] program table

omit [DecidableEq V] in
theorem observations_take {α : Type*} (n : ℕ) (program : OracleComp T V α)
    (table : T → V) : (program.observations table).take n = before n program table := by
  simp only [observations, before, queries_stopAfter, List.map_take]

/-- Direct use on a normalized execution discharges the freshness
obligation for either producer/consumer order. -/
def normalizedDependencyOrPrediction {α : Type*} [DecidableEq T]
    (project : T → Option V) (program : OracleComp T V α) (table : T → V)
    (producer consumer : Fin ((dedup [] program).observations table).length)
    (hdistinct : ((dedup [] program).observations table)[producer.val].1 ≠
      ((dedup [] program).observations table)[consumer.val].1)
    (hdependency : project ((dedup [] program).observations table)[consumer.val].1 =
      some ((dedup [] program).observations table)[producer.val].2) :
    (producer.val < consumer.val) ⊕' PredictionHit project ((dedup [] program).observations table) :=
  dependencyOrPrediction project _ (normalized_inputs_nodup program table)
    producer consumer hdistinct hdependency

theorem PredictionHit.actual_answer {α : Type*} (program : OracleComp T V α)
    (table : T → V) (project : T → Option V)
    (witness : PredictionHit project (program.observations table)) :
    table (program.observations table)[witness.position.val].1 ∈
      PairingTargets.keys project ((program.observations table).take witness.position.val) := by
  rw [observations_consistent program table _ (List.getElem_mem witness.position.isLt)]
  exact witness.hit

theorem PredictionHit.prefix_update {α : Type*} [DecidableEq T]
    (program : OracleComp T V α) (table : T → V) (project : T → Option V)
    (witness : PredictionHit project (program.observations table)) (word : V) :
    PairingTargets.keys project (before witness.position.val program
      (Function.update table (program.observations table)[witness.position.val].1 word)) =
      PairingTargets.keys project ((program.observations table).take witness.position.val) := by
  rw [observations_take]
  apply prefix_prediction_targets_update
  simpa [observations, ← List.map_take, List.map_map, Function.comp_def] using witness.fresh

/-- Two successive dependencies, such as payment hash → note hash → nonce,
either put the first producer before the final consumer or identify which
dependency predicted a fresh answer. The actual protocol projections remain
caller inputs. -/
def chainOrPrediction (firstProject secondProject : T → Option V) (history : List (T × V))
    (hnodup : (history.map Prod.fst).Nodup) (first middle last : Fin history.length)
    (hfirstDistinct : history[first.val].1 ≠ history[middle.val].1)
    (hsecondDistinct : history[middle.val].1 ≠ history[last.val].1)
    (hfirst : firstProject history[middle.val].1 = some history[first.val].2)
    (hsecond : secondProject history[last.val].1 = some history[middle.val].2) :
    (first.val < last.val) ⊕' (PredictionHit firstProject history ⊕' PredictionHit secondProject history) :=
  match dependencyOrPrediction firstProject history hnodup first middle hfirstDistinct hfirst with
  | .inr witness => .inr (.inl witness)
  | .inl hbefore =>
    match dependencyOrPrediction secondProject history hnodup middle last hsecondDistinct hsecond with
    | .inr witness => .inr (.inr witness)
    | .inl hafter => .inl (hbefore.trans hafter)

namespace Examples

abbrev Input := Bool × Bool

def project (input : Input) : Option Bool := if input.1 then some input.2 else none
def table (input : Input) : Bool := !input.1
def causal : OracleComp Input Bool Unit :=
  .query (false, false) (fun word => .query (true, word) (fun _ => .pure ()))
def predicted : OracleComp Input Bool Unit :=
  .query (true, true) (fun _ => .query (false, false) (fun _ => .pure ()))
def repeated : OracleComp Input Bool Unit :=
  .query (true, true) (fun _ => predicted)

def causalResult := normalizedDependencyOrPrediction project causal table
  ⟨0, by decide⟩ ⟨1, by decide⟩ (by decide) (by decide)
def predictedResult := normalizedDependencyOrPrediction project predicted table
  ⟨1, by decide⟩ ⟨0, by decide⟩ (by decide) (by decide)
def repeatedResult := normalizedDependencyOrPrediction project repeated table
  ⟨1, by decide⟩ ⟨0, by decide⟩ (by decide) (by decide)

#guard match causalResult with | .inl _ => true | .inr _ => false
#guard match predictedResult with | .inl _ => false | .inr hit => hit.position.val == 1
#guard match repeatedResult with | .inl _ => false | .inr hit => hit.position.val == 1
#guard repeated.queries table == [(true, true), (true, true), (false, false)]
#guard (dedup [] repeated).queries table == [(true, true), (false, false)]
#guard decide (PairingTargets.keys project (before 1 predicted table) = {true})
#guard PairingTargets.keys project (before 1 predicted (Function.update table (false, false) false)) ==
  PairingTargets.keys project (before 1 predicted table)

def firstProject (input : ℕ) : Option Bool := if input = 1 then some true else none
def secondProject (input : ℕ) : Option Bool := if input = 2 then some false else none
def chainHistory (inputs : List ℕ) : List (ℕ × Bool) :=
  inputs.map fun input => (input, decide (input = 0))

def orderedChain := chainOrPrediction firstProject secondProject (chainHistory [0, 1, 2])
  (by decide) ⟨0, by decide⟩ ⟨1, by decide⟩ ⟨2, by decide⟩
  (by decide) (by decide) (by decide) (by decide)
def firstPredictedChain := chainOrPrediction firstProject secondProject (chainHistory [1, 0, 2])
  (by decide) ⟨1, by decide⟩ ⟨0, by decide⟩ ⟨2, by decide⟩
  (by decide) (by decide) (by decide) (by decide)
def secondPredictedChain := chainOrPrediction firstProject secondProject (chainHistory [0, 2, 1])
  (by decide) ⟨0, by decide⟩ ⟨2, by decide⟩ ⟨1, by decide⟩
  (by decide) (by decide) (by decide) (by decide)

#guard match orderedChain with | .inl _ => true | .inr _ => false
#guard match firstPredictedChain with
  | .inr (.inl hit) => hit.position.val == 1
  | _ => false
#guard match secondPredictedChain with
  | .inr (.inr hit) => hit.position.val == 2
  | _ => false

end Examples

end Tachyon.OracleDependencies
