import Tachyon.Foundation.OracleWithReads
import Tachyon.OracleHistoryTargets

/-!
# Locating verifier reads after cache normalization

Cache normalization preserves the membership of every designated verifier
input. An executable first-index lookup then locates its actual observation;
no data witness is extracted from an existential proposition.
-/

namespace Tachyon.Foundation.Oracle.OracleComp

variable {T V α : Type*} [DecidableEq T]

theorem mem_queries_dedup_or_cache (program : OracleComp T V α) (table : T → V)
    (cache : List (T × V)) (hconsistent : ∀ row ∈ cache, table row.1 = row.2)
    (input : T) (hinput : input ∈ program.queries table) :
    input ∈ (dedup cache program).queries table ∨ input ∈ cache.map Prod.fst := by
  induction program generalizing cache with
  | pure value => cases hinput
  | query current next ih =>
    rw [dedup]
    cases hfind : cache.find? (fun row => row.1 = current) with
    | some row =>
      have hrow := List.mem_of_find?_eq_some hfind
      have hcurrent : row.1 = current := by simpa using List.find?_some hfind
      have hword : table current = row.2 := hcurrent ▸ hconsistent row hrow
      rcases List.mem_cons.mp hinput with rfl | htail
      · exact .inr (List.mem_map.mpr ⟨row, hrow, hcurrent⟩)
      · change input ∈ (dedup cache (next row.2)).queries table ∨ input ∈ cache.map Prod.fst
        rw [← hword]
        exact ih (table current) cache hconsistent htail
    | none =>
      rcases List.mem_cons.mp hinput with rfl | htail
      · exact .inl List.mem_cons_self
      · have hnew : ∀ row ∈ (current, table current) :: cache, table row.1 = row.2 := by
          intro row hrow
          rcases List.mem_cons.mp hrow with rfl | hrow
          · rfl
          · exact hconsistent row hrow
        rcases ih (table current) ((current, table current) :: cache) hnew htail with hnorm | hcache
        · exact .inl (List.mem_cons_of_mem current hnorm)
        · rcases List.mem_cons.mp hcache with rfl | hcache
          · exact .inl List.mem_cons_self
          · exact .inr hcache

theorem mem_queries_dedup (program : OracleComp T V α) (table : T → V)
    (input : T) (hinput : input ∈ program.queries table) :
    input ∈ (dedup [] program).queries table := by
  rcases mem_queries_dedup_or_cache program table [] (by simp) input hinput with h | h
  · exact h
  · cases h

theorem designated_mem_normalized {n : ℕ} (points : α → Fin n → T)
    (program : OracleComp T V α) (table : T → V) (i : Fin n) :
    points (program.run table) i ∈ (dedup [] (withReads points program)).queries table :=
  mem_queries_dedup _ table _ (designated_mem_queries points program table i)

def observationIndex (history : List (T × V)) (input : T)
    (hmem : input ∈ history.map Prod.fst) : Fin history.length :=
  ⟨(history.map Prod.fst).idxOf input, by
    simpa only [List.length_map] using List.idxOf_lt_length_iff.mpr hmem⟩

theorem observationIndex_input (history : List (T × V)) (input : T)
    (hmem : input ∈ history.map Prod.fst) :
    history[(observationIndex history input hmem).val].1 = input := by
  simpa only [observationIndex, List.getElem_map] using
    List.getElem_idxOf (List.idxOf_lt_length_iff.mpr hmem)

def designatedIndex {n : ℕ} (points : α → Fin n → T)
    (program : OracleComp T V α) (table : T → V) (i : Fin n) :
    Fin ((dedup [] (withReads points program)).observations table).length :=
  observationIndex _ (points (program.run table) i) (by
    simpa [observations, List.map_map, Function.comp_def] using
      designated_mem_normalized points program table i)

theorem designatedIndex_input {n : ℕ} (points : α → Fin n → T)
    (program : OracleComp T V α) (table : T → V) (i : Fin n) :
    ((dedup [] (withReads points program)).observations table)[(designatedIndex points program table i).val].1 =
      points (program.run table) i :=
  observationIndex_input _ _ _

namespace LocationExamples

def program : OracleComp ℕ Bool ℕ := .query 7 (fun _ => .pure 7)
def points (output : ℕ) (i : Fin 2) : ℕ := output + i.val
def table (input : ℕ) : Bool := decide (input = 7)

#guard (withReads points program).queries table == [7, 7, 8]
#guard (dedup [] (withReads points program)).queries table == [7, 8]
#guard (designatedIndex points program table 0).val == 0
#guard (designatedIndex points program table 1).val == 1

end LocationExamples

end Tachyon.Foundation.Oracle.OracleComp
