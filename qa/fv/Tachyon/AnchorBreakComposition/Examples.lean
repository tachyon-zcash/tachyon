import Tachyon.AnchorBreakComposition

/-! Classification regressions use finite computable data. The polynomial
adapter regressions are kernel-checked mathematical examples, not runtime tests. -/

namespace Tachyon.AnchorBreaks.CompositionExamples

open Polynomial SourceQueryBreaks

def collision : ScopedBreak constantModel [false, true] [] :=
  ⟨.commitment ⟨false, true, by decide, rfl⟩, ⟨by simp, by simp⟩⟩

-- Same Pedersen point: only the Pedersen branch is admissible.
#guard match collision.refineComposition (pc := fun _ => ()) (bridge := id)
    (by intro p _; rfl) with
  | .pedersen _ _ _ => true
  | _ => false

-- Distinct points, constant bridge: composite equality is NOT Pedersen equality.
#guard match collision.refineComposition (pc := id) (bridge := fun _ : Bool => ())
    (by intro p _; rfl) with
  | .bridge col _ _ _ => col.left == false && col.right == true
  | _ => false

#guard match (crossDomainBreak constantModel () () () () false rfl).refineComposition
    (pc := id) (bridge := fun _ : Bool => ()) (by intro p _; rfl) with
  | .hash _ _ => true
  | _ => false

example : (collision.refineComposition (pc := id) (bridge := fun _ : Bool => ())
    (by intro p _; rfl)).forget = collision := by simp

def model : Model ℚ[X] Unit Unit ℕ :=
  ⟨fun _ => (), fun _ _ _ => (), fun _ _ => (), (), 0⟩

noncomputable def polyCollision : CommitmentCollision model :=
  ⟨0, 1, zero_ne_one, rfl⟩

theorem bounded : ∀ p ∈ ([0, 1] : List ℚ[X]), p.natDegree < 1 := by
  intro p hp
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hp
  rcases hp with rfl | rfl <;> simp

noncomputable def pedersen : ScopedPrimitiveBreak model
    (polyCommit (fun _ : Fin 1 => (0 : ℚ))) (fun _ => ()) [0, 1] [] :=
  .pedersen polyCollision (by simp [polyCollision]) (by simp [polyCommit, commitGen])

-- Actual bounded polynomial equality enters the EXISTING adapter. Its returned
-- coefficients are the difference of the original openings, not a chosen relation.
example : (match pedersen.toPolyBreak bounded with
    | .pedersen w => w.collision.left = 0 ∧ w.collision.right = 1 ∧
        w.relation.coeffs 0 = -1
    | _ => False) := by
  change (0 : ℚ[X]) = 0 ∧ (1 : ℚ[X]) = 1 ∧ _
  refine ⟨rfl, rfl, ?_⟩
  norm_num [pedersen, ScopedPrimitiveBreak.toPolyBreak,
    NontrivialDLRelation.ofPolyCollision, NontrivialDLRelation.ofCollision, polyCollision]

noncomputable def bridged : ScopedPrimitiveBreak model
    (polyCommit (fun _ : Fin 1 => (1 : ℚ))) (fun _ => ()) [0, 1] [] :=
  .bridge polyCollision (by simp [polyCollision])
    (by simp [polyCollision, polyCommit, commitGen]) rfl

-- The distinct-Pedersen/equal-bridge branch stays a bridge witness, even though
-- both polynomials satisfy the rank bound. No DL relation is manufactured.
example : (match bridged.toPolyBreak bounded with
    | .bridge _ _ _ _ => True
    | _ => False) := by trivial

example : (pedersen.toPolyBreak bounded).forget = pedersen.forget := by simp
example : (bridged.toPolyBreak bounded).forget = bridged.forget := by simp

end Tachyon.AnchorBreaks.CompositionExamples
