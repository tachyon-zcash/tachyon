import Lean.Util.CollectAxioms
import Lean.Elab.Command

/-!
# Axiom budget

`#check_axiom_budget n₁ … nₖ` checks every declaration of every imported `Tachyon` module:

* it declares no axiom;
* it depends on no axiom other than `propext`, `Classical.choice` and `Quot.sound`, which rules out
  `sorryAx` and `Lean.ofReduceBool` (`native_decide`);
* each of `n₁ … nₖ` was among the declarations checked, so the module filter is not empty;
* the imported `Tachyon` modules are the `.lean` files under `Tachyon/` together with `Tachyon`,
  less the module running the check, so a file the root module doesn't import is reported.

It follows ragu's `Ragu.Meta.EndpointCensus` and its axiom check (ragu `origin/main` 5d225645), but
tachyon's budget is Lean's standard three for every declaration, and tachyon has no executables
and no `native_decide`. So it checks every declaration instead of discovering endpoints by name, and
it doesn't import CompElliptic's checker. Like ragu's, it guards against drift, not against a
metaprogram written to deceive it.
-/

namespace Tachyon.Meta

open Lean Elab Command

/-- The axioms a `Tachyon` declaration may depend on. -/
def allowedAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

/-- The module names of the `.lean` files under `dir`, prefixed by `pre`. -/
partial def moduleNamesUnder (dir : System.FilePath) (pre : Name) : IO (Array Name) := do
  let mut names := #[]
  for entry in ← dir.readDir do
    if ← entry.path.isDir then
      names := names ++ (← moduleNamesUnder entry.path (pre.str entry.fileName))
    else if entry.path.extension == some "lean" then
      if let some stem := entry.path.fileStem then
        names := names.push (pre.str stem)
  return names

syntax (name := checkAxiomBudget) "#check_axiom_budget" (ppSpace ident)* : command

@[command_elab checkAxiomBudget]
def elabCheckAxiomBudget : CommandElab := fun stx => do
  let pins := stx[1].getArgs.map (·.getId)
  let env ← getEnv
  let mut checked : NameSet := {}
  let mut modules : NameSet := {}
  for modName in env.header.moduleNames, modData in env.header.moduleData do
    unless (`Tachyon).isPrefixOf modName do continue
    modules := modules.insert modName
    for name in modData.constNames do
      checked := checked.insert name
      if let some (.axiomInfo _) := env.find? name then
        throwError "{name} is an axiom"
      for ax in ← collectAxioms name do
        unless allowedAxioms.contains ax do
          throwError "{name} depends on {ax}"
  for pin in pins do
    unless checked.contains pin do
      throwError "{pin} is not a declaration of an imported Tachyon module"
  let files := (← moduleNamesUnder "Tachyon" `Tachyon).push `Tachyon
  for file in files do
    unless file == env.mainModule || modules.contains file do
      throwError "{file} is not imported"
  for modName in modules do
    unless files.contains modName do
      throwError "{modName} has no file under Tachyon/"

end Tachyon.Meta
