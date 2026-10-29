import Mathlib.Data.List.Basic
import Aesop

/-!
# Evidence-tree replay returns certified leaf data or a concrete hash collision

This models the integrity argument behind `EvidenceTreeDescend` and
`EvidenceTreeOpen` (`stamp/proof/evidence.rs`). The tree and opening path are
data, and `replayOrCollision` computes a leaf certificate or distinct tagged
hash inputs with equal outputs. No global hash injectivity is assumed.

`B` is the encoded public bucket preimage, including its profile and network
fields; it must not contain ignored metadata. Relating this encoded schema to
the actual Poseidon circuit is an implementation/canonical-encoding boundary.
Private provenance is carried in `Leaf b`, not hashed as part of `b`.

The tree uses a quaternary constructor directly rather than modelling the
two binary PCD assembly steps separately: this is a structural over-approximation
for the replay claim, since every assembled node already has four certified
subtrees. Network-field checks may further restrict those trees; no replay can
invent a leaf even in this larger tree set. These deliberate abstraction
choices avoid duplicating assembly steps unrelated to the integrity reduction.
Fixed batches of descent levels compose by concatenating path steps.
-/

namespace Tachyon.EvidenceReplay

universe u v w

inductive Side | first | second | third | fourth deriving DecidableEq

structure Quad (D : Type v) where
  first : D
  second : D
  third : D
  fourth : D
  deriving DecidableEq

def Quad.get {D : Type v} (q : Quad D) : Side → D
  | .first => q.first
  | .second => q.second
  | .third => q.third
  | .fourth => q.fourth

inductive Input (B : Type u) (D : Type v)
  | leaf (bucket : B)
  | node (children : Quad D)
  deriving DecidableEq

structure Model (B : Type u) (D : Type v) where
  leafHash : B → D
  nodeHash : Quad D → D

def Model.eval {B : Type u} {D : Type v} (m : Model B D) : Input B D → D
  | .leaf b => m.leafHash b
  | .node children => m.nodeHash children

variable {B : Type u} {D : Type v} {Leaf : B → Type w}

structure Collision (m : Model B D) (inputs : List (Input B D)) where
  left : Input B D
  right : Input B D
  left_mem : left ∈ inputs
  right_mem : right ∈ inputs
  distinct : left ≠ right
  equal : m.eval left = m.eval right

def Collision.weaken {m : Model B D} {xs ys : List (Input B D)} (w : Collision m xs)
    (h : xs ⊆ ys) : Collision m ys :=
  ⟨w.left, w.right, h w.left_mem, h w.right_mem, w.distinct, w.equal⟩

def NoCollisionsOn (m : Model B D) (inputs : List (Input B D)) : Prop :=
  ∀ x ∈ inputs, ∀ y ∈ inputs, m.eval x = m.eval y → x = y

def Collision.elim {m : Model B D} {xs : List (Input B D)} (w : Collision m xs)
    (h : NoCollisionsOn m xs) : False := w.distinct (h _ w.left_mem _ w.right_mem w.equal)

/-- The positive leaf certificates are retained as data through node assembly
and caps (a cap is just a node containing four copies of the same subtree). -/
inductive Tree (m : Model B D) (Leaf : B → Type w) : D → Type (max u v w)
  | leaf (b : B) (certificate : Leaf b) : Tree m Leaf (m.leafHash b)
  | node {a b c d : D} (first : Tree m Leaf a) (second : Tree m Leaf b)
      (third : Tree m Leaf c) (fourth : Tree m Leaf d) :
      Tree m Leaf (m.nodeHash ⟨a, b, c, d⟩)

def Tree.inputs {m : Model B D} {root : D} : Tree m Leaf root → List (Input B D)
  | .leaf b _ => [.leaf b]
  | .node (a := a) (b := b) (c := c) (d := d) first second third fourth =>
      .node ⟨a, b, c, d⟩ :: (first.inputs ++ second.inputs ++ third.inputs ++ fourth.inputs)

def child {m : Model B D} {a b c d : D}
    (first : Tree m Leaf a) (second : Tree m Leaf b) (third : Tree m Leaf c)
    (fourth : Tree m Leaf d) : (s : Side) → Tree m Leaf ((Quad.mk a b c d).get s)
  | .first => first
  | .second => second
  | .third => third
  | .fourth => fourth

theorem child_inputs_subset {m : Model B D} {a b c d : D}
    (first : Tree m Leaf a) (second : Tree m Leaf b) (third : Tree m Leaf c)
    (fourth : Tree m Leaf d) (s : Side) :
    (child first second third fourth s).inputs ⊆ (Tree.node first second third fourth).inputs := by
  intro x hx
  cases s <;> simp_all [child, Tree.inputs] <;> aesop

/-- Each path node records the actual child-digest witness and checked hash
equation from one descent level. `stop` may occur at any depth. -/
inductive Path (m : Model B D) : D → D → Type v
  | stop (root : D) : Path m root root
  | step {root target : D} (children : Quad D) (side : Side)
      (check : m.nodeHash children = root) (rest : Path m (children.get side) target) :
      Path m root target

def Path.inputs {m : Model B D} {root target : D} : Path m root target → List (Input B D)
  | .stop _ => []
  | .step children _ _ rest => .node children :: rest.inputs

def Path.length {m : Model B D} {root target : D} : Path m root target → ℕ
  | .stop _ => 0
  | .step _ _ _ rest => rest.length + 1

variable [DecidableEq B] [DecidableEq D]

/-- A replay either returns the actual leaf provenance or computes a scoped
hash collision. Stopping at an inner node yields a cross-domain collision. -/
def replayOrCollisionAux (m : Model B D) {root target : D} (tree : Tree m Leaf root)
    (path : Path m root target) (claimed : B) (hopen : m.leafHash claimed = target)
    (fuel : ℕ) (hFuel : path.length ≤ fuel) :
    Leaf claimed ⊕' Collision m (tree.inputs ++ path.inputs ++ [.leaf claimed]) := by
  cases path with
  | stop =>
    cases tree with
    | leaf b certificate =>
      by_cases h : claimed = b
      · cases h
        exact .inl certificate
      · exact .inr ⟨.leaf claimed, .leaf b, by simp, by simp [Tree.inputs],
          (fun heq => h (Input.leaf.inj heq)), hopen⟩
    | node first second third fourth =>
      exact .inr ⟨.leaf claimed, .node _, by simp, by simp [Tree.inputs],
        (by intro h; cases h), hopen⟩
  | step children side check rest =>
    cases fuel with
    | zero => exact False.elim (Nat.not_succ_le_zero _ hFuel)
    | succ fuel =>
      cases tree with
      | leaf b _ =>
        exact .inr ⟨.node children, .leaf b, by simp [Path.inputs], by simp [Tree.inputs],
          (by intro h; cases h), check⟩
      | node first second third fourth =>
        rename_i a b c d
        by_cases h : children = Quad.mk a b c d
        · cases h
          cases replayOrCollisionAux m (child first second third fourth side) rest claimed hopen fuel
              (Nat.le_of_succ_le_succ hFuel) with
          | inl result => exact .inl result
          | inr witness =>
            apply PSum.inr
            apply witness.weaken
            intro x hx
            simp only [List.mem_append, List.mem_singleton] at hx
            rcases hx with (hx | hx) | hx
            · exact List.mem_append_left _ (List.mem_append_left _
                (child_inputs_subset first second third fourth side hx))
            · simp [Path.inputs, hx]
            · simp [hx]
        · exact .inr ⟨.node children, .node _, by simp [Path.inputs], by simp [Tree.inputs],
            (fun heq => h (Input.node.inj heq)), check⟩
termination_by fuel
decreasing_by omega

-- Explicit fuel supplies a well-founded measure despite dependent root-index
-- transports after comparing child vectors. The wrapper supplies the exact path
-- length, so this is not an additional caller assumption or rejection case.
def replayOrCollision (m : Model B D) {root target : D} (tree : Tree m Leaf root)
    (path : Path m root target) (claimed : B) (hopen : m.leafHash claimed = target) :
    Leaf claimed ⊕' Collision m (tree.inputs ++ path.inputs ++ [.leaf claimed]) :=
  replayOrCollisionAux m tree path claimed hopen path.length (Nat.le_refl _)

/-- The conditional replay theorem is scoped to the supplied tree, path and
claimed leaf, never to the hash's entire finite domain. -/
def replayOfNoCollisions (m : Model B D) {root target : D} (tree : Tree m Leaf root)
    (path : Path m root target) (claimed : B) (hopen : m.leafHash claimed = target)
    (hlocal : NoCollisionsOn m (tree.inputs ++ path.inputs ++ [.leaf claimed])) : Leaf claimed :=
  match replayOrCollision m tree path claimed hopen with
  | .inl certificate => certificate
  | .inr witness => False.elim (witness.elim hlocal)

namespace Examples

def model : Model Bool Unit := ⟨fun _ => (), fun _ => ()⟩
def ExampleLeaf (b : Bool) := {value : Bool // value = b}
def leaf : Tree model ExampleLeaf () := .leaf false ⟨false, rfl⟩
def capped : Tree model ExampleLeaf () := .node leaf leaf leaf leaf
def path : Path model () () := .step ⟨(), (), (), ()⟩ .third rfl (.stop ())

#guard match replayOrCollision model capped path false rfl with
  | .inl certificate => certificate.val == false
  | .inr _ => false

#guard match replayOrCollision model capped path true rfl with
  | .inl _ => false
  | .inr witness => match witness.left, witness.right with
    | .leaf true, .leaf false => true
    | _, _ => false

#guard match replayOrCollision model capped (.stop ()) false rfl with
  | .inl _ => false
  | .inr witness => match witness.left, witness.right with
    | .leaf _, .node _ => true
    | _, _ => false

#guard match replayOrCollision model leaf path false rfl with
  | .inl _ => false
  | .inr witness => match witness.left, witness.right with
    | .node _, .leaf _ => true
    | _, _ => false

def nodeCollisions : Model Bool Bool := ⟨id, fun _ => false⟩
def falseLeaf : Tree nodeCollisions ExampleLeaf false := .leaf false ⟨false, rfl⟩
def falseNode : Tree nodeCollisions ExampleLeaf false := .node falseLeaf falseLeaf falseLeaf falseLeaf
def wrongChildren : Path nodeCollisions false true :=
  .step ⟨true, true, true, true⟩ .first rfl (.stop true)

#guard match replayOrCollision nodeCollisions falseNode wrongChildren true rfl with
  | .inl _ => false
  | .inr witness => match witness.left, witness.right with
    | .node _, .node _ => true
    | _, _ => false

end Examples

end Tachyon.EvidenceReplay
