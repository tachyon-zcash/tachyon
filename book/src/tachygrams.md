# Tachygrams

## What is a tachygram?

A tachygram is a deterministic field element ($\mathbb{F}_p$) derived from a note:

- **Spend**: nullifier $\mathsf{tg} = \mathsf{nf} = F_{\mathsf{nk}}(\Psi \| \text{flavor})$ (Poseidon GGM tree PRF, domain `Tachyon-NfDerive`)
- **Output**: commitment $\mathsf{tg} = \mathsf{cm} = \text{Poseidon}_\text{Tachyon-NoteCmmt}(\mathsf{rcm}, \mathsf{pk}, v, \Psi)$

The circuit computes both values with the constraint that a witness tachygram
matches one of them: $(\mathsf{tg} - \mathsf{nf})(\mathsf{tg} - \mathsf{cm}) = 0$.

Tachygrams are opaque to observers: you can't tell if any given tachygram is a
nullifier or a commitment.

## What is deterministic and what isn't

The key hierarchy splits into two independent branches from the spending key.
These branches share key material but no randomness.

- $sk \to nk$ (nullifier deriving key) - contributes to nullifiers
- $sk \to ask \to ak = [ask]G$ (spend auth key) - contributes to actions

Actions produce unpredictable $rk$ and $cv$ values:

- $rk = ak + [\alpha]G$ with fresh $\alpha$ randomizer per action
- $cv = [v]V + [rcv]R$ with fresh $rcv$ trapdoor per action

But nullifier inputs are fixed per note per epoch:

- $nk$ is constant
- $\psi$ is bound to the note
- $\text{flavor}$ is the epoch

A spend attempt in a given epoch produces one nullifier, reliably.

**So actions use fresh per-action randomness, but tachygrams are deterministic.**

**The proof is the link.** At proof creation time, each action is bound to its tachygram, but the PCD only exposes accumulated values.
An observer sees a bag of actions and a bag of tachygrams with no individual correspondences visible.

## Public Data

The proof's public output `StampDigest` carries three field elements:

| Field | Type | Elements | Description |
| ----- | ---- | -------- | ----------- |
| `action_acc` | $\mathbb{F}_p$ scalar | 1 | Multiplicative Poseidon accumulator over action digests |
| `tachygram_acc` | $\mathbb{F}_p$ scalar | 1 | Multiplicative Poseidon accumulator over tachygrams |
| `anchor` | $\mathbb{F}_p$ scalar | 1 | Accumulator state reference |

Both accumulators use multiplicative field-element accumulation.
Each element is hashed (Poseidon, domain-separated) and offset by $+1$ to guarantee nonzero output.
The accumulator is the product of all such values:

$$\mathsf{action\_acc} = \prod_i \bigl(\text{Poseidon}_\text{Tachyon-ActnDgst}(\mathsf{cv}_i \| \mathsf{rk}_i) + 1\bigr)$$

$$\mathsf{tachygram\_acc} = \prod_i \bigl(\text{Poseidon}_\text{Tachyon-TgrmDgst}(\mathsf{tg}_i) + 1\bigr)$$

Field multiplication is commutative, so PCD tree shape doesn't matter.

Multiplicative accumulation prevents the post-proof substitution attack: finding substitute values whose product matches the proven accumulator reduces to the discrete logarithm problem in the scalar field, maintaining 128-bit security regardless of the number of elements.

**This header is 'public' but not published.**
The stamp carries only tachygrams, anchor, and proof bytes.
**The header is recoverable if you have the correct set of tachygrams and the correct set of actions.**

The verifier reconstructs the full `StampDigest` following appropriate rules.
This way, the verifier knows a consensus-valid set of tachygrams was used in proof generation.

Each `ActionLeaf` seed computes one tachygram contribution; `StampMerge` multiplies
them together.
PCD soundness means the only way to produce a valid
proof is through `seed` + `fuse`, so an attacker cannot skip leaf circuits or
strip duplicate contributions between steps.

<!-- TODO
The number of tachygrams in a stamp can be greater than the number of actions.
This will require an additional leaf step that can accept the 'bonus' tachygram and provide it to the accumulator.
-->

## Verification

The verifier has: the public actions $(rk_i, cv_i, sig_i)$, the listed
tachygrams $tg_i$, the anchor, and the proof bytes.

1. **Anchor range**: check anchor is within valid epoch window
2. **No duplicate tachygrams**: check the tachygram list for repeats
3. **Action sigs**: verify each $sig_i$ against $rk_i$ (RedPallas)
4. **Binding sig**: verify against $\sum cv_i$
5. **Reconstruct header**: build `StampDigest { anchor, action_acc, tachygram_acc }`
   - **Recompute action_acc**: $\prod(\text{Poseidon}(\mathsf{cv}_i \| \mathsf{rk}_i) + 1)$ from visible actions
   - **Recompute tachygram_acc**: $\prod(\text{Poseidon}(\mathsf{tg}_i) + 1)$ from listed tachygrams
6. **Verify proof**: call Ragu `verify(Pcd { proof, data: header })`

<!-- TODO
Anchor range: Or check the block's epoch is within the anchor window?
-->

The verifier constructs the header from scratch.
If the proof was computed over different accumulators (e.g. from a double-spend), the reconstructed header won't match and verification fails.

## Overlapping aggregation

Can overlapping aggregates be merged? E.g., merge $\{a,b\}$ and $\{b,c\}$ to
produce $\{a,b,c\}$?

### 1. An overlapping merge is detectable

The multiplicative accumulator encodes multiplicity, committing to *how many times* each element appears.
In the formulas below, $H(x) = \text{Poseidon}(x) + 1$ denotes the nonzero hash used for accumulator elements (as described in [Verification](#verification) above).
When `StampMerge` multiplies two intersecting accumulators, the intersection is evident:

$$\text{merged} = H(a) \cdot H(b) \cdot H(b) \cdot H(c) \quad (b \text{ counted twice})$$

$$\text{clean} = H(a) \cdot H(b) \cdot H(c) \quad (b \text{ counted once})$$

These are different field elements (since $H(b)^2 \neq H(b)$ for nonzero, non-unity hash outputs).

### 2. Lying about an overlapping merge is not possible

An aggregator who merged overlapping stamps has exactly two options:

**Option A** — list tachygrams without duplicates $\{a, b, c\}$:

$$\text{reconstructed} = H(a) \cdot H(b) \cdot H(c)$$
$$\text{proof's actual} = H(a) \cdot H(b) \cdot H(b) \cdot H(c)$$

Proof doesn't verify against the reconstructed header.
Rejected.

**Option B** — list tachygrams with duplicates $\{a, b, b, c\}$:

$$\text{reconstructed} = H(a) \cdot H(b) \cdot H(b) \cdot H(c)$$
$$\text{proof's actual} = H(a) \cdot H(b) \cdot H(b) \cdot H(c)$$

Proof *would* verify, but consensus detects duplicate $b$, so the stamp was
already rejected.

### 3. There doesn't seem to be a path to support overlapping merges

Could consensus allow duplicate tachygrams to enable overlap?
No.
Overlap merge and a double-spend are **indistinguishable** from the protocol's perspective.

To achieve this, we'd have to relax the 'set' qualities of the tachygram vector on the stamp, to allow specifying and validating repeat accumulation.

Now consider some tachygram $tg$ appearing in stamp A and stamp B:

- **Scenario 1 (overlap):** Two aggregates independently included the same original stamp containing $tg$, and then merged again.
  Now $tg$ is accumulated twice.

- **Scenario 2 (double-spend):** A user creates two transactions spending the same note.
  Both transactions are balanced.
  Both produce nullifier $tg$ because tachygrams are deterministic.
  Both are then are merged to an aggregate.
  Now $tg$ is accumulated twice.
  
Observable data in both cases: you've got a stamps containing double-accumulation for tachygram $tg$, with some linked but unidentifiable actions in the adjuncts.
The proofs may be 'valid' in both cases, if you repeat accumulation of $tg$ when recreating your proof input.

The distinction is *intent*, but that intent isn't observable post-aggregation, because you can't correlate or identify the behavior of the actions.

<!-- TODO
An extraction circuit may be able to remove overlap before merging.
-->

### Implications

- **No in-circuit disjointness check needed.** The accumulator's binding property + data availability + duplicate detection is sufficient.
- **Data availability is a hard requirement.** Tachygrams must be listed in the block — without the list, the verifier can't reconstruct the header.
- **Mempool policy is not security.** Aggregators and miners may be adversarial.

  Only proof soundness + consensus rules (no duplicate tachygrams) provide guarantees.
