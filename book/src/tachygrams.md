# Tachygrams

## What is a tachygram?

A tachygram is a deterministic field element ($\mathbb{F}_p$) derived from a note:

- **Spend**: nullifier $\mathsf{tg} = \mathsf{nf} = F_{\mathsf{mk}}(\text{flavor})$ where $\mathsf{mk} = \text{Poseidon}_\text{Tachyon-MkDerive}(\Psi, \mathsf{nk})$ (GGM tree PRF, domain `Tachyon-NfDerive`)
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

The PCD header carries two polynomial commitments and an anchor:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `action_acc` | EC point (Pallas) | Pedersen vector commitment to the action accumulator polynomial |
| `tachygram_acc` | EC point (Pallas) | Pedersen vector commitment to the tachygram accumulator polynomial |
| `anchor` | `Anchor` | pool state commitment at a specific block |

Both accumulators use polynomial commitments.
For actions, each element is hashed (Poseidon, domain `Tachyon-ActnDgst`) into a root $r_i \in \mathbb{F}_p$.
For tachygrams, the tachygram field element is used directly as the root.
Each accumulator polynomial is the product of linear factors:

$$\mathsf{action\_poly}(X) = \prod_i \bigl(X - \text{Poseidon}_\text{Tachyon-ActnDgst}(\mathsf{cv}_i \| \mathsf{rk}_i)\bigr)$$

$$\mathsf{tachygram\_poly}(X) = \prod_i \bigl(X - \mathsf{tg}_i\bigr)$$

The header values are Pedersen vector commitments to the coefficients:
$\mathsf{action\_acc} = \text{Commit}(\mathsf{action\_poly})$,
$\mathsf{tachygram\_acc} = \text{Commit}(\mathsf{tachygram\_poly})$.

Polynomial coefficients are canonical (independent of root ordering), so PCD tree shape doesn't matter.

Polynomial commitment prevents the post-proof substitution attack: finding a substitute set of roots whose committed polynomial matches the proven commitment reduces to the discrete logarithm problem on the elliptic curve, maintaining 128-bit security regardless of the number of elements.

**This header is 'public' but not published.**
The stamp carries only tachygrams, anchor, and proof bytes.
**The header is recoverable if you have the correct set of tachygrams and the correct set of actions.**

The verifier reconstructs the full header following appropriate rules.
This way, the verifier knows a consensus-valid set of tachygrams was used in proof generation.

Each leaf step (`OutputStamp`, `SpendStamp`) creates a 1-member tachygram set;
`MergeStamp` combines the sets. PCD soundness means the only way to produce a
valid proof is through `seed` + `fuse`, so an attacker cannot skip leaf circuits
or strip duplicate contributions between steps.

## Verification

The verifier has: the public actions $(rk_i, cv_i, sig_i)$, the listed
tachygrams $tg_i$, the anchor, and the proof bytes.

1. **Anchor**: check the anchor matches a recent pool state
2. **No duplicate tachygrams**: check the tachygram list for repeats
3. **Action sigs**: verify each $sig_i$ against $rk_i$ (RedPallas)
4. **Binding sig**: verify against $\sum cv_i$
5. **Reconstruct**: build `(action_acc, tachygram_acc, anchor)`
   - **Recompute action_acc**: build polynomial from roots $\text{Poseidon}(\mathsf{cv}_i \| \mathsf{rk}_i)$, commit
   - **Recompute tachygram_acc**: build polynomial from roots $\mathsf{tg}_i$, commit
6. **Verify proof**: call Ragu `verify(Pcd { proof, data: header })`

The verifier constructs the header from scratch.
If the proof was computed over different accumulators (e.g. from a double-spend), the reconstructed header won't match and verification fails.
