# Nullifiers

A nullifier is a Poseidon $\mathbb{F}_p$ commitment to two private values (the note's trapdoor $\psi$[^notes] and the wallet's nullifier key $\mathsf{nk}$[^keys]) and a relevant epoch $e$ according to consensus. So, the nullifier for a given note is different every epoch.

In order to spend a note, the transaction author must publish an anchored[^anchor] proof that no nullifier for the note has ever been published, and publish two nullifiers (for the anchor epoch and the next future epoch).

Pool state immediately advances beyond the proof's anchor, so consensus must confirm these nullifiers did not enter the pool in the intervening time. The second published nullifier allows consensus to handle an epoch transition if necessary.

[^notes]: See [Notes](./notes.md).
[^keys]: See [Keys](./keys.md).
[^anchor]: See [Anchor](./anchor.md).

## Derivation

Derivation involves a Goldreich-Goldwasser-Micali tree so that proofs involving nullifier derivation may be trustlessly delegated. Any given node in the tree may only climb towards the leaves, and never back towards the root.

The tree has depth $D$ and arity $A$, covering leaf epochs $e \in [0,\ A^D - 1]$.

A node at depth $d$ in the tree covers a contiguous range of $A^{D-d}$ consecutive epochs.

### Root

The note's master key $\mathsf{mk}$ is derived from the note's trapdoor $\psi$ and the wallet's nullifier key $\mathsf{nk}$. This is the tree's root.

$$
\mathsf{mk} = \mathsf{KDF}^{\mathsf{root}}_\psi(\mathsf{nk}) =
    \mathsf{Poseidon}_\texttt{Tachyon-NfPrefix}\!(
        \psi, \mathsf{nk}
    )
$$

The root covers all epochs, and should be kept secret.

### Climb

To climb towards the leaf at some epoch $e$, decompose into $d \in [0 \ldots D]$ base-$A$ direction chunks (most significant bits first) and climb one step per chunk.

$$
\mathsf{KDF}^{\mathsf{climb}}_\psi(e, 0) =
    \mathsf{KDF}^{\mathsf{root}}_\psi(\mathsf{nk})
$$

$$
\mathsf{KDF}^{\mathsf{climb}}_\psi(e, d) =
    \mathsf{Poseidon}_\texttt{Tachyon-NfPrefix}\!\left(
        \mathsf{KDF}^{\mathsf{climb}}_\psi(e, d-1),\ \left\lfloor
            e / A^{D-d}
        \right\rfloor
        \bmod A
    \right)
$$

The value at $\mathsf{KDF}^{\mathsf{climb}}_\psi(e, D)$ is the leaf key for epoch $e$.

### Leaf

The leaf key is hashed once more under a separate domain to derive the nullifier.

$$
\mathsf{nf} =
    \mathsf{Poseidon}_\texttt{Tachyon-NfDerive}\!\left(
        \mathsf{KDF}^{\mathsf{climb}}_\psi(e, D)
    \right)
$$
