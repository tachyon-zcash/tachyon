# Nullifiers

A nullifier is a secret bound at note creation, and published later to destroy the note. Each note has a distinct nullifier per epoch.

To spend a note, a transaction author must prove that no valid nullifier for the note has been published in the pool between the note's creation and some anchor[^anchor].
Spending a note publishes two of its nullifiers to the pool, for the anchor epoch and the next epoch, making such a proof impossible to produce for later anchors.

Pool state is likely to advance between proof creation and mining, so consensus closes the gap by confirming the nullifiers did not enter the pool in the interim.[^tachygrams] The second nullifier allows consensus to tolerate an epoch transition in that interim.

## Derivation

A nullifier is the output of a Poseidon sponge. Abstractly,

$$
  \mathsf{nf}_e = \mathsf{PRF}^{\mathsf{nfTachyon}}_{\mathsf{mk}}(e)
$$

Because $\mathsf{nf}_e$ is the output of a pseudo-random function of master key $\mathsf{mk}$ and epoch $e$, distinct epochs have unrelated nullifiers.

Epochs are grouped at sponge rate $r$ for proof efficiency.
One sponge squeezes $r$ consecutive nullifiers starting at base epoch $w = e - (e \bmod r)$

$$
    \mathsf{Poseidon}_\texttt{Tachyon-NfDerive}\!(
      \mathsf{mk}, w
    ) = (\mathsf{nf}_w, \ldots,\ \mathsf{nf}_{w + r - 1})
$$

So $\mathsf{nf}_e$ is the member at position $e - w$ in its group.

## Binding

The master key $\mathsf{mk}$ is derived from the note trapdoor $\psi$ and nullifier key $\mathsf{nk}$.

The note commitment $\mathsf{cm}$ digests $\psi$ and the payment key $\mathsf{pk}$, which transitively binds $\mathsf{nk}$ via its own derivation, closing the circle with $\mathsf{mk}$.

Distinct notes under the same $\mathsf{nk}$ should not re-use $\psi$ because the pair $(\psi, \mathsf{nk})$ produce an identical $\mathsf{mk}$ and identical sequence of nullifiers.

## Delegation

A delegate may observe pool state and prove the absence of nullifiers without holding key material or any information about a note.

The delegate is provided an arbitrary sequence of values $\delta_{e..e+d}$ to prove absent from epochs $e..e+d$ and these tested values are committed as a contiguous sequence.

$$
  \Delta(X) =
    \prod_{i = e}^{e+d} \Bigl(
        \bigl( \delta_{i} + (i+1)X \bigr)^3 - 2
    \Bigr)
$$

In parallel, $\mathsf{mk}$ proves derivation of a nullifier sequence for a range at least covering the delegated sequence.

$$
  N(X) = \prod_{j} \Bigl(
      \bigl( \mathsf{nf}_{j} + (j+1)X \bigr)^3 - 2
    \Bigr)
$$

Witness material $ C = N \setminus \Delta $ is prepared for the expected complement.

$$
  C(X) = \prod_{j \notin e..e+d} \Bigl(
      \bigl( \mathsf{nf}_{j} + (j+1)X \bigr)^3 - 2
    \Bigr)
$$

The delegate returns its proof of absence, and the relationship is verified by challenge.

$$
  N = C \uplus \Delta
   \quad \iff \quad
  N(X) = C(X) \cdot \Delta(X)
$$

The delegate's values are arbitrary until bound to a proven derivation. If the delegate constructed a proof diverging from the correct sequence, no relationship can be established with $N$ and the delegate's proof is useless.

[^anchor]: [Anchor](./anchor.md) describes the pool state commitment.

[^tachygrams]: See [Tachygrams](./tachygrams.md) for the unified consensus rule covering all published tachygrams.
