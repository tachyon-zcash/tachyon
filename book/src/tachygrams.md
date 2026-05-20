# Tachygrams

A tachygram is an opaque Poseidon $\mathbb{F}_p$ commitment to the creation or destruction of a note[^notes].

A tachyon transaction is published with a stamp containing tachygrams for the notes involved in its proven actions.

An output action involves a note commitment.

$$
\mathsf{tg} = \mathsf{cm} =
    \mathsf{Poseidon}_\texttt{Tachyon-CmDerive}(
        \mathsf{rcm}, \mathsf{pk}, v, \psi
    )
$$

A spend action involves a nullifier[^nullifiers].

$$
\mathsf{tg} = \mathsf{nf} =
    \mathsf{Poseidon}_\texttt{Tachyon-NfDerive}\!\left(
        \mathsf{KDF}^{\mathsf{climb}}_\psi(e, D)
    \right)
$$

## Tachygram sets

A stamp contains the tachygrams of every action it covers.

A stamp's covered actions may be small (a single action with one or two
tachygrams) or large (many aggregated actions). Ideally, the consensus chain
will contain aggregated[^aggregation] bundles[^bundle].

The covering proof in a stamp has witnessed a commitment to an unordered set of those tachygrams.

$$
\mathsf{tachygram\_acc}(X) =
   \prod_i \left(
      X - \mathsf{tg}_i
   \right)
$$

This set is the atomic unit which folds into pool state to contribute to the anchor[^anchor].

## Consensus validation

When a stamp is published, consensus checks that every tachygram in the stamp is absent from every block of the current epoch and the immediately preceding epoch. A duplicate within that two-epoch window is rejected.

The window spans two epochs because a stamp can republish a tachygram in two distinct ways.

A stamp's anchor may have been advanced within its epoch via `StampLift`[^proof-tree], so the stamp could have been built at any earlier height in the same epoch. Consensus therefore scans every block in the anchor's epoch, not just blocks after the anchor.

A spend publishes a nullifier for the current epoch and one for the next epoch[^nullifiers-pair]. The next-epoch nullifier published in epoch $e$ is the present-epoch nullifier that any later spend of the same note would have to publish in epoch $e+1$. Including the previous epoch in the check catches that collision.

[^notes]: See [Notes](./notes.md) for the note's field structure: $\mathsf{pk}$, $v$, $\psi$, $\mathsf{rcm}$.

[^nullifiers]: See [Nullifiers](./nullifiers.md) for the GGM derivation that yields $\mathsf{KDF}^\mathsf{climb}_\psi(e, D)$.

[^aggregation]: See [Aggregation](./aggregation.md) for how stamps merge their tachygram sets.

[^bundle]: See [Bundle](./bundle.md) for the on-wire encoding of bundles and the layout of a stamp trailer.

[^anchor]: See [Anchor](./anchor.md) for the Poseidon chain that absorbs each stamp's tachygram-set commitment.

[^proof-tree]: See [Proof Tree](./proof-tree.md) for how `StampLift` advances a stamp's anchor within an epoch.

[^nullifiers-pair]: See [Nullifiers](./nullifiers.md) for the present/future nullifier pair published with each spend.
