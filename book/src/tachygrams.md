# Tachygrams

A tachygram is an opaque Poseidon $\mathbb{F}_p$ commitment to the creation or destruction of a note[^notes].

A tachyon transaction is published with a stamp containing tachygrams for the notes involved in its proven actions.

Every action publishes exactly two tachygrams, whichever kind it is.

An output action publishes its note commitment and a padding tachygram.

$$
\mathsf{tg}_0 = \mathsf{cm} =
    \mathsf{Poseidon}_\texttt{Tachyon-CmDerive}(
        \mathsf{rcm}, \mathsf{pk}, v, \psi
    )
$$

$$
\mathsf{tg}_1 = \mathsf{tg}_\bot =
    \mathsf{Poseidon}_\texttt{Tachyon-PadDeriv}(
        \mathsf{rcm}, \mathsf{pk}, v, \psi
    )
$$

The pad commits to the note opening rather than to $\mathsf{cm}$. Both values appear in the same published multiset, so a pad derived as $\mathsf{tg}_\bot = H^\mathsf{pad}(\mathsf{cm})$ would let an observer test every pair in the set for that relation, match each output to its own pad, and recover the output count. Deriving both from the opening leaves an observer with two unlinkable field elements.

A spend action publishes a nullifier for the present epoch and one for the next[^nullifiers].

$$
\mathsf{tg}_0 = \mathsf{nf}_e, \qquad \mathsf{tg}_1 = \mathsf{nf}_{e+1}
$$

Uniform arity is what makes the two action kinds indistinguishable in the published set: an observer counting tachygrams learns the action count and nothing about the split between spends and outputs.

## Tachygram sets

A stamp contains the tachygrams of every action it covers.

A stamp's covered actions may be few (a single action, so two tachygrams) or
many (aggregated actions, two apiece). Ideally, the consensus chain will
contain aggregated[^aggregation] bundles[^bundle].

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

[^nullifiers]: [Nullifiers](./nullifiers.md) gives the derivation of $\mathsf{nf}_e$ from the note's master key, and why a spend publishes the pair rather than one value.

[^aggregation]: See [Aggregation](./aggregation.md) for how stamps merge their tachygram sets.

[^bundle]: See [Bundle](./bundle.md) for the on-wire encoding of bundles and the layout of a stamp trailer.

[^anchor]: See [Anchor](./anchor.md) for the Poseidon chain that absorbs each stamp's tachygram-set commitment.

[^proof-tree]: See [Proof Tree](./proof-tree.md) for how `StampLift` advances a stamp's anchor within an epoch.

[^nullifiers-pair]: See [Nullifiers](./nullifiers.md) for the present/future nullifier pair published with each spend.
