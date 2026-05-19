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

[^notes]: See [Notes](./notes.md) for the note's field structure: $\mathsf{pk}$, $v$, $\psi$, $\mathsf{rcm}$.

[^nullifiers]: See [Nullifiers](./nullifiers.md) for the GGM derivation that yields $\mathsf{KDF}^\mathsf{climb}_\psi(e, D)$.

[^aggregation]: See [Aggregation](./aggregation.md) for how stamps merge their tachygram sets.

[^bundle]: See [Bundle](./bundle.md) for the on-wire encoding of bundles and the layout of a stamp trailer.

[^anchor]: See [Anchor](./anchor.md) for the Poseidon chain that absorbs each stamp's tachygram-set commitment.
