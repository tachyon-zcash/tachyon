# Notes

A note is a discrete unit of value in the Tachyon shielded pool.

An output operation creates a note by publishing a commitment.

A spend operation consumes a note by publishing a nullifier.

## Fields

Tachyon notes are simple: a note carries only its recipient, value, and two trapdoors.

| Field | Type | Description |
| ----- | ---- | ----------- |
| $\mathsf{pk}$ | $\mathbb{F}_p$ | recipient's payment key[^keys] |
| $v$ | u64 | value in zatoshi, $1 \leq v \leq 2.1 \times 10^{15}$ |
| $\psi$ | $\mathbb{F}_p$ | nullifier trapdoor[^nullifiers] |
| $\mathsf{rcm}$ | $\mathbb{F}_p$ | note commitment trapdoor |

Zero-value notes are forbidden.

## Commitment

The note commitment binds all four fields:

$$
\mathsf{cm} =
    \mathsf{Poseidon}_\texttt{Tachyon-CmDerive}(
        \mathsf{rcm}, \mathsf{pk}, v, \psi
    )
$$

For an output operation, $\mathsf{cm}$ is the published [tachygram](./tachygrams.md).

## Nullifier

Complete derivation is covered in [Nullifiers](./nullifiers.md).

The note nullifier changes per epoch. Briefly, a nullifier for epoch $e$ is derived:

$$
\mathsf{nf} =
    \mathsf{Poseidon}_\texttt{Tachyon-NfDerive}\!\left(
        \mathsf{KDF}^{\mathsf{climb}}_\psi(e, D)
    \right)
$$

For a spend operation, two nullifiers at present epoch $e$ and next epoch $e+1$ are published as [tachygrams](./tachygrams.md).

[^keys]: See [Keys](./keys.md) for $\mathsf{pk}$ derivation from $(\mathsf{ak}, \mathsf{nk})$.
[^nullifiers]: See [Nullifiers](./nullifiers.md) for how $\psi$ enters nullifier derivation.
