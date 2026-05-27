# Nullifiers

A nullifier is a secret bound at note creation and revealed to destroy the note. Each note should have a unique nullifier per epoch.

To spend a note, a transaction author must prove that no valid nullifier for it has been published in the pool between the note's creation and some anchor[^anchor]. Spending a note publishes two of its nullifiers to the pool, for the anchor epoch and the next epoch, making such a proof impossible to produce afterward.

Pool state is likely to advance between proof creation and mining, so consensus closes the gap by confirming the nullifiers did not enter the pool in the interim.[^tachygrams] The second nullifier allows consensus to tolerate an epoch transition in that interim.

## Pronullifiers

A pronullifier is a per-epoch value for a note that is used to produce a nullifier. A note's pronullifiers are the coefficients of a polynomial:

$$M(X) = \sum_i M_i X^i$$

Adding the note's commitment $\mathsf{cm}$ to a pronullifier yields a nullifier:

$$N_e = M_e + \mathsf{cm}$$

Doing this for the whole sequence gives the nullifier polynomial:

$$N(X) = \sum_i \left( M_i + \mathsf{cm} \right) X^i$$

Pronullifiers should remain private. The sequence should be high-entropy, but its derivation and structure are unspecified.

<!-- todo: elaborate on re-use and predictable pronullifiers -->

## Binding

A note is bound to its nullifiers when it is created. During a transaction, the note commits pronullifier polynomial $M$ with generator $\mathcal{G}$ to the $\psi$ field of the note:

$$\psi = \sum_i [M_i]\,\mathcal{G}_i$$

The note commitment $\mathsf{cm}$ digests $\psi$ among the other note fields, publicly binding the sequence when the commitment enters the pool as a tachygram. The stamp inclusion anchors $M_0$ to a specific epoch.

At inclusion, $\phi$ represents the nullifier polynomial $N$ committed with $\mathsf{cm}$ blinding:

$$\phi = [\mathsf{cm}]\,\mathcal{H} + \sum_i [N_i]\,\mathcal{G}_i$$

Equivalently it is $\psi$ with every coefficient shifted by $\mathsf{cm}$ and blinded, the homomorphic step:

$$\phi = \psi + [\mathsf{cm}]\Bigl( \mathcal{H} + \sum_i \mathcal{G}_i \Bigr)$$

The $[\mathsf{cm}]\,\mathcal{H}$ term uses a generator independent of the $\mathcal{G}_i$ so it pins $\phi$ to $\mathsf{cm}$ and so to the note.

## Less Future

From epoch $e$ onward the note's future $\phi_e$ commits the tail of $N$ re-based to degree zero, with the same $\mathsf{cm}$ blind:

$$\phi_e = [\mathsf{cm}]\,\mathcal{H} + \sum_i [N_{e+i}]\,\mathcal{G}_i $$

Its pronullifier counterpart $\psi_e$ commits the tail of $M$ re-based the same way:

$$\psi_e = \sum_i [M_{e+i}]\,\mathcal{G}_i$$

The homomorphic relationship survives the truncation.

$$ \psi \xleftrightarrow{\mathsf{cm}} \phi $$
$$ \psi_e \xleftrightarrow{\mathsf{cm}} \phi_e $$

However, rebasing is not a group operation.

$$
    \psi_e \not\leftrightarrow \psi_{e+d}
$$
$$
    \phi_e \not\leftrightarrow \phi_{e+d}
$$
$$
    \psi_e \not\leftrightarrow \phi_{e+d}
$$

Relationships between commitments to the rebased sequences are not homomorphically evident.

## Delegation

The holder of $M$ can outsource the search for its nullifiers in the pool.[^delegation] It hands a delegate the next window of values $\Delta_{e..e+d}$ which should be nullifiers $N_{e..e+d}$ but which may be completely meaningless. The sequence forms a polynomial like before:

$$\Delta(X) = \sum_{i < d} \Delta_{e+i}\,X^i$$

It proves them absent from the pool across stamps and epochs, oblivious to $M$ and $\mathsf{cm}$ and the note, and commits the sequence on the generators alone:

$$\delta = \sum_{i < d} [\Delta_{e+i}]\,\mathcal{G}_i$$

The wallet may privately confirm $\delta$ is the prefix of the sequence $\phi_e$ commits:

$$\sum_i N_{e+i}\,X^i = \Delta(X) + X^d \sum_i N_{e+d+i}\,X^i$$

Dropping $\Delta$ and shifting the tail down by $d$ leaves the future from epoch $e+d$ onward. Only the wallet holds $M$ so only it can blind that tail and fold the coverage into a fresh $\phi_{e+d}$ of its own.[^lift]

Re-basing is what lets a window be arbitrary. Any run of nullifiers shifts down to a degree-zero polynomial that stands as a witness on its own, so the wallet can carve out and delegate any window from any epoch.

In the proof tree the window is measured in epoch-boundary crossings: $d$ is the segment's crossing count (`elapsed_size`) and $\Delta$ holds one nullifier per crossing (`elapsed`). The epoch in progress at the span's tip is not yet complete, so its nullifier is carried separately as `present_nf` and tied to the rebased future's degree-zero coefficient at the lift, rather than folded into $\Delta$. This keeps a span sound when either end falls mid-epoch.

[^anchor]: [Anchor](./anchor.md) describes the pool state commitment
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the unified consensus rule covering all published tachygrams.
[^lift]: This shrink is the `SpendableLift` proof step; see [Proof Tree](./proof-tree.md).
[^delegation]: The delegate composes the absence proofs the wallet later lifts onto its own commitment; see [Proof Tree](./proof-tree.md).
