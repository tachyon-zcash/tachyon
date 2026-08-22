# Nullifiers

A nullifier is a secret bound at note creation, and published later to destroy the note. Each note has a distinct nullifier per epoch.

To spend a note, a transaction author must prove that no valid nullifier for it has been published in the pool between the note's creation and some anchor[^anchor]. Spending a note publishes two of its nullifiers to the pool, for the anchor epoch and the next epoch, making such a proof impossible to produce afterward.

Pool state is likely to advance between proof creation and mining, so consensus closes the gap by confirming the nullifiers did not enter the pool in the interim.[^tachygrams] The second nullifier allows consensus to tolerate an epoch transition in that interim.

## Derivation

A note's nullifiers are squeezed from a Poseidon sponge keyed by the note's master key, in groups of four, so that a window of consecutive epochs can be proven at once and a note's nullifier-absence proofs trustlessly delegated.

### Master key

The note's master key $\mathsf{mk}$ is derived from the note's trapdoor $\psi$ and the wallet's nullifier key $\mathsf{nk}$.

$$
\mathsf{mk} =
    \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}\!(
        \psi, \mathsf{nk}
    )
$$

The master key is fixed per note, and should be kept secret.

### Groups

Nullifiers are derived four at a time. Writing $w = \lfloor e/4 \rfloor$ for the group holding epoch $e$ and $j = e \bmod 4$ for its position within the group,

$$
\mathsf{nf}_e = \mathsf{squeeze}_j\bigl(
    \mathsf{absorb}(\texttt{Tachyon-NfDerive},\ \mathsf{mk},\ w)
\bigr)
$$

counting squeezes from zero. The group size is the sponge's rate, so a group of four costs one permutation. Each group absorbs $w$ from scratch, so $\mathsf{nf}_e$ is a function of $\mathsf{mk}$ and $e$ alone, written $\mathsf{PRF}^{\mathsf{nfTachyon}}_{\mathsf{mk}}(e)$ where the derivation's structure does not matter.

Because $\mathsf{nf}$ is a pseudo-random function of $\mathsf{mk}$ and the epoch $e$, distinct epochs yield unrelated nullifiers, and an author cannot steer a nullifier toward a chosen value.

### Windows

One derivation proof derives a window of 16 consecutive epochs, four groups, from a group-aligned base, and exports any range inside it. The exported range is carried as one sequence polynomial in the Horner encoding described under [Delegation](#delegation), so a consumer reads the epochs it needs out of the range, and a longer span is a chain of fused ranges.

## Binding

$\psi$ is carried in the note and digested into the note commitment $\mathsf{cm}$, alongside the payment key $\mathsf{pk}$, which itself pins $\mathsf{nk}$[^pk]. So $\mathsf{cm}$ fixes both $\psi$ and $\mathsf{nk}$, hence $\mathsf{mk}$, hence the entire nullifier sequence. A note has exactly one nullifier sequence, frozen when its commitment enters the pool as a tachygram.

The proof tree never trusts a freely witnessed nullifier. Wherever a nullifier is consumed, a derivation proves in-circuit that it is the note's $\mathsf{mk}$ squeezed at that epoch, and binds that derivation to the note by $\mathsf{cm}$.[^derive]

$\psi$ must be unique per note. Two notes that reuse the same $\psi$ share $\mathsf{mk}$ and therefore the same nullifier sequence, so spending one publishes the other's nullifiers.

### Spendable

A spendable tracks an unspent note as the pool advances. It carries the note's current nullifier, its pool anchor, and the note commitment:

$$(\,\mathsf{nf}_e,\;\; \mathsf{anchor},\;\; \mathsf{cm}\,)$$

$\mathsf{nf}_e$ is the nullifier the wallet would publish to spend now, at the lineage's current epoch $e$. Advancing the spendable (a lift) proves every nullifier from epoch $e$ up to the new epoch absent from the pool, then moves $\mathsf{nf}_e$ and the anchor forward together. $\mathsf{cm}$ rides along unchanged, binding the whole lineage to one note, and so to one value: the spend commits to the value inside $\mathsf{cm}$, which the creation stamp proved minted.

A lift advances the current nullifier only to the genuine next nullifier, and the next lift's starting nullifier must equal the current one. Because both are PRF outputs, that equality forces the same note and the same epoch, so a lineage cannot skip an epoch or splice in another note.

### Delegation

The holder of $\mathsf{mk}$ can outsource the search for its nullifiers in the pool.[^delegation] It hands a delegate the next window of values $\Delta_{e..e+d}$, which should be the nullifiers $\mathsf{nf}_{e..e+d}$ but which the delegate treats as opaque. The delegate proves them absent from the pool across stamps and epochs, oblivious to $\mathsf{mk}$, $\psi$, $\mathsf{cm}$, and the note, and commits the sequence on the coefficient generators in Horner order, oldest member at the top and the present one at $\mathcal{G}_0$:

$$\delta = \sum_{i} [\Delta_{e+i}]\,\mathcal{G}_{d-i}$$

A sequence is never empty and its members are nonzero, so $\delta$ is never the identity point. The oldest member pins the window's exact length.

At the lift the wallet binds $\delta$ to genuine nullifiers: it reads the window's coefficients at the delegated epochs out of a derived window that covers them, so each $\Delta_{e+i}$ is the real $\mathsf{nf}_{e+i}$. The window is measured in epoch-boundary crossings: $d$ is the crossing count and $\delta$ holds one nullifier per crossing, and the nullifier of the epoch in progress at the span's tip.

A window may be arbitrary because the read takes any run of coefficients out of a covering derivation. So the wallet can delegate any window inside one, and only the wallet, holding the note, can fold the proven absence into the lineage.[^lift]

[^anchor]: [Anchor](./anchor.md) describes the pool state commitment.
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the unified consensus rule covering all published tachygrams.
[^pk]: $\mathsf{pk} = \mathrm{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x, \mathsf{nk})$ binds $\mathsf{nk}$ into the commitment, so a wrong $\mathsf{nk}$ yields a wrong $\mathsf{cm}$.
[^derive]: The derivation steps and their consumers; see [Proof Tree](./proof-tree.md).
[^delegation]: The delegate composes the absence proofs the wallet later lifts onto its own lineage; see [Proof Tree](./proof-tree.md).
[^lift]: This fold is the `SpendableLift` proof step; see [Proof Tree](./proof-tree.md).
