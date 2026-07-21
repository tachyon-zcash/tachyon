# Nullifiers

A nullifier is a secret bound at note creation, and published later to destroy the note. Each note has a distinct nullifier per epoch.

To spend a note, a transaction author must prove that no valid nullifier for it has been published in the pool between the note's creation and some anchor[^anchor]. Spending a note publishes two of its nullifiers to the pool, for the anchor epoch and the next epoch, making such a proof impossible to produce afterward.

Pool state is likely to advance between proof creation and mining, so consensus closes the gap by confirming the nullifiers did not enter the pool in the interim.[^tachygrams] The second nullifier allows consensus to tolerate an epoch transition in that interim.

## Derivation

A note's nullifier for epoch $e$ is the epoch index encrypted under the note's master key, so a window of consecutive epochs' nullifiers can be proven in bulk as one committed polynomial, and the search for them in the pool trustlessly delegated.

### Master key

The note's master key $\mathsf{mk}$ is derived from the note's trapdoor $\psi$ and the wallet's nullifier key $\mathsf{nk}$:

$$
\mathsf{mk} = [\,k,\ w\,] =
    \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}\!(
        \psi, \mathsf{nk}
    )
$$

One sponge, two squeezes: the cipher's round key $k$ and a dedicated whitening key $w$. The master key is fixed per note and must be kept secret; its holder can derive every epoch's nullifier.

### Cipher

The nullifier PRF is a whitened cipher keyed by $\mathsf{mk}$:

$$
\mathsf{nf}_e = \mathsf{PRF}^{\mathsf{nfTachyon}}_{\mathsf{mk}}(e) = \textsf{Tachyon-MiMC}_k(e) + w
$$

Tachyon-MiMC is MiMC over $\F_p$: 64 rounds of the degree-5 S-box under the single round key $k$, added every round,

$$
x_0 = e, \qquad x_{i+1} = (x_i + k + c_i)^5, \qquad \textsf{Tachyon-MiMC}_k(e) = x_{64}
$$

with the round constants $c_i$ fixed by BLAKE2b under the personalization $\texttt{Tachyon-MiMC0064}$ and $c_0 = 0$, and the whitening key $w$ added once after the final round.

Because $\mathsf{nf}_e$ is a pseudo-random function of $\mathsf{mk}$ and the epoch $e$, distinct epochs yield unrelated nullifiers, and an author cannot steer a nullifier toward a chosen value.

### Windows

One derivation proof covers a window of 128 consecutive epochs starting at some epoch $b$. The window's 128 cipher evaluations, 64 round states each, interpolate row-major as a trace polynomial $T$ over an order-8192 multiplicative domain $\langle\omega\rangle$. The whitened trace takes the window's nullifiers as its values on the last-column coset, one nullifier point per epoch:

$$
W = T + w, \qquad \mathsf{nf}_{b+j} = W(\sigma\zeta^{j})
$$

with $\zeta = \omega^{64}$ generating the row subgroup and $\sigma = \omega^{63}$ shifting it onto the nullifier coset. The whitened commitment follows homomorphically from the trace commitment, and a consumer reads any covered nullifier as a single opening. The trace identities that certify a window are enforced in the [proof tree](./proof-tree.md).

## Binding

$\psi$ is carried in the note and digested into the note commitment $\mathsf{cm}$, alongside the payment key $\mathsf{pk}$, which itself pins $\mathsf{nk}$[^pk]. So $\mathsf{cm}$ fixes both $\psi$ and $\mathsf{nk}$, hence $\mathsf{mk}$, hence the entire nullifier sequence. A note has exactly one nullifier sequence, frozen when its commitment enters the pool as a tachygram.

The proof tree never trusts a freely witnessed nullifier. Wherever a nullifier is consumed, a derivation proof shows in-circuit that it is the encryption of its epoch under the note's master key, and binds that derivation to the note by $\mathsf{cm}$.[^derive]

$\psi$ must be unique per note. Two notes that reuse the same $\psi$ share $\mathsf{mk}$ and therefore the same nullifier sequence, so spending one publishes the other's nullifiers.

### Spendable

A spendable tracks an unspent note as the pool advances. It carries the note's current nullifier, its pool anchor, and the note commitment:

$$(\,\mathsf{nf}_e,\;\; \mathsf{anchor},\;\; \mathsf{cm}\,)$$

$\mathsf{nf}_e$ is the nullifier the wallet would publish to spend now, at the lineage's current epoch $e$. Advancing the spendable (a lift) proves every nullifier from epoch $e$ up to the new epoch absent from the pool, then moves $\mathsf{nf}_e$ and the anchor forward together. $\mathsf{cm}$ rides along unchanged, binding the whole lineage to one note, and so to one value: the spend commits to the value inside $\mathsf{cm}$, which the creation stamp proved minted.

A lift advances the current nullifier only to the genuine next nullifier, and the next lift's starting nullifier must equal the current one. Because both are PRF outputs, that equality forces the same note and the same epoch, so a lineage cannot skip an epoch or splice in another note.

### Delegation

The holder of $\mathsf{mk}$ can outsource the search for its nullifiers in the pool.[^delegation] It hands a delegate the next window of values $\Delta_{e..e+d}$, which should be the nullifiers $\mathsf{nf}_{e..e+d}$ but which the delegate treats as opaque. The delegate proves them absent from the pool across stamps and epochs, oblivious to $\mathsf{mk}$, $\psi$, $\mathsf{cm}$, and the note, and commits the sequence on the coefficient generators, terminated by a sentinel $1$ one position above the window:

$$\delta = \sum_{i} [\Delta_{e+i}]\,\mathcal{G}_i + \mathcal{G}_d$$

The sentinel keeps every committed sequence nonzero (an empty window is the constant $1$), so $\delta$ is never the identity point, and it pins the window's exact length.

At the bind the wallet proves each $\Delta$ genuine: it re-witnesses the whitened window trace $W$ against the derivation's commitment, reads the covered run of nullifier points off $W$, and folds at a challenge $\chi$ bound to both commitments,

$$
\Delta(\chi) + (\mathsf{nf}_{\mathrm{tip}} - 1)\,\chi^{d}
    = \sum_{i=0}^{d} \chi^{i}\, \mathsf{nf}_{e+i}
$$

so each committed value is forced to the real $\mathsf{nf}_{e+i}$. The span is measured in epoch-boundary crossings: $d$ is the crossing count and $\delta$ holds one nullifier per crossing, plus the nullifier of the epoch in progress at the span's tip, which is carried separately because that epoch is not yet complete. The swap of the sentinel for the tip binds the tip too, so the lineage's new current nullifier is itself a genuine nullifier rather than a free value.

Coverage is what lets a span be arbitrary. The derivation need only cover the delegated span, and the fold telescopes over any run of nullifier points inside the window, so the wallet can delegate any span within one 128-epoch window, longer delegations composing across successive binds and lifts; only the wallet, holding the note, can fold the proven absence into the lineage.[^lift]

[^anchor]: [Anchor](./anchor.md) describes the pool state commitment.
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the unified consensus rule covering all published tachygrams.
[^pk]: $\mathsf{pk} = \mathrm{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x, \mathsf{nk})$ binds $\mathsf{nk}$ into the commitment, so a wrong $\mathsf{nk}$ yields a wrong $\mathsf{cm}$.
[^derive]: The derivation chain and its consumers; see [Proof Tree](./proof-tree.md).
[^delegation]: The delegate composes the absence proofs the wallet later lifts onto its own lineage; see [Proof Tree](./proof-tree.md).
[^lift]: This fold is the `SpendableLift` proof step; see [Proof Tree](./proof-tree.md).
