# Nullifiers

A nullifier is a secret bound at note creation, and published later to destroy the note. Each note has a distinct nullifier per epoch.

To spend a note, a transaction author must prove that no valid nullifier for it has been published in the pool between the note's creation and some anchor[^anchor]. Spending a note publishes two of its nullifiers to the pool, for the anchor epoch and the next epoch, making such a proof impossible to produce afterward.

Pool state is likely to advance between proof creation and mining, so consensus closes the gap by confirming the nullifiers did not enter the pool in the interim.[^tachygrams] The second nullifier allows consensus to tolerate an epoch transition in that interim.

## Derivation

Derivation stretches a small per-note master key into committed polynomials, so that one certification covers every epoch's nullifier and a note's nullifier-absence proofs may be trustlessly delegated as opaque value windows.

### Master key

The note's master key $\mathsf{mk}$ is a schedule of $32$ round keys derived from the note's trapdoor $\psi$ and the wallet's nullifier key $\mathsf{nk}$, in two parts of $16$. One Poseidon sponge per part absorbs the domain, the part index, $\psi$, and $\mathsf{nk}$, then squeezes that part's keys:

$$
\mathsf{mk}[16i + s] =
    \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}\!\left(
        i, \psi, \mathsf{nk}
    \right)\!\big[s\big]
    \qquad i \in \{0, 1\},\ s \in [0, 16)
$$

$\mathsf{mk}$ covers all epochs, and should be kept secret.

### Expansion

A $32$-round MiMC cipher $E_{\mathsf{mk}}$ over the pow5 S-box, keyed cyclically by $\mathsf{mk}$ and finished with a dedicated whitening key $w$, expands the master key into the derivation schedule: the $1024$ keys

$$
K_r = E_{\mathsf{mk}}\!\left(s + \delta\,r\right) \qquad r \in [0, 1024).
$$

The input salt $s$, the input stride $\delta$, and the whitening key $w$ are squeezed from a domain-separated Poseidon sponge over a fixed prefix of $\mathsf{mk}$ ($\texttt{Tachyon-NfExpand}$), so the cipher's inputs are secrets of the note, never public constants.

The schedule is produced in four parts of $256$ (one proof step per part) that interleave into a single orbit. Input secrecy is what makes the schedule's width real: a schedule key alone yields no known plaintext/ciphertext pair, so recovering $\mathsf{mk}$ from leaked keys means eliminating the secret input across two outputs, a resultant of degree $5^{64} \approx 2^{148}$ rather than a univariate solve at the cipher's symbolic degree $5^{32} \approx 2^{74}$; the secret stride $\delta$ hides even the pairwise input differences such an elimination would otherwise use.

### Emitter polynomials

The schedule keys an $8192$-round MiMC cipher (the *emitter*, cycling the orbit eight times). Per note, $N = 4$ derivation polynomials $T_j$ are built, each the interpolant of the emitter's full round-state trace on a per-polynomial secret salt:

$$
T_j(\omega^r) = s_{j,r}
    \qquad s_{j,\,r} \text{ the } r\text{-th round state of } E^{8192}_{K}\!\left(\mathsf{mk}_s^{(j)}\right)
$$

over the order-$8192$ domain $\langle\omega\rangle$. The salts $\mathsf{mk}_s^{(j)}$, the per-polynomial weight bases $\rho_j$, and the secret query shift $c$ are all squeezed from domain-separated Poseidon sponges over a fixed prefix of $\mathsf{mk}$ ($\texttt{Tachyon-NfSalt\_\_}$ and $\texttt{Tachyon-NfWeight}$).

### Query

The nullifier at epoch offset $d$ from the note's creation epoch is the weighted off-domain query

$$
\mathsf{nf}_d = \sum_{j} \rho_j^{\,d}\; T_j\!\left(c\,\gamma^{d}\right)
$$

where $\gamma$ generates the order-$S$ query coset ($S = 16384$, $\omega = \gamma^2$) and $c \notin \langle\gamma\rangle$. The off-domain shift is load-bearing: evaluation at a domain point *is* an emitter round-state, so keeping the query coset $c\,\langle\gamma\rangle$ disjoint from $\langle\omega\rangle$ ensures every published nullifier is a Lagrange combination of the whole trace, never a raw round-state.

Because $\mathsf{nf}_d$ is a pseudo-random function of $\mathsf{mk}$ and the offset $d$, distinct epochs yield unrelated nullifiers, and an author cannot steer a nullifier toward a chosen value.

## Binding

$\psi$ is carried in the note and digested into the note commitment $\mathsf{cm}$, alongside the payment key $\mathsf{pk}$, which itself pins $\mathsf{nk}$[^pk]. So $\mathsf{cm}$ fixes both $\psi$ and $\mathsf{nk}$, hence $\mathsf{mk}$, hence the entire nullifier sequence. A note has exactly one nullifier sequence, frozen when its commitment enters the pool as a tachygram.

The proof tree never trusts a freely witnessed nullifier. The derivation chain certifies the $T_j$ once, in-circuit, against the note's $\mathsf{mk}$ and $\mathsf{cm}$; wherever a nullifier is consumed, the query is re-evaluated against those certified commitments.[^derive]

$\psi$ must be unique per note. Two notes that reuse the same $\psi$ share $\mathsf{mk}$ and therefore the same nullifier sequence, so spending one publishes the other's nullifiers.

### Spendable

A spendable tracks an unspent note as the pool advances. It carries the note's current nullifier, its pool anchor, and the note commitment:

$$(\,\mathsf{nf}_e,\;\; \mathsf{anchor},\;\; \mathsf{cm}\,)$$

$\mathsf{nf}_e$ is the nullifier the wallet would publish to spend now, at the lineage's current epoch $e$. Advancing the spendable (a lift) proves every nullifier from epoch $e$ up to the new epoch absent from the pool, then moves $\mathsf{nf}_e$ and the anchor forward together. $\mathsf{cm}$ rides along unchanged, binding the whole lineage to one note, and so to one value: the spend commits to the value inside $\mathsf{cm}$, which the creation stamp proved minted.

A lift advances the current nullifier only to a genuine next query value, and the next lift's starting nullifier must equal the current one. Because both are PRF outputs, that equality forces the same note and the same epoch, so a lineage cannot skip an epoch or splice in another note.

### Delegation

The holder of $\mathsf{mk}$ can outsource the search for its nullifiers in the pool.[^delegation] It hands a delegate the next window of values $\Delta_{e..e+d}$, which should be the nullifiers $\mathsf{nf}_{e..e+d}$ but which the delegate treats as opaque. The delegate proves them absent from the pool across stamps and epochs, oblivious to $\mathsf{mk}$, $\psi$, $\mathsf{cm}$, and the note, and commits the sequence on the coefficient generators, terminated by a sentinel $1$ one position above the window:

$$\delta = \sum_{i} [\Delta_{e+i}]\,\mathcal{G}_i + \mathcal{G}_d$$

The sentinel keeps every committed sequence nonzero (an empty window is the constant $1$), so $\delta$ is never the identity point, and it pins the window's exact length.

At the lift the wallet binds $\delta$ to genuine query values: a homomorphic running-sum argument over the certified $T_j$ proves the committed sequence matches the note's real $\mathsf{nf}_{e+i}$ at each offset. The window is measured in epoch-boundary crossings: $d$ is the crossing count and $\delta$ holds one nullifier per crossing, plus the nullifier of the epoch in progress at the span's tip, which is carried separately because that epoch is not yet complete. The wallet binds the tip too, so the lineage's new current nullifier is itself a genuine query value rather than a free one.

The offset indexing is what lets a window be arbitrary. The running-sum accumulator reads any contiguous arc $[e, e+d)$ of the query coset as an endpoint difference, so the wallet can delegate any window from any epoch, and only the wallet, holding the note, can fold the proven absence into the lineage.[^lift]

[^anchor]: [Anchor](./anchor.md) describes the pool state commitment.
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the unified consensus rule covering all published tachygrams.
[^pk]: $\mathsf{pk} = \mathrm{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x, \mathsf{nk})$ binds $\mathsf{nk}$ into the commitment, so a wrong $\mathsf{nk}$ yields a wrong $\mathsf{cm}$.
[^derive]: The derivation chain and its consumers; see [Proof Tree](./proof-tree.md).
[^delegation]: The delegate composes the absence proofs the wallet later lifts onto its own lineage; see [Proof Tree](./proof-tree.md).
[^lift]: This fold is the `SpendableLift` proof step; see [Proof Tree](./proof-tree.md).
