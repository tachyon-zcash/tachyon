# A Deep Dive on Tachyon

Although Tachyon’s central contribution is its use of prunable nullifiers to
scale Zcash without compromising privacy, we begin from a different vantage point.
Rather than diving directly into how evolving nullifiers work, we first examine a
foundational design decision in Tachyon’s key structure: the separation of concerns across subprotocols that shapes the rest of the system.

The [Zcash Spec](https://zips.z.cash/protocol/protocol.pdf) is most illustrious
for its sedimentary layers of meticulous notations and its evolving key
structures across network upgrades.
We marvel at the sophistication of the key designs, at the laborious effort
behind to strive for efficiency, security, and rich functionalities all at once.
But why such growing complexity? After all, the Sprout upgrade, following the
original [Zerocash](https://eprint.iacr.org/2014/349.pdf), only requires one
payment key and one encryption key.

<P align="center">
  <img src="./assets/zcash_keys.png" alt="zcash_keys" />
</p>

One source of the complexity is the **separation of proof generation and
transaction authorization**. In Zerocash/Sprout, a valid SNARK proof already
ensures rightful ownership, thus no further authorization needed theoretically.
In practice, however, hardware wallets are both resource constrained and vendor
gated to support intensive proof generation. While Sprout can lean on the zero
knowledge of SNARKs to prevent linkability, Sapling spends authorized via
signatures requires *re-randomizable signature* to prevent linkage between
spends from the same owner. This re-randomization manifests through the
*authorization key* $\ak$ in the secret witness and the *randomized authorization
key* $\rk = \ak + [\alpha]\,\G$ in the public instance of the proof.
The spend authorization signature is verified against the publicized $\rk$.

Another reason for the complexity is the **conflation of note ownership
and note transmission**. Since the original Zerocash (inherited in all Zcash
upgrades), the payment address serves *dual* purposes: declaring note ownership
and facilitating transmission of note secrets. The sender of a transaction
needs to securely communicate the output note openings so that they can be spent
later by the recipient. Without assuming secure channels between all users,
Zcash has been transmitting the encrypted memo *in-band* as part of the
transaction, effectively using the blockchain as the public bulletin board.
The payment address, publicized to the sender, contains a *transmission key*
which is the encryption key of a hybrid public key encryption scheme.
Zcash, from Sapling onward, is extra cautious about the privacy leakage in case
of colluding senders under reused transmission keys.
Therefore, *diversified address* is introduced to randomized the transmission
key *while preserving the same incoming viewing key* $\ivk$ for memo decryption
and detecting incoming notes.

Furthermore, **fine-grained disclosure of transaction flows** requires a
distinct *outgoing viewing key* to enable optional viewing of outbound notes.
Viewing keys support selective disclosure of both incoming and outgoing notes,
either to the account holder or to authorized third parties.
This separation also facilitates quantum-safe outgoing viewing keys from day
one, as they are not subject to the address-diversification requirement that
currently ties $\ivk$ to discrete-log–based constructions.

## Decoupling Payment Protocol from Shielded Protocol {#decouple}

A key observation Tachyon makes is that we can **separate the concerns of
spend authorization and note transmission**! This separation appears in the
decoupling of the shielded protocol from the payment protocol. The payment protocol
is responsible for full payment address construction, note transmission, and
selective disclosure capabilities, while the shielded protocol is reduced to the
minimal functionality required to maintain the shielded pool and enforce note
ownership and authorized transfers on-chain.

Informally:

- Shielded protocol: binds every note to an owner for spend authorization
  - Spend authorization requires both valid proof of ownership (proof of
  knowledge on $\nk$) and transaction authorization (signature under $\rk$)
  - Beyond maintaining the shielded pool, the blockchain acts as a data
  availability layer for arbitrary payment-protocol data
- Payment protocol: securely transmits relevant note info to intended recipients
  - Wallets, typically standardized, define the concrete key derivation hierarchy
  needed to satisfy the payment protocol’s functionality and security requirements.
  - Wallets may support multiple payment protocols, such as 
  Payment request ([ZIP-321](https://zips.z.cash/zip-0321)) and
  URI-encapsulated Payments ([ZIP-324](https://zips.z.cash/zip-0324)).

The rationale for this separation becomes clearer when examining the underlying
key material. Of all derived keys, *only two* are strictly necessary for enforcing
note ownership: the nullifier key $\nk$, used to derive nullifiers, and the
authorization key $\ak$, used to derive the randomized spend validation key.
Both are known only to the note owner and supply as secret witnesses in the
SNARK proof.

In Zcash today, a shielded payment address binds together $(\ak, \nk)$ and
additionally includes $\ivk$ for incoming note detection. Tachyon instead
decomposes this structure into a payment key $\pk = H(\ak, \nk)$ and a separate
transmission key managed entirely by the payment protocol. This significantly
simplifies the shielded protocol’s key architecture by removing functionality
unrelated to spend authorization.

> Among the main [security properties](https://zcash.github.io/orchard/design/nullifiers.html#security-properties),
> Tachyon shielded protocol needs to uphold Ledger Indistinguishability, 
> Balance, Note Privacy, Note Privacy (OOB), Spend Unlinkability (but attackers access
> restricted to only payment key).
> Full Spend Unlinkability (attacker with $\ivk$ access) and Faerie Resistance are now
> the responsibilities of the payment protocol.
> Security analysis on a more [comprehensive list](https://github.com/daira/zcash-security) of properties is outside our scope.

This separation[^reproduce-orchard] yields several benefits:
a narrower and more manageable scope for shielded pool upgrades,
cleaner isolation of security assumptions for auditing,
greater flexibility in exploring payment protocol designs while preserving a stable
shielded core, and the ability to develop sub-protocols in parallel.
More broadly, we believe this separation of concerns enables Tachyon, and future
post-Tachyon upgrades, to evolve more rapidly while supporting more modular
security analysis.

[^reproduce-orchard]: One way to convince yourself that such separation works is
    to reproduce all of Orchard functionalities in this decoupled framework. We
    leave it as a homework exercise for the readers. 
    As a hint, your diversified address now may look like
    $\mathsf{addr} := (\pk, \tk)$ where
    $\pk = \mathsf{Com}(\ak, \nk; \rpk)$ is the diversified payment key,
    $\tk = (d, pk_d)$ is the diversified transmission key.
    Your $\ivk = \mathsf{ToScalar}(\PRF_\sk([9]))$ can now be directly
    derived from master spending key $\sk$, rather than meandering through
    layers of indirect derivation (similarly for outgoing viewing key).

## Shielded Protocol {#shielded}

We incrementally cover the whole Tachyon shielded protocol in this section.

> Note: in practice, all derivation functions (e.g., hash, KDF, XOF, and Derive)
> should be domain-separated;
> we omit this detail here for simplicity of presentation.

### Payment Key {#payment-key}

As explained [above](#decouple), Tachyon shielded protocol only expects an
authorization key $\ak$ from a re-randomizable signature scheme[^redpalla] and
a nullifier key $\nk$. While both keys *should* be derived from a master spending
key as per [ZIP-32](https://zips.z.cash/zip-0032), the concrete derivation path
is specified by wallet standards. The transfer proofs in shielded transaction only
use them directly as secret witnesses to further derive public values including
(randomized) spend validating key $\rk$ and nullifier $\nf$, but never constrain
their derivations. The shielded protocol only mandates that they are
indistinguishable from randomly sampled keys.
    
[^redpalla]: Tachyon sticks with $\mathsf{RedPallas}$, a Schnorr-based signature
    over the Palla curve supporting re-randomization, as in Orchard.
    See our [approach](#pq-rerand) when fully migrating to post-quantum world.

<P align="center">
  <img src="./assets/tachyon_keys.svg" alt="tachyon_keys" />
</p>

The payment key $\pk = H(\ak, \nk)$ represents a note owner.
The hash-based derivation from the $(\ak, \nk)$ tuple provides a succinct owner
field in a note and offers
[quantum recoverability](https://zips.z.cash/draft-ecc-quantum-recoverability) today.
Publicizing $\ak$, a Schnorr signing key, to senders who might have future access
to a quantum computer exposes the user 
["Harvest Now, Decrypt Later"](https://en.wikipedia.org/wiki/Harvest_now%2C_decrypt_later)
risk.

Spend authorization follows the same construction as in Orchard.
The authorization key pair satisfies the DLog relation $\ak = [\ask]\,\G$, and
can be re-randomized into an unlinkable key pair using a randomizer $\alpha\in\F$.
Transactions are signed using the re-randomized signing key $\ask + \alpha$.
The resulting signature is unlinkable to the original spending authority,
while remaining verifiable against the randomized spend validating key $\rk$,
defined as:

$$
\rk = \ak + [\alpha]\,\G = [\ask + \alpha]\,\G
$$

### Note {#note}

A tachyon note is a tuple:

$$
\mathsf{Note}^\mathsf{Tachyon} := (\pk, v, \psi, \rcm)
$$

where $\pk$ is the [payment key](#payment-key), $v$ is the value of the note,
$\psi$ is pseudo-random note identity that binds to the note nullifier value
as an input to its derivation, and $\rcm$ is a random commitment trapdoor[^cm-psi].
In contrast to Sapling/Orchard, the note commitment in Tachyon
$\cm = \mathsf{Com}(\pk, v, \psi; \rcm)$ is purely based on symmetric primitives[^cm].
Thus, Tachyon doesn't require extra enforcement on $\rcm$ derivation on wallets
to achieve quantum recoverability
like [Orchard does](https://x.com/zkDragon/status/2026047830759182672).

[^cm-psi]: Pseudorandom values like $\psi$ and $\rcm$ should be
    deterministically derived from the wallet master key via secure KDF to avoid
    poor operational entropy. The derivation should be standardized.

[^cm]: Sapling and Orchard uses variants of the vector Pedersen commitment,
    which relies on DLog hardness. We choose Sponge-based Hash constructed from
    algebraic permutation Poseidon.
    
### Evolving Nullifier {#nf}

Readers should refer to Sean's 
[post](https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/)
and the [short note [BM25]](https://eprint.iacr.org/2025/2031.pdf) for a
detailed motivation and an overview of Tachyon's evolving nullifiers.

A scaling Zcash produces more note commitments and nullifiers, both accumulating
in the shielded pool. The commitment set grows on disk, but luckily storage is cheap.
The nullifier set becomes the bottleneck: every transaction must check that its
inputs' nullifiers have never appeared before, which forces consensus nodes to
keep the whole set in memory *on the critical path*.
At Visa-level throughput, this nullifier state would grow by an [unattainable
500 GB per day](https://youtu.be/D51JV1ItMGE?si=5i5ByeKYg6fhf7U8&t=201).

Tachyon offloads most of this check to the user. The consensus node retains only
nullifiers from the most recent blocks; the user supplies an *exclusion proof*
attesting that their nullifier does not appear anywhere in the older history.
This proof must be kept current as each new block lands, which Tachyon achieves
incrementally via [proof-carrying data (PCD)](https://tachyon.z.cash/ragu/concepts/pcd).
Since constantly scanning blocks and refreshing proofs is onerous, users can
outsource the task to an *oblivious syncing service (OSS)*. However, updating
an exclusion proof requires knowing the nullifier value, and a nullifier revealed
to the syncing service let it trace the eventual spend of that note — a disastrous
privacy leak. Tachyon resolves this by letting nullifiers **evolve across
epochs**: the value a user shares with the OSS in one epoch is unlinkable to the
value revealed at spend time. This breaks a long-standing Zcash invariant:
each note has only *one* nullifier that is globally unique value in the pool.
As a result, Tachyon requires both a new nullifier derivation and a new
double-spending prevention mechanism.


> **<a id="philosophy">Philosophy:</a> Client-side Validation**
> ([CSV](https://eprint.iacr.org/2025/068)).
>
> Tachyon's scaling approach rests on one principle: move validation off the
> critical path of consensus and onto the client wherever possible. As a
> blockchain scales, the burden on consensus nodes grows along every axis —
> compute, memory, storage, and bandwidth. The remedy is to let the transacting
> client prove its own correctness and leave consensus only cheap verification.
> This principle guides many design decisions beyond our prunable nullifiers.

The ideal functionality for an epoched nullifier is a deterministic function

$$\nf_e = \mathsf{KDF}(\nk, \psi, e)$$

whose outputs are indistinguishable from random bytes. Such an $\nf_e$ binds to
both the spending authority (via $\nk$) and the underlying note (via its
per-note trapdoor $\psi$), while remaining unlinkable across epochs to anyone
without $\nk$.

Two additional constraints shape the choice of $\mathsf{KDF}$:

- **Constrained evaluation.** The wallet should be able to delegate $\nf_e$
  computation for a *range* of epochs to an OSS while keeping every epoch
  outside that range opaque to the service. Without this, outsourcing
  block-scanning would cost the user their privacy.
- **Circuit efficiency.** The spend proof constrains $\nf_e$ in-circuit, so the
  construction should be circuit friendly.

A natural abstraction for the first constraint is the *constrained PRF*
[[BW13]](https://eprint.iacr.org/2013/352.pdf): from the master key one can
derive a constrained key that enables the evaluation of the PRF at a certain
subset of the input domain and nowhere else. Section 3.3 of [BW13]
explains the *prefix-fixing* family realized by the seminal 
[[GGM84] PRF](https://crypto.stanford.edu/pbc/notes/crypto/ggm.html)
which is sufficient for us.

#### GGM-based Nullifier {#nf-ggm}

Let $\bits{e} = (e_0, e_1, \ldots, e_{\ell-1}) \in \{0,1\}^\ell$ be the
binary expansion of $e$ (so $e_0$ is the most significant bit).
Let $G: \{0,1\}^s \rightarrow \{0,1\}^{2s}$ be a length-doubling PRG, split into
halves $G(x) = G_0(x)\, \|\, G_1(x)$. In practice, we can instantiate $G_0(x) =
H(0 \| x), G_1(x) = H(1 \| x)$ with some hash function $H$ modeled as random oracle.
The GGM PRF walks down a binary tree from a seed, branching left or right at each
level according to the input bits:

$$
F^{\mathsf{GGM}}_{\seed}(e) :=
G_{e_{\ell-1}}\!\Bigl( \cdots G_{e_1}\!\bigl( G_{e_0}(\seed) \bigr) \cdots \Bigr)
$$

The Tachyon nullifier instantiates this GGM PRF with a per-note seed bound to
both the user's nullifier key $\nk$ and the note's trapdoor $\psi$:

$$
\nf_e = F^{\mathsf{GGM}}_{\PRF_\nk(\psi)}(e) =
G_{e_{\ell-1}}\!\Biggl( \cdots G_{e_1}\!\Bigl( G_{e_0}(\PRF_\nk(\psi)) \Bigr) \cdots \Biggr)
$$

A few properties worth highlighting:

- **Per-note and owner-bound**: Only the holder of $\nk$ can compute the seed
  $\PRF_\nk(\psi)$, so only the owner can derive $\nf_e$. The seed also
  depends on the per-note $\psi$, so different notes live in completely
  disjoint GGM trees: a prefix key delegated for one note grants the OSS
  *nothing* about any other note's nullifiers.[^cross-note-attack]
- **Forward-only**: Each $G_b$ is one-way — from any internal node one can
  walk further down, but cannot recover its parent or reach a sibling
  subtree. A partially-walked node thus lets its holder reach every leaf
  below it, and nothing else.
- **Provably pseudorandom**: For uniform $\nk$, the seed $\PRF_\nk(\psi)$ is
  pseudorandom by PRF security; GGM then yields pseudorandom $\nf_e$ over
  any distinct epoch queries, sequential or even adversarially chosen.
- **Circuit efficient**: One PRF call to derive the seed plus $\ell$ PRG
  calls down the tree — a single $\nf_e$ costs $\ell + 1$ hashes when both
  the PRF and $G_0, G_1$ are instantiated with Poseidon.

[^cross-note-attack]: Had we instead used a note-independent
    $k_e = F^{\mathsf{GGM}}_\nk(e)$ and folded $\psi$ into a final
    $\nf_e = \PRF_{k_e}(\psi)$, the same $k_e$ would be shared across every
    note the user owns. An OSS holding a delegated $k_e$ for note $A$ could
    then compute $\nf_e^{(B)} = \PRF_{k_e}(\psi_B)$ for any other note $B$
    whose $\psi_B$ it knows — and since $\psi$ is sender-shared via the
    payment protocol, a colluding sender-OSS would learn the epoch-$e$
    nullifier of every note it ever sent the user. Worse, *future*
    delegations would retroactively unmask past spends: receiving $k_{e+1}$
    later lets the attacker compute $\PRF_{k_{e+1}}(\psi_A)$ for a note $A$
    already spent at epoch $e+1$ and find the match in the on-chain
    nullifier history. Binding the GGM seed itself to per-note $\psi$ severs
    both attacks: each note has its own tree, and a delegated subtree key
    cannot cross GGM trees.

The forward-only property is exactly what makes OSS delegation work. For any
prefix $\mathbf{v}$ of length $d$, the internal node
$k_\mathbf{v} := G_{v_{d-1}}(\cdots G_{v_0}(\seed) \cdots)$ is a
*prefix-constrained key*: its holder can derive $\nf_e$ for every $e$ in
*this note's* tree whose top $d$ bits equal $\mathbf{v}$, and learns nothing
about any other $\nf$ — including any nullifier of a *different* note, whose
tree is rooted at a different seed.

Concretely, in a 3-bit epoch space, delegating the range
$[2, 4) = \{010, 011\}$ for some note amounts to handing the OSS the depth-2
prefix key

$$k_{01} = G_1(G_0(\seed)), \qquad \seed = \PRF_\nk(\psi)$$

from which it forward-walks $G_0$ and $G_1$ to obtain $k_{010}$, $k_{011}$ and
thus $\nf_2, \nf_3$ for that note. Because $G$ is one-way, the OSS cannot
reach any node outside the `01` subtree, so future revelations of
$\nf_4, \nf_5, \ldots$ remain unlinkable to anything it has seen.

When the requested range does not align to a single subtree, it is delegated as
a *set of prefix keys*: one per maximal subtree contained in the range.
Delegating $[0, 7) = \{0, 1, \ldots, 6\}$, for example, requires three subtree
roots (all under the same per-note $\seed$):

$$\bigl\{\; G_0(\seed),\quad G_0(G_1(\seed)),\quad G_0(G_1(G_1(\seed))) \;\bigr\}$$

covering $\{0,1,2,3\}$, $\{4,5\}$, and $\{6\}$ respectively. In the worst case
an arbitrary range in an $\ell$-bit epoch space needs $O(\ell)$ prefix keys, so
the delegated key material is variable-size.


<P align="center">
  <img src="./assets/ggm.svg" alt="ggm" />
</p>

#### Nullifier Security {#nf-sec}

We now examine how the evolving nullifier upholds the security properties [carved
out](#decouple) for the shielded protocol. Readers can safely skip this
section and come back later since the analysis refers to concepts introduced
in later sections.

**Balance.** Only the holder of $\nk$ can compute any $\nf_e$, since the GGM
seed $\PRF_\nk(\psi)$ requires it. The spend circuit pins both $\nf_e$ and
$\nf_{e+1}$ to a deterministic function of the note and epoch, so a note has
exactly one valid nullifier per epoch and no freedom to mint a fresh value that
dodges a past spend. Double-spending is then ruled out by two complementary
checks that [leave no gap](#consensus-rule). The [spendability proof](#spendability)
certifies the nullifier absent throughout pruned history up to its anchor, and
consensus rescans the recent window (the current epoch and the one before) that
the proof does not reach. Publishing both $\nf_e$ and $\nf_{e+1}$ extends this
across the epoch boundary, so a note cannot be spent twice even as $e$ advances.

**Note Privacy.** The adversary is a keyless third party reading the whole
on-chain transaction, including any in-band memo. The shielded footprint, namely
the commitment $\cm$ (hidden by $\rcm$), the spend's revealed nullifiers
(pseudorandom by GGM PRF security), the rerandomized $\rk$, and the hiding $\cv$,
reveals none of $\pk$, $v$, $\psi$. The in-band memo is payment-protocol data
that the shielded protocol carries opaquely and never parses (committed only to
`da_digest`), so its secrecy rests on the payment protocol's encryption, not on
the shielded core.

**Note Privacy (OOB).** Here the note plaintext travels out of band rather than
as an in-band ciphertext, so the adversary of concern is the sender, who learns
$\pk, v, \psi, \rcm$ but never the recipient's $\nk$. Because every $\nf_e$ hangs
off the secret seed $\PRF_\nk(\psi)$, knowledge of the note plaintext alone does
not let the sender, or anyone it colludes with, recognize the recipient's
eventual spend on chain or link it back to the note it sent.

**Spend Unlinkability.** Across epochs the $\{\nf_e\}$ of a fixed note are
mutually pseudorandom to anyone lacking $\nk$, by GGM PRF security, and this
holds even for the pair $\nf_e, \nf_{e+1}$ revealed together at spend. An OSS
[delegated](#nf-ggm) a prefix key for a range $[e_1, e_2)$ can refresh exclusion
proofs there, but the tree's forward-only structure prevents it from reaching
any leaf beyond the range, in particular the spend leaf, since
[syncing stops at $e-1$](#txflow). To an attacker holding only the on-chain
$\cm$, the spend is unlinkable to it, since the two draw on disjoint randomness
($\rcm$ versus the GGM seed). The stronger flavor of spend unlinkability, under
incoming viewing key access, falls to the payment protocol, since Tachyon's
shielded core has no $\ivk$.

**Faerie-gold via the wallet.** In Orchard, Faerie-gold resistance comes from
binding each new note's $\rho$ to the unique nullifier of an input note.
Tachyon's [tachygram accumulator](#acc) does not assign notes a canonical
position, so the shielded protocol cannot enforce that binding. A malicious
sender could in principle pick colliding $\psi$ values across two notes sent
to the same recipient, where only one of them is spendable. We push detection
to the recipient's wallet: upon receiving a note, the wallet computes $\nf_e$
at the current epoch and rejects the note if it collides with any other note
it currently holds. Since a wallet's note set is small, the check is cheap;
the knowledge that compliant wallets will reject such collisions is enough to
deter the attack.

### Tachygram Accumulator {#acc}

All shielded pools in Zcash today maintain two separate accumulators:
a note commitment Merkle tree for efficient inclusion proofs and a nullifier
set with constant-time membership queries for exclusion testing.

Tachyon instead uses a single cryptographic accumulator whose members are
encoded as roots of a polynomial, so that both membership and non-membership
tests reduce to a single evaluation query.
Conveniently, Tachyon's PCD proof system natively and cheaply supports
evaluation queries against *online polynomial oracles*[^polyoracle].
Because the accumulator is universal[^universal], it need not distinguish
nullifiers from note commitments: a single accumulator collects
indistinguishable 32-byte blobs, each a **tachygram**, that can be either a
nullifier *or* a commitment.

$$
\tg := \begin{cases}
    \cm = \mathsf{Com}(\pk, v, \psi; \rcm) &\quad\text{in Output actions}\\
    \nf_e = \mathsf{KDF}(\nk, \psi, e) &\quad\text{in Spend actions}
\end{cases}
$$

[^polyoracle]: Ragu PCD proof, through [reduction of
    knowledge](https://eprint.iacr.org/2022/009), reduces down to a list of
    evaluation claims of multiple opening points on multiple polynomials.
    These claims are then
    [folded](https://tachyon.z.cash/ragu/protocol/core/accumulation/pcs.html)
    into a single running aggregated claim.
    Ragu expose the capability to fuse online/application-time polynomial
    queries into the proof system directly, without encoding the evaluation
    through the constraint system which can be expensive.
    This is spiritually similar to
    [lookup argument](https://zcash.github.io/halo2/design/proving-system/lookup.html)
    enforced as part of the PIOP relation rather than through the circuit.
    
[^universal]: In [crypto literature](https://eprint.iacr.org/2018/1188.pdf),
    a universal accumulator is dynamic (supports insertion and removal) and
    supports both membership and non-membership proofs.

The accumulator is the commitment to a polynomial $f^\tg(X)$:

$$
\tgacc = \mathsf{Com}(f^\tg(X)) = \mathsf{Com}( \prod_i{(X - \tg_i)} )
$$

The key properties of this universal accumulator:

- Membership is enforced via $f^\tg(x) = 0$, non-membership via
  $f^\tg(x) \neq 0$. Both tests are insensitive to multiplicity, so this is a
  *multiset* accumulator: a tachygram appearing $m$ times contributes the factor
  $(X - \tg_i)^m$, but a single occurrence already certifies membership.
  - We do not deduplicate. In honest operation every tachygram is a distinct
    pseudorandom blob, so multiplicity exceeds one only with negligible (or
    adversarial) probability; and since (non-)membership ignores multiplicity,
    such cases are harmless. 
- Members are *unordered*: a multiset commitment, not a vector commitment.
- <a id="union">**Multiset union**</a>
  is polynomial multiplication, yielding a product accumulator
  $f^\tg(X) \cdot g^\tg(X)$ (unconditionally, with no disjointness precondition);
  multiset difference is division, yielding a quotient $\frac{f^\tg(X)}{g^\tg(X)}$
  whenever the divisor is contained, and failing with a remainder otherwise.
  - A union can be tested via $p(r) \iseq f(r) \cdot g(r)$ at a random point
    $r\sample\F$.

We emphasize a subtlety in the security of this polynomial-based accumulator.
Since some polynomial commitment schemes are not degree-binding (KZG, Pedersen,
etc.), the (non-)membership test is complete and sound only if the commitment
is honestly computed.
Concretely, consider a set of 10 items with its correct accumulator $\acc$.
An attacker appends a malicious item $\tg_{11}$ and produces an $\acc'$
indistinguishable from a normal Pedersen commitment. Since $\acc'$ does not
bind the degree of the committed polynomial, a verifier could be fooled into
accepting a membership test for $\tg_{11}$. Similarly, an attacker given an
untrusted accumulator could drop genuine members from the polynomial. These
attacks are impossible in Tachyon because every $\tgacc$ is verified by
consensus validators using the technique [below](#acc-correct).

#### Checking Accumulator Correctness {#acc-correct}

Our goal is to check the correctness of the accumulator value $\tgacc$ given
a public list of $\set{\tg_i}$ *without expensive recomputation*.

The solution is batch verification via a randomized point check.
The verifier samples a random $r\sample\F$ and invokes the PCS evaluation
procedure on the (commitment, point, evaluation) claim $(\tgacc, r, y_r)$, where
$y_r = \prod (r - \tg_i)$ is computed locally.
Naturally, this proof can be made non-interactive with Fiat-Shamir.
Notably, the verifier performs only cheap field operations, avoiding the group
operations that recomputing the commitment would require (for Pedersen, KZG, or
Bulletproof PCS).


### Tachyon Transaction {#tx}

![tachyon_tx](./assets/tachyon_tx.svg)

Each block contains one or more transactions. Each transaction has a `txid`,
which commits only to its _effecting data_
([ZIP-244](https://zips.z.cash/zip-0244)) and thus serves as the stable
identifier for p2p gossip, and a `wtxid`
([ZIP-239](https://zips.z.cash/zip-0239)), which additionally commits to the
potentially malleable authorization data.
Each transaction optionally contains a bundle of transfers from each pool:
JoinSplit for Sprout (soon deprecated), Spend/Output for Sapling, Action for
Orchard, and now Tachyon Action for the new Tachyon pool.

A **Tachyon Action transfer** either spends an old note or creates a new one.
Whether a spend or an output, its *Action description* is uniformly represented
by a pair $(\rk, \cv)$, where $\rk$ is the randomized spend validating key, whose
derivation *binds to the underlying note*, and $\cv$ is a blinding commitment to
the net value (negative for a spend).
Unlike Sapling and Orchard, the tachygrams (nullifier or commitment) are left
out of the description, because evolving per-epoch nullifiers are no longer
static. We instead bind the note to $\rk$ through its randomizer $\alpha$:

$$
\begin{cases}
\rk = [\ask + \alpha]\,\G \\
\alpha = \PRF(\cm \| \theta)  \quad\theta\text{: arbitrary entropy}
\end{cases}
$$

The Tachyon bundle inside a transaction carries a sequence of Action
descriptions together with the net balance of all action transfers
$v^{\mathsf{bal}}$, proven by a *binding signature* $\sigma^{\mathsf{bind}}$ as
in Sapling/Orchard.

<details>
<summary>Recall: How binding signature works.</summary>

The net value commitment $\cv$ in every action description is Pedersen-committed:

$$
\cv = [v]\,\G + [\rcv]\,\H
$$

where $\rcv$ is the blinding factor and $\H$ is an independent group generator.

By the homomorphic property of Pedersen commitments, the verifier can sum the
$\cv$ in a bundle to obtain $\sum_i{\cv_i}$, itself a blinding commitment to the
net balance $v^\mathsf{bal}$ with blinding factor $\bsk = \sum_i{\rcv_i}$:

$$
\sum_i{\cv_i} = [\sum_i{v_i}]\,\G + [\sum_i{\rcv_i}]\,\H
= [v^\mathsf{bal}]\,\G + [\bsk]\,\H.
$$

To verify the net balance, the validator reconstructs a discrete-log public key

$$
\bvk = \sum_i{\cv_i} - [v^\mathsf{bal}]\,\G,
$$

and then verifies a Schnorr signature $\sigma^\mathsf{bind}$ produced under
$\bsk$. Effectively, the signature serves as a proof of knowledge of the secret
scalar $\bsk$ behind the public key $\bvk$.

</details>

Before describing the stamp, we name a recurring object it relies on: the
<a id="spendability"></a>**spendability proof**.
To spend a note, its owner must convince consensus that
the note is *currently spendable* — that its commitment was once added to the
pool (*inclusion*) and that, in every epoch since, the note's nullifier *for that
epoch* has stayed absent (*exclusion*).
Since the pool retains only recent tachygrams and prunes the rest
([above](#nf)), neither fact is checkable from a node's live state; the spender
instead carries an updateable PCD proof of both, taken relative to a particular
[anchor](#anchor) that pins a point in pool history. The proof can be constructed
as soon as the note's creation transaction lands in a block, and is thereafter
*lifted* forward with its anchor advanced over newer transactions.
The owner need not keep it perpetually fresh: lifting is usually a
retroactive syncing pass, run (or delegated to an OSS) only when a spend is
intended, to carry the proof up to the spending epoch. We defer the lifting
machinery (the [proof tree](#prooftree) and its steps) to a later section; for
now it suffices that every spend consumes a spendability proof anchored near the
chain tip when its transaction is published.

A **Tachyon Stamp** provides the PCD proof for the [Action statement](#statement)
along with its public inputs: a set of tachygrams $\set{\tg_i}$, their
accumulator $\tgacc$, and an anchor value from the [anchor chain](#anchor).
Alternatively, the stamp holds a `wtxid` reference to another transaction whose
stamp carries an aggregated PCD proof and the corresponding public inputs.
The accumulator is included to spare miners from recomputing it over all
tachygrams; instead, the correctness of $\tgacc$ is proven as part of the Action
statement using the [batched verification trick](#acc-correct).
The **stamp is updateable** in three main ways:
1. [**in-epoch anchor lift**](#in-e): advance the anchor within the same epoch,
updating the inclusion proof of Spend note commitments.
2. [**cross-epoch anchor lift**](#cross-e): advance the anchor into a new epoch,
which requires revealing a [new nullifier](#nf) and updating the spendability
proof (both the commitment inclusion and nullifier exclusion) of Spend notes.
3. [**bundle aggregation**](#aggregation):
a new aggregated transaction is created whose stamp
contains the union of tachygrams, the accumulator of that union, an anchor, and an
aggregated PCD proof. The stamps of all constituent transactions are replaced by a
reference to the aggregated transaction's `wtxid`.

> Note: an aggregated Tachyon bundle shares exactly the same format as a normal
> standalone bundle (a.k.a. a _Tachyon autonome_), and may even carry additional
> Action descriptions of its own. A purely aggregating bundle, by contrast,
> carries an empty Action list (hence no authorization signatures), a zero value
> balance, a trivial binding signature, and a stamp holding the aggregated proof
> and its proof data.
>
> The balance check and authorization signature verification (including the
> `SIGHASH` computation) are identical for every bundle, aggregated or standalone.
> The only difference is proof verification: an aggregated bundle verifies against
> the single stamp of the aggregated transaction, so its cost is amortized across
> all constituents and thus economically incentivized.

Importantly, each Action description is **associated with two tachygrams**, a
consequence of the evolving nullifiers. If a user proves only the nullifier
$\nf_e$ for the current epoch $e$, the epoch may advance to $e+1$ before the
transaction is picked up from the mempool. Since neither miners nor the OSS—the
latter responsible only for syncing past epochs, and never learning future
nullifiers, least of all at spend time—can unilaterally update the proof, the
transaction goes stale and requires further user input to refresh. This is poor
UX and a potential timing side-channel that leaks privacy. We therefore require
every spend action to reveal (and prove in circuit) the nullifiers for **both the
current and the next epoch**, leaving an ample buffer against this cross-epoch
race. To keep spend and output actions indistinguishable, we further require each
output action to publish a random dummy tachygram alongside its note commitment.

All non-malleable parts, collectively the *effecting data*, hash into a stable
identifier `txid`: a bundle commitment from each pool, their value balance
$v^{\mathsf{bal}}$, and encrypted memo bytes.
The Tachyon bundle commitment $\actacc$ is defined similarly to the tachygram accumulator:

$$
\actacc = \mathsf{Com}(\prod_i{(X - a_i)})
\quad\text{where }
a_i = H(\cv_i, \rk_i)
$$

All mutable parts (orange in the diagram) commit only to the `auth_digest`, and
hence transitively to `wtxid = txid || auth_digest`; only the stable parts
(green in the diagram) contribute to `txid`.

Specifically,

- `txid` commits to $(\actacc \| v^\mathsf{bal})$. Importantly, for the Tachyon
pool the memos are *not* effecting data and are therefore excluded from the
`txid` inputs.
- `auth_digest` commits to $(\set{\sigma^\mathsf{act}}, \sigma^\mathsf{bind}, \mathsf{stamp})$.
- an additional `da_digest` commits to the (optional) opaque memo bytes, which
are unconstrained (never parsed or interpreted) and thus have no effect on the
shielded protocol.


Finally, the Tachyon bundle carries a spend authorization signature for every
Action description, each signed over the `SIGHASH`, which commits to the same
transaction-wide effecting data (across all pools) used to derive `txid`[^txid-sighash].
Block space can additionally serve as a data-availability layer for arbitrary
payment-protocol data used in note transmission; the shielded protocol neither
interprets this data nor checks its correctness. As explained [later](#payment),
the payment protocol Tachyon targets keeps KEM key material (e.g., Orchard's
`epk`) out of band, which shrinks the in-band footprint, is quantum-safe from
day one, and leaves the format unchanged even through a full
[quantum upgrade](#pq).

[^txid-sighash]: `txid` and `SIGHASH` are domain-separated with different
    personalization strings, but they commit to the same effecting data.
    `SIGHASH` further incorporates a *SIGHASH type* byte, the `nConsensusBranchId`
    network-version identifier (e.g., NU5, NU6), and other consensus-level metadata.

### Anchor Chain {#anchor}

An anchor chain is a hash chain of **per-stamp** [tachygram accumulators](#acc).
Every stamp carries a $\tgacc$ committing to the tachygrams it introduces: those
of a single bundle for a standalone transaction (a *Tachyon autonome*), or the
union across many for an [aggregate](#tx). Each new stamp extends the chain by
hashing its accumulator into the running state:

$$
\tgst \leftarrow H(\mathsf{st^{tg}_{old}} \;\|\; \tgacc)
$$

<P align="center">
  <img src="./assets/anchor_chain.svg" alt="anchor_chain" />
</p>

The chain therefore advances at *sub-block, above-transaction* granularity: in a
block of transactions with all standalone Tachyon bundles it ticks once per
transaction. A stamp's $\mathsf{anchor}$ field may reference any node value
$\tgst$ in the chain, anchoring at a historical snapshot of the pool state.

Why anchor *per-stamp rather than per-block*, when the block is the unit of
consensus finality? The primary justification is that it minimizes validator
work, in alignment with our [philosophy](#philosophy). Each stamp already ships a
$\tgacc$ whose correctness is [batch-verified in circuit](#acc-correct), so a
validator merely hashes it into the chain. A per-block anchor would instead force
every validator to rebuild a block-wide accumulator from scratch: re-accumulating
every tachygram in the block, interpolating the product polynomial, and
committing it which involves an expensive multi-scalar multiplication for some PCS
choices. A secondary benefit of sub-block granularity is allowing note creation
and spend *in the same block* which enables true atomic swaps.[^swap]

[^swap]: Atomic swaps need the miner's cooperation. Better yet, the swap
    participants are themselves the block builder. Say Alice wants to swap her
    Sapling coin for Bob's Orchard coin. She builds her half with a validity
    proof but *no* authorization signature and sends it to Bob. Assuming the
    miner agrees to place it at the top of the next block, Bob can predict the
    exact anchor value that will exist right after her transaction is absorbed.
    Anchoring to that not-yet-realized point, Bob builds and fully authorizes the
    matching half and returns it to Alice, who then authorizes her own half and
    submits both. Alice is safe because her transaction is inert until Bob
    supplies his fully stamped and signed one; Bob is safe because Alice cannot
    publish his transaction alone — its proof verifies only if the anchor chain
    actually contains Alice's tachygrams ahead of his, and absent that the
    claimed anchor is a phantom that consensus rejects.

Per-stamp cadence also raises concerns about the cost of generating exclusion
proofs. To prove $\nf_e$ never appeared in epoch $e$, a user could naively show
$f^\tg(\nf_e) \neq 0$ against the accumulator of *every* stamp folded into the
chain that epoch. Instead, we leverage the [multiset union](#union) operation
on our accumulator polynomials to collapse the per-stamp checks into one.
The product of all stamp polynomials in an epoch is itself an accumulator over
all tachygrams of that epoch — the <a id="epoch-acc">*epoch accumulator*</a> $e(X)$:

$$
\underbrace{\circ \overset{f^\tg_1(X)}{\longrightarrow} \circ
\overset{f^\tg_2(X)}{\longrightarrow} \circ \overset{\ldots}{\longrightarrow} \circ}
_{\text{entire epoch: } e(X) = \prod_i{f^\tg_i(X)}}
$$

and $\nf_e$ is absent from the epoch exactly when $e(\nf_e) \neq 0$. Anyone
(typically an OSS) can prove that $e(X)$ is the correct product of the committed
$\tgacc_i = \mathsf{Com}(f^\tg_i(X))$ already fixed in the anchor chain by showing
$e(r) \iseq \prod_i{f^\tg_i(r)}$ using the proof system's cheap polynomial-oracle
queries[^polyoracle]. Since the queries are served natively by the folding scheme
and not through a step circuit, $e(X)$ may have degree as large as the SRS of the PCS
allows, independent of any per-PCD-step-circuit size limit. Admittedly, the prover
cost is still linear in the epoch's stamp count, but it is paid *once* and then
**amortized**. The epoch accumulator $e(X)$, carrying its correctness proof, can
now be reused by every unspent note to directly test the exclusion of their
epoched nullifiers.

This removes the per-stamp checks, but $e(X)$ still has degree linear in the
total number of tachygrams in the epoch $N$. We now present an optimization
trick that reduces the amortized per-nullifier cost to strictly sublinear.

#### Quadratic Residue Filters {#qr-trick}

> This subsection is a self-contained optimization; readers can safely skip it and
> continue to the [transaction life cycle](#txflow).

Our goal: let a user prove non-membership of $\nf_e$ over an *entire epoch* at
cost logarithmic in $N$, the number of tachygrams that epoch (equivalently, the
anchor-chain length).

The idea is **bucketing**. Suppose we sort every tachygram into one of $2^k$
buckets by a rule that (i) a nullifier can cheaply prove it follows and (ii)
splits the field evenly. Then $\nf_e$ falls into exactly one bucket, and it can
only ever collide with the tachygrams sharing that bucket. Thus, non-membership
across the whole epoch collapses to non-membership against a *single* bucket's
accumulator, holding only $\approx N/2^k$ entries. Taking $k = \log N - \log\log N$
shrinks each bucket to $\approx \log N$ entries while keeping the query $O(\log N)$.
Quadratic residues give us exactly such a rule.

**A number theory detour.** Over a prime field $\F$, the nonzero elements split
perfectly in half: the *quadratic residues* ($\QR$) and the *non-residues* ($\NQR$).
Both classes are cheap to test in-circuit:

- $x \in \QR$: supply the root $y$ as advice; one constraint $y^2 = x$.
- $x \in \NQR$: fix a public non-residue $c$ and supply $y$ with $y^2 = cx$,
  since multiplying by a non-residue flips the class:

$$
\begin{cases}
x\in\QR \iff c\cdot x \in\NQR \\
x\in\NQR \iff c\cdot x \in\QR
\end{cases}
$$

A **QR filter** is one such split with a random offset: draw $R \sample \F$ and
classify $x$ by whether $x + R$ is a residue. A random offset cuts the field
roughly in half, and $k$ independent offsets $R_1, \ldots, R_k$ tag every element
with a $k$-bit **QR profile** $\v{b} = (b_1, \ldots, b_k) \in \{0,1\}^k$, where
$b_j = 1$ iff $x + R_j \in \QR$ (written $x \in \QR_{R_j}$) and $b_j = 0$
otherwise. The $k$ filters together sort the field into $2^k$ disjoint buckets of
roughly equal size.

<a id="batch-qr">**Batched QR Test.**</a> Given the vanishing polynomial over
some elements $f(X)=\prod_i{(X - x_i)}$, we can batch-test that all elements are
QR, namely $\forall x_i \in \QR$, as follows:

- Prover interpolates all QR pairs $(x_i, y_i)$ into a polynomial $g(X)$ where
$g(x_i) = y_i$ and $x_i = y_i^2$
- Prover computes $h(X)=\frac{g(X) - X}{f(X)}$ and sends commitments to $g(X)$
and $h(X)$ to the Verifier
  - Observe that the numerator $g(X) - X$ vanishes over all $x_i$, thus must
  perfectly divide the vanishing polynomial $f(X)$
- Verifier samples a random $r\sample\F$, and test: $g(r) - r \iseq f(r)\cdot h(r)$

**Building the buckets (once, by the OSS).** Fix $R_1, \ldots, R_k \sample \F$ at
system startup. Conceptually, the buckets are the leaves of a binary tree built
by recursively splitting the epoch accumulator by each filter. Splitting
$e(X) = \prod_{j=1}^N (X - \tg_j)$ by $R_1$ gives

$$
\begin{cases}
q_0(X) = \prod_{\tg_i\in\NQR_{R_1}}{(X - \tg_i)}\\
q_1(X) = \prod_{\tg_i\in\QR_{R_1}}{(X - \tg_i)}\\
e(X) = q_0(X) \cdot q_1(X)
\end{cases}
$$

so $q_1$ gathers the tachygrams passing the $R_1$ filter and $q_0$ its
complement; bisecting each by $R_2$ gives four, and so on:

$$
\begin{cases}
q_{00}(X) = \prod_{\tg_i\in\NQR_{R_2} \,\cap\, \NQR_{R_1}}{(X - \tg_i)}\\
q_{10}(X) = \prod_{\tg_i\in\QR_{R_2} \,\cap\, \NQR_{R_1}}{(X - \tg_i)}\\
q_0(X) = q_{00}(X) \cdot q_{10}(X)
\end{cases}
\quad
\begin{cases}
q_{01}(X) = \prod_{\tg_i\in\NQR_{R_2} \,\cap\, \QR_{R_1}}{(X - \tg_i)}\\
q_{11}(X) = \prod_{\tg_i\in\QR_{R_2} \,\cap\, \QR_{R_1}}{(X - \tg_i)}\\
q_1(X) = q_{01}(X) \cdot q_{11}(X)
\end{cases}
$$

After $k$ filters we reach $2^k$ leaves, where leaf $q_{\v{b}}(X)$ holds exactly
the tachygrams of profile $\v{b}$.

In practice the OSS never splits top-down. It keeps the $2^k$ bucket accumulators
live and *streams* tachygrams into them: as each new stamp lands, it computes
every tachygram's profile $\v{b}$ (its $k$ QR bits) and folds the factor
$(X - \tg)$ into the matching leaf $q_{\v{b}}$. Internal product nodes are formed
bottom-up only when a decomposition proof calls for them. Maintaining the buckets
costs $O(kN)$ linear-factor multiplications across the epoch, amortized over all
users and all nullifiers.

<P align="center">
  <img src="./assets/qr_trick.svg" alt="qr_trick" />
</p>

With the buckets maintained, a user proves $\nf_e$ absent from the *entire epoch*
in three parts:

1. **Profile.** Compute $\nf_e$'s QR profile $\v{b}$ ($k$ squaring constraints)
   pinning down the single leaf $q_{\v{b}}$ it could possibly belong to.
2. **Leaf non-membership.** Test $q_{\v{b}}(\nf_e) \neq 0$ against that one leaf,
   of expected degree $N/2^k$.
3. **Path decomposition.** Certify that $q_{\v{b}}$ is genuinely the
   profile-$\v{b}$ bucket of the epoch accumulator $e(X)$, by walking the
   root-to-leaf path and checking, at each level $j$, two things:
   - *product relation*: the on-path parent equals the product of its two children,
   tested at a random point as in the [accumulator correctness check](#acc-correct);
   - *sibling QR purity*: the *off-path* sibling is pure in its QR class with
     respect to $R_j$: a single [batched QR test](#batch-qr), applied directly for
     a $\QR$ sibling or to $c\cdot(\cdot)$ for an $\NQR$ one.[^sibling]

[^sibling]: Why the sibling test, and why only one per level? The product checks
    alone are not enough: a cheating OSS could hide a tachygram equal to $\nf_e$
    by misfiling it into the *sibling* subtree, leaving the user's leaf test to
    wrongly report absence. Sibling purity shuts this down. If the off-path
    sibling provably holds only elements of the opposite class at level $j$, then
    every on-path-class element of the parent is forced into the on-path child —
    it has nowhere else to go. Chaining this down all $k$ levels pins every
    profile-$\v{b}$ element of $e(X)$, in particular any occurrence of $\nf_e$,
    into the leaf $q_{\v{b}}$. Hence $e(\nf_e) = 0 \iff q_{\v{b}}(\nf_e) = 0$, and
    a passing leaf test certifies epoch-wide exclusion. Constraining only the
    sibling is enough: purity of the off-path side already captures all
    on-path-class elements, and a stray wrong-class element that leaks *into* the
    on-path child can at worst make an honest exclusion proof fail (a false
    positive), never admit a double-spend (a false negative).

The decomposition certifies $q_{\v{b}}$ only *relative to* $e(X)$. Full soundness also
needs $e(X)$ to be canonical, the correct product of the per-stamp $\tgacc_i$
committed in the anchor chain, which is the separate
[epoch-accumulator correctness](#epoch-acc) proof from above.

**Cost.** Each level adds one product check and one batched QR test, each settled
by $O(1)$ random-point evaluations, so the path is $O(k)$; the leaf test adds work
proportional to its degree $N/2^k$. Setting $2^k = N/\log N$, i.e.
$k = \log N - \log\log N$, balances the two — leaves hold $\approx \log N$
tachygrams and the path is $\approx \log N$ levels deep — for an $O(\log N)$
per-nullifier proof, strictly sublinear. (Pushing $k$ all the way to $\log N$
would shrink leaves to $O(1)$, but the $O(k)$ path cost still dominates at
$O(\log N)$ while the bucket count doubles, so nothing is gained.) This
per-nullifier cost sits *on top of* the OSS's one-time epoch work: maintaining the
buckets ($O(kN)$) and proving $e(X)$ canonical. Both the path-decomposition proofs
(shared by everyone whose nullifier lands in the same bucket) and the $e(X)$
proof (shared by all) are paid once and amortized across the epoch.

### Transaction Life Cycle {#txflow}

1. **Select notes, delegate syncing.** The wallet picks the input notes to spend
and the output notes to create, fixing the target spending epoch $e$. For each
input note the bulk of the work is bringing its [spendability proof](#spendability)
up to date, from wherever it was last synced through epoch $e-1$. The wallet
delegates this to an [OSS](#nf), handing over the
[prefix-constrained keys](#nf-ggm) for exactly the epoch range to be synced. From
those, the OSS derives the note's per-epoch nullifiers $\nf_i$ and proves their
derivation in-circuit, while learning nothing about epochs outside the range,
especially the eventual spend leaf $\nf_e$.

2. **Lift the spendability proof.** Maintaining the proof means advancing its
[anchor](#anchor) along the anchor chain while preserving both halves of the
claim:
    - *Exclusion* is extended exactly as in the [anchor chain section](#anchor):
    for each epoch, the note's nullifier $\nf_i$ for that epoch is shown absent
    from the epoch accumulator $e(X)$ (cheaply, via the
    [QR-filter test](#qr-trick)), with no per-stamp membership tests.
    - *Inclusion* needs no re-proving of membership: the note's commitment was
    shown to lie in its creating stamp's accumulator *once*, and each lift simply
    extends that anchor to the new one along the chain's hash links.
    - Within an epoch this is an [in-epoch lift](#in-e); crossing a boundary is a
    [cross-epoch lift](#cross-e), which reveals the new epoch's nullifier and runs
    a PCD step binding $\nf_i$ and $\nf_{i+1}$ to the *same note* (matching the
    underlying commitment), so the chain of per-epoch exclusions cannot be spliced
    across notes. The OSS repeats this epoch by epoch up to $e-1$ and returns the
    synced proof.

3. **Generate the stamp.** With the synced spendability proof in hand, the wallet
folds it into a final proof step establishing the spend-specific facts: the
integrity of the current and next-epoch nullifiers $\nf_e, \nf_{e+1}$ (both
[derived from the same note](#nf)), the output commitments, and the correct
computation of the bundle accumulator $\tgacc$ over all revealed tachygrams (the
[batched correctness check](#acc-correct)).
The result is the [Tachyon stamp](#tx): the PCD proof for the
[Action statement](#statement) together with its public inputs
$(\set{\tg_i}, \tgacc, \mathsf{anchor})$. Revealing *both* $\nf_e$ and $\nf_{e+1}$
is what insures the transaction against the [cross-epoch race](#tx) while it
waits in the mempool.

4. **Authorize and bind.** Concurrent to the proving path of steps 1-3,
the wallet assembles the transaction body, computes the [`SIGHASH`](#tx) over
the effecting data, and produces:
    - a spend-authorization signature for every action, signed under the
    [re-randomized key](#payment-key) $\ask + \alpha$ and verifiable against the
    published $\rk$;
    - the net value balance $v^\mathsf{bal}$ and a single [binding signature](#tx)
    $\sigma^\mathsf{bind}$ over the value commitments.

5. **Mempool and aggregation.** The finished transaction enters the mempool as a
standalone *Tachyon autonome*. A miner (or any [aggregator](#aggregation)) may
then fold it together with others: it lifts every input stamp onto a common
anchor, takes the [multiset union](#union) of their tachygrams and the
accumulator of that union, and produces a single aggregated PCD proof. Each
constituent's stamp is replaced by a reference to the aggregate transaction's
`wtxid`, moving the tachygrams, anchor, and proof onto the aggregate.

#### Consensus Validation {#consensus-rule}

Of the consensus rules, the bundle balance check and authorization-signature
validation are unchanged from Orchard; only stamp verification is new.

**Stamp verification.** Given the published tachygrams $\set{\tg_i}$ (a spend
folds in $\nf_e$ and $\nf_{e+1}$, an output its commitment and a dummy), the
accumulator $\tgacc$, and the anchor, the validator:

1. confirms the `anchor` is a genuine node value in the consensus
   [anchor chain](#anchor);
2. verifies the stamp's PCD proof against $(\set{\tg_i}, \tgacc, \mathsf{anchor})$,
   i.e. the [Action statement](#statement). The statement internally enforces
   $\tgacc$'s consistency with the published $\set{\tg_i}$ (the
   [batched check](#acc-correct)), the integrity of the revealed nullifiers and
   output commitments, and the spendability of every spent note up to the anchor.

**The exclusion window (new double-spend rule).** A spendability proof attests
absence only up to its anchor, which lies back in epoch $e-1$. It says nothing
about the stretch from the anchor to the block our transaction lands in, where
the same note could already have been spent. Consensus closes this blind spot
with a live check: it keeps the tachygrams of recent blocks in memory and rejects
the bundle if a spent note's nullifier already appears there.

Because the anchor sits in $e-1$, the live check must also cover that epoch's
nullifier. Consensus tests all three against the window, which spans the
**current epoch and the one before it**:

- $\nf_{e-1}$ covers the tail of epoch $e-1$ past the anchor, the range that
spendability proof does not cover;
- $\nf_e$ covers the current epoch, catching a competing spend ahead of ours;
- $\nf_{e+1}$ guards the [cross-epoch race](#tx): if the transaction is mined only
  after epoch $e+1$ begins, $\nf_{e+1}$ is the value consensus checks as current
  then.

**Standalone vs. aggregated.** Balance, authorization, and the tachygram-window
check run per constituent bundle in both cases; only the stamp proof differs. A
standalone autonome is verified against its own stamp, whereas the constituents of
an [aggregated](#aggregation) bundle have had their stamps stripped and replaced
by a reference, so one PCD proof stands in for the whole batch and amortizes
verification across it.

### Proof Tree {#prooftree}

There are a couple of statements, the final Action statement will takes Spendable proof
as input, and folds in more standard Spend/Output-like statement including the accumulator
correctness proof.

This is where we describe the proof tree. we describe the data (header) and steps that updates
them where each distinct step is a circuit and we specify their statement.

#### In-epoch Lift {#in-e}

#### Cross-epoch Lift {#cross-e}

#### Aggregation {#aggregation}

#### Tachyon Action Statement {#statement}

## Payment Protocol {#payment}

As defined in the [motivation](#decouple), the payment protocol is in charge of
secure note transmission. This goal entails a full payment address design that
carries key material for incoming note detection, and infrastructure for fast
memo retrieval and spending witness construction.
The leading Tachyon-compatible payment protocol is being developed by the 
[ValarGroup](https://github.com/valargroup). Here we explain their high-level
architectures and design rationales.

```mermaid
flowchart TB
    subgraph _Payment Protocol_
    addr["**Address Creation**
    Payment link"]
    memo["**Memo Encryption**"]
    discovery["**Note Discovery**
    Incoming note detection + decryption"]
    check["**Spendability Check**
    Note spendability + Faerie Gold Prevention"]
    wit["**Witness Construction**
    OSS delegation, Stamp Generation, Authorization"]
    end

    subgraph _Shielded Protocol_
    transfer["**Shielded Transfer**"]
    end

    addr -- "`pk`" --> transfer
    memo -- "`(tag, memo)`" --> transfer
    transfer --> discovery --> check --> wit
```

The infamous[^sandblast] pain point around existing note transmission mechanism
is its shielded sync through **trial decryption** of memo distributed in-band.
We recommend [Roman's article](https://x.com/akhtariev/status/2044113751767691637)
for a detailed motivation and problem statement. Briefly, the linear scanning for
trial decryption leaks metadata and becomes infeasible for bandwidth-limited mobile
wallets as Zcash throughput scales.

[^sandblast]: Due to the linear cost of the shielded sync and an unprotective
    gas price, Zcash NU5 experienced a DOS attack, referred to as [the sandblasting
    attack](https://electriccoin.co/blog/a-look-back-nu5-and-network-sandblasting/),
    preventing wallets from syncing fast enough to access their funds.

One promising solution is a primitive called **Private Information Retrieval**
(PIR), which allows clients to query a database without the server learning anything
about client's query
(slides below by [Corrigan-Gibbs](https://www.youtube.com/watch?v=Jdzrf3im1gQ)).
With PIR, the recipient can generate a fresh `tag` for each incoming note and
send it to the sender as part of the full payment address. The sender then publish
the encrypted memo with the tag attached. These `(tag, encrypted_memo)` key-value
pair are stored in a PIR database for instant retrieval without privacy leakage.

<P align="center">
  <img src="./assets/pir.png" alt="pir_corrigan_gibbs" />
</p>

Modern single-server PIR requires $\Theta(N)$ preprocessing for faster online
response and lower per-query communication. Many performance metrics that we
care about scale with $\Theta(\sqrt{N})$, therefore care must be taken to curb
the database growth and their expected max sizes.
For our scope, the payment protocol at least maintains these PIR databases
(we use `key => value` for entry format):

- Epoched memo store: per-epoch `tag => memo` store, synced from the
[DA blobs](#tx) appearing on chain.
- Epoched tachygram store: per-epoch, 
[Hash-table-bucketed](https://github.com/valargroup/spendability-pir/blob/main/nullifier/README.md)
`H(tg)[:4] => tg (32 bytes) || blk_height (u32_le) || anchor_height (u32_le) || action_count (u8)` store,
keeping track of tachygrams and the block and anchor in which they appear.
- Encapsulation key store: global `H(ek) => ek` store for full ML-KEM encapsulation key
from its short digest.

### Full Payment Address {#address}

The [decoupling](#decouple) split the owner-binding payment key from the
note-transmission key, leaving the latter for the payment protocol to define. A
Tachyon full payment address is

$$
\addr = (\underbrace{\tag}_{\text{per-note}},\; \underbrace{H(\ek),\, \pk_d}_{\text{per-sender}})
\qquad
\begin{cases}
    (\ek, \dk) \leftarrow \mathsf{ML\text{-}KEM.KeyGen}()\\
    \pk_d = H(\ak, \nk; \rpk)
\end{cases}
$$

with three pieces:

- $\pk_d$, the *diversified payment key*: the owner $\pk$ a note commits to,
  randomized by a trapdoor $\rpk$ so that two payment keys of the same
  wallet are unlinkable. The decoupling lets us diversify the payment key
  independently of the transmission key.
- $(\ek, \dk)$, a fresh ML-KEM key pair sampled per sender, whose
  encapsulation key $\ek$ is the recipient's transmission key. Since $\ek$ runs
  to a few KB, the address carries only its short digest $H(\ek)$ and the
  full key is fetched on demand from the encapsulation-key PIR database.
- $\tag$, a per-note retrieval handle for looking up the encrypted memo by PIR.
  It is derived from per-sender key material so the recipient can predict it, as
  the [next section](#discovery) explains.

**Why not Orchard's DH transmission key.** Orchard derives a diversified
transmission key $[\ivk]\,g_d$ from a long-lived incoming viewing key. That is
not quantum-private: a sender holding (or one day acquiring) a quantum computer
could recover $\ivk$ from $g_d$ and $[\ivk]\,g_d$ by discrete log, and an $\ivk$
grants viewing access to *every* incoming note of the recipient, past and future.
This is a textbook
["harvest now, decrypt later"](https://en.wikipedia.org/wiki/Harvest_now%2C_decrypt_later)
exposure. ML-KEM avoids it entirely, since the shared secret is not recoverable
by a quantum computer and the symmetric encryption keyed under it is likewise
quantum-safe.

We sample the KEM key pair *deterministically*. Although
[ML-KEM's public `KeyGen`](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
is randomized, wallets call the derandomized `KeyGen_Internal(d, z)` with
$(d, z)$ derived from the HD-wallet master spending key, so the key pair is
reproducible from the seed rather than dependent on fresh operational entropy.

**No persistent viewing key.** Address diversification historically existed to
stop colluding senders from recognizing that two addresses belong to the same
recipient. Tachyon reaches full unlinkability with no long-lived $\ivk$ at all:
$\pk_d$ is randomized per address by $\rpk$, the $(\ek, \dk)$ pair is freshly
sampled per sender, and $\tag$ is fresh per note, so nothing persistent ties two
addresses together. This raises a question: with no standing viewing key to scan
against, how does a recipient still discover incoming notes efficiently? The
[next section](#discovery) answers it.

**Address PKI (optional).** Publishing only $H(\ek)$ already needs a lookup
service for the full $\ek$ (the encapsulation-key PIR store). One could push this
into a small PKI: map a short, stable handle $H(\addr)$ to the full address and
fetch it by PIR. The catch is that the $\tag$ component evolves per note, so such
a PKI can only register the *per-sender* portion $(H(\ek), \pk_d)$, never the
whole address.

### Note Discovery {#discovery}

With no persistent $\ivk$, a recipient cannot scan the chain by trial-decrypting
every memo under one viewing key. Discovery runs instead through the
[epoched memo store](#payment) keyed by $\tag$. The idea: the $\tag$ of the
$i$-th note from a given sender is derived deterministically from the per-sender
key material the recipient itself established (for instance $\tag_i = \PRF(s, i)$
for a per-sender seed $s$), so the recipient can *predict* exactly which tags to
expect and fetch only those by PIR, leaking nothing to the server.

Concretely, for each sender relationship the recipient tracks how many notes it
has already seen and an upper bound on how many that sender might have sent. To
sync an epoch, it regenerates the tags across that outstanding range, PIR-queries
the `tag => memo` store for each, and keeps the hits. There is no linear scan, no
trial decryption, and the server observes only oblivious queries.

**Which key decrypts.** Each $\tag$ belongs to exactly one sender relationship,
and that relationship fixes the recipient's decapsulation key $\dk$ (the private
half of the per-sender $(\ek, \dk)$). So a memo fetched by $\tag$ is decrypted
with the $\dk$ of the address under which that $\tag$ was issued. The sender
encapsulates to $\ek$ to obtain a shared secret and ships the ML-KEM ciphertext
beside the encrypted memo; the recipient runs $\mathsf{Decaps}(\dk, \cdot)$ to
recover the same secret and open it. The $\tag$ thus indexes both the memo and
the key that opens it.


### Note Spendability {#spendable}

Two questions gate whether a received note is worth keeping: is it actually
spendable, and is it free of Faerie-gold collisions.

**Spendability and witness data.** A note is spendable only if its commitment
was added to the pool and its nullifier has stayed absent since. Building and
maintaining the [spendability proof](#spendability) requires knowing, for any
tachygram, whether and where it appears on chain. The
[epoched tachygram store](#payment) supplies this privately: a
[hash-bucketed](https://github.com/valargroup/spendability-pir/blob/main/nullifier/README.md)
PIR database mapping a tachygram's short prefix to its full value and the block
and anchor heights where it landed. A wallet queries it to locate its note's
commitment (for inclusion) and to confirm its per-epoch nullifiers are absent
(for exclusion), all without revealing which tachygram it is asking about.

**Faerie-gold prevention.** Recall the shielded protocol
[pushes Faerie-gold detection to the wallet](#nf-sec): a cheap nullifier test
lets the recipient reject colliding notes. On receiving a note the wallet
computes its nullifier at a fixed reference epoch and checks it against the notes
it already holds. A malicious sender has two avenues, both blocked:

- *Reused $\psi$.* Two notes sent to one recipient with the same $\psi$ share
  every $\nf_e$; recomputing $\nf$ at the reference epoch exposes the collision,
  and the wallet keeps only one (only one was ever spendable).
- *Targeted collision.* Choosing a $\psi$ whose nullifier collides with that of
  an honestly created note is a second-preimage on the nullifier derivation,
  infeasible for a hash/PRF-based $\nf$.

### Witness Construction {#witness}

Witness construction is where the payment protocol's databases feed the shielded
protocol's [transaction life cycle](#txflow). Having discovered and validated its
notes, a spender:

1. pulls inclusion and exclusion data for each input from the
   [epoched tachygram store](#spendable), and delegates the heavy per-epoch
   [spendability syncing](#txflow) to an OSS through
   [prefix-constrained keys](#nf-ggm);
2. folds the synced spendability proofs into a [stamp](#tx), then authorizes and
   binds the bundle, as detailed in the [life cycle](#txflow).

In short, the shielded protocol defines *what* the witness must prove, and the
payment protocol supplies the data-availability and private-retrieval layer that
makes assembling it practical at scale.

## Quantum Safety {#pq}

Tachyon is designed to be **quantum-private today and quantum-sound after a
future upgrade**. These are different bars. Privacy must hold retroactively,
since an adversary can harvest today's chain and decrypt once it has a quantum
computer, so anything protecting privacy must already be post-quantum. Soundness
(no forgery, no theft) need only hold at spend time, so it can wait for a
coordinated network upgrade before quantum computers arrive.

**Quantum-private today.** Everything Tachyon publishes is either a hiding
commitment or encrypted under post-quantum symmetric/KEM crypto, so a future
quantum computer learns nothing about old transactions:

- the owner field $\pk = H(\ak, \nk)$ and the note commitment $\cm$ are
  hash/symmetric (Poseidon) commitments, hiding even against a quantum computer;
- nullifiers are PRF/hash outputs, pseudorandom against a quantum computer, so
  [spend unlinkability](#nf-sec) survives;
- memos travel under [ML-KEM](#address), post-quantum from day one.

The only discrete-log values on chain are the randomized validating key
$\rk = [\ask + \alpha]\,\G$ and the binding key. Re-randomization makes even
these quantum-*private*: a quantum computer can take the discrete log of $\rk$ to
recover $\ask + \alpha$, but $\alpha = \PRF(\cm \,\|\, \theta)$ is a fresh secret
mask, so the result is unlinkable to $\ask$ or to any other spend. Privacy and
unlinkability therefore already hold against a quantum adversary.

**Not yet quantum-sound.** What a quantum computer *can* do is forge. Recovering
$\ask + \alpha$ lets it sign a spend authorization, and breaking the
discrete-log-based PCD proof system lets it fabricate a spend proof for a note it
does not own. Together that is theft. Closing the gap needs two post-quantum
replacements, the only parts of Tachyon not yet quantum-safe:

1. a re-randomizable signature scheme, which has no efficient post-quantum
   analogue (Schnorr re-randomization is intrinsically discrete-log);
2. discrete-log-based address diversification, already sidestepped by the
   payment protocol's fresh per-sender $\ek$ (no $[\ivk]\,g_d$, see
   [above](#address)).

### PQ Signature Re-randomization {#pq-rerand}

Re-randomization buys unlinkability by publishing a fresh-looking but valid
key/signature each spend. With no post-quantum re-randomizable signature, we
recover the same effect from zero knowledge. Instead of broadcasting a signature
to be checked against $\rk$, the spender proves *knowledge* of a valid
post-quantum signature (hash- or lattice-based) in zero knowledge. The proof
reveals nothing about the signature, so two spends by the same key stay
unlinkable, exactly what re-randomization provided. Since authorization is now a
proof rather than a separate signature, it folds into the transaction's
[PCD proof](#pq-pcd), unifying authorization and validity into one post-quantum
artifact.

### PQ PCD Proofs {#pq-pcd}

The remaining gap is the proof system itself. Tachyon's PCD/folding (Ragu)
commits with discrete-log-based polynomial commitments, which a quantum computer
breaks, undermining the proof soundness that the theft vector above relies on. A
full quantum upgrade swaps this for a **lattice-based folding scheme** resting on
SIS/Module-LWE rather than discrete log. The folding structure that makes
Tachyon's [spendability proofs](#spendability) incremental is preserved; only the
underlying commitment and its hardness assumption change. Concrete lattice
folding constructions are an active research area, and the details remain TBD.
