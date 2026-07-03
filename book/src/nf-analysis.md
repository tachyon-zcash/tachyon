# Nullifier Analysis

## Background

Excerpt from the Tachyon [deep dive](./revisit.md) below.

A Tachyon note is:

$$
\mathsf{Note} := (\pk, v, \psi, \rcm) 
$$

where $\pk$ is the payment key, $v$ is the value of the note, 
$\psi$ is pseudo-random note identity that binds to the note nullifier value as
an input to its derivation, and $\rcm$ is a random commitment trapdoor.

The ideal functionality for an epoched nullifier is a deterministic function:

$$
\nf_e = \mathsf{KDF}(\nk, \psi, e)
$$

whose outputs are indistinguishable from random bytes. Such an $\nf_e$ binds to
both the spending authority (via $\nk$) and the underlying note (via its per-note
trapdoor $\psi$), while remaining unlinkable across epochs to anyone without $\nk$.

We proposed a [**GGM-based nullifier**](./revisit.md#nf-ggm) whose derivation
requires walking a tree where descending one level involves a Poseidon hash.
The construction details are irrelevant thus skipped here.
The main takeaway is: a single nullifier derivation (full tree walk) already
saturates the circuit capacity for a PCD step!

<details>
<summary><a id="ggm-cost"><b>GGM Cost</b></a>: Calculation Details</summary>
    
The GGM tree size is determined by how large of the epoch space do we want to
support. A depth-$14$ tree implies the largest epoch value being $2^{14}-1$.
Assuming 1 day/epoch, this translates to 45 years in the future which is
reasonable. A full root-to-leaf walk of such tree requires $14$ Poseidon hashes.
    
Step circuit size (`max_mul_gates`) is $n=2^{11}=2048$. Since our constraint
system allows $4n$ linear constraints, this budget is overly abundant and we only
focus on multiplication constraints. Step capacity for Poseidon is $7$ ([see
here](https://github.com/tachyon-zcash/ragu/pull/720)) as per-permutation gate
cost is $288$.
    
With a [mixed-arity optimization](./revisit.md#mixed-arity) of the tree, where
the arity is higher towards the root and binary towards the leaf, we can cut
down the depth to 7, thus fit a full derivation in a single step. $\blacksquare$
    
</details>

Ideally, we want to **fit more (at least two) nullifier derivations in a single
step**. For example, the [`NfDerive` step](./revisit.md#steps) derives both
$\nf_e$ and $\nf_{e+1}$ for the spending epoch $e$ in a single step.
Therefore, the challenge is to find alternative nullifier constructions with
lower circuit complexity.

The high-level idea is to construct a degree-$d$ polynomial $f_k(X)$ such that:

- $f_k(\cdot)$ is keyed by $k = \mathsf{KDF}(\nk, \psi)$ so that only $\nk$-holder
  (namely note owners) knows the full $f_k(X)$ and its derivation is bound to the
  specific note identity $\psi$.
- Highly efficient to evaluate $\nf_e = f_k(e)$: only $O(\log{d})$ work.
  - epoch domain size $|E| < d + 1$
- Given any set of evaluation points $S \subseteq E$ and their evaluations
  $\{f_k(i)\}_{i\in S}$, *any evaluation outside the set $f_k(j \notin S)$ is
  indistinguishable from random*.
  - strictly stronger requirement than "cannot compute $f_k(j)$": unpredictability
    is insufficient; semantic security is necessary for spend unlinkability.
  - relaxing statistical indistinguishability to computational expands the
    design space.

This alternative is a promising direction because proving $\nf_e$ derivation is
now an evaluation claim, which can be either proven directly in circuit (only
field ops) or piggyback on the [online polynomial oracle](./revisit.md#acc)
exposes by the Ragu proof system (low circuit cost).

## Threat Model

We discuss security from the perspective of recipients whom we address to as
"users". Senders and syncing services (OSS) are untrusted. Here are the
assumptions/setup:

- $\psi, \rcm$: picked by the sender.
- $\nk$: privately known to the user.
- OSS can derive nullifiers for a finite range of delegated epochs. They cannot
  locate/link the note commitment $\cm$ or future nullifiers outside the range.
- malicious users try to double-spend by publishing $\nf_e' \neq \nf_e$ for the
  same note in any epoch $e$ that both pass the derivation integrity check.

## Attempt 1: Statistically Indistinguishable

### Attempt 1.1: User-sampled

- User randomly samples a $f(X)$ of bounded degree, commits to it and sends
  $\cm_f$ to the sender.
  - to support epoch range $[0, d]$, take $d=2^{14}$ which is $\approx 45$
    years assuming a 1 day/epoch pace
- Sender prepares the Output note by setting $\psi = \mathsf{Extract}(\cm_f)$.
  Effectively, the $\cm$ commits to the nullifier polynomial.
  - user wallet rejects incoming note with unknown/wrong/repeated $\psi$
- OSS directly receives a single PCD proof attesting $\{\nf_i\}_{i\in R}$ for the
  delegated range $R$.

Pros:

- The circuit cost is minimum: load the note opening $\mathsf{Note}$ and $\cm_f$
  as secret witness, enforce $\psi = \mathsf{Extract}(\cm_f)$ in circuit, then
  append a PCS eval claim of form $(\cm_f, e, \nf_e)$ to the PolyQuery oracle.
- Proving multiple $\nf_e$ is practically free since querying multiple points on
  an already committed polynomial in our PolyQuery oracle incurs negligible cost.
  - Note that we don't need to witness the actual $f(X)$ or evaluate it in
    circuit thanks to the oracle, thus no special structure required for $f(X)$.
- Statistical indistinguishable due to random sampling and the $|E|\leq d$
  assumption where $E$ is the epoch domain. In practice, coefficients are
  PRF-derived from some master seed.

Cons:

1. UX nightmare: every new note requires user involvement (freshly samples then
   sends OOB).
2. Assisted proving required: OSS who tries to prove $f(e) = \nf_e$ in the
   [PCS evaluation protocol](https://tachyon.z.cash/ragu/protocol/core/accumulation/pcs)
   without access to the full $f(X)$ requires user's assistance to compute the
   evaluation of its quotient polynomial $q(u)$ at FS-challenge point $u$.
   Circumventing this impossible inconvenience leaves us with the solution where
   the user generate a PCD proof for *all* nullifier values of the delegated
   range as an input to the OSS's proof tree.
   
Among the two disadvantages, the interactive UX is the hairy one. Naturally, a
user can preload a sequence of future $\{\cm_f\}$ to the sender out-of-band.
However, this would increase the state management overhead since the wallet
needs to track all previously issued but yet unused $\cm_f$ to reject incoming
notes of unknown/repeated $\psi=\cm_f$.

Meanwhile, assisted proving is arguably inevitable (for all our attempts here).
The OSS cannot learn the full $f(X)$ since otherwise all future nullifiers are
computable and spend unlinkability is violated. To assist OSS, the user either
directly prove the full derivation of delegated nullifiers or prove the partial
evaluation of $f_k(e)$, refered as the delegation key, and OSS completes the
rest of the evaluation.[^ggm-partial] In the latter case, those partial
evaluations should reveal nothing about the full $f_k(X)$.

[^ggm-partial]: In the original GGM-based nullifier, the [`DelegateCert`
    step](./revisit.md#steps) proves integrity of the internal node whose value
    is the delegation key.

### Attempt 1b: Sender-sampled

A natural modification to avoid the user/recipient interaction is to switch to
sender-sampled random polynomials. However, the challenge is to cryptographically
bind to $\cm$. We have two ways:

1. Sender randomly sample $f(X)$ of degree $d=2^{14}$, using whatever entropy
   source, set $\psi = \mathsf{Commit}(f(X))$, thus binds to $\cm$.
2. Sender deterministically derives coefficients:
$$
\begin{aligned}
k &= H(\nk) \quad\text{(recipient-provided)}\\
a_0,\ldots,a_d &\leftarrow \mathsf{XOF}(k, \psi, d+1)\\
f(X) &= \sum_{i=0}^d a_i \, X^i
\end{aligned}
$$
   since coefficients binds to $(\nk, \psi)$, it transitively binds to $\cm$.

The problem with both approaches are their circuit costs. The first approach
requires enforcing $\mathsf{Commit}$ of a degree-$d$ polynomial in-circuit. The
second approach requires deriving all coefficients in-circuit: when instantiating
$\mathsf{XOF}$ with Poseidon-based sponge construction for variable-length
output, to witness the full $f(X)$ in-circuit requires $\frac{d}{\mathsf{Rate}}$ Poseidon
permutation. Both burden a higher cost than the original GGM construction.

## Attempt 2: Product of Sparse Polynomials

> To eliminate recipient interaction during note creations, we avoid user-sampling
of coefficients. Instead, we explore a structured $f_k(X)$ where the $f_k(\cdot)$
description (i.e. coefficients) is fully determined by $(\nk, \psi)$, thus its
evaluation is enforced through proofs that $k = \mathsf{KDF}(\nk, \psi)$ and
$\nf_e = f_k(e)$. For circuit efficiency, we need to find a $f_k(X)$ with
sublinear evaluation logic which implies structured polynomials with **concise
algebraic descriptions**.
>
> Here, "concise" means fewer than $d+1$ independent coefficients, not just a
short generator program (that could expand a random seed into sufficient entropy).
Particularly, we relax our indistinguishability **from statistical to
computational** in pursuit of circuit efficiency.
We argue that this relaxation is *inevitable* when going beyond attempt 1.

We explore the first approach here and the second approach in the remaining sections.

- **product** of (low-degree) sparse polynomials
- **composition** of (low-degree) round functions where each round includes
  linear confusion and non-linear diffusion (via algebraic s-box)

Unlike attempt 1 whose $f(X)$ is randomly sampled with $(d+1)\cdot |\F|$-bit
entropy, thus remains statistically hiding so long as we reveal $\leq d$
evaluations. Our *structured* $f_k(X)$ candidates, with concise descriptions and
less entropy, must withstand various algebraic attacks.[^attack-lit]
We start with the GCD attack to demonstrate the necessity of polynomial degree
much higher than the epoch domain size: $\deg(f_k(X)) \gg |E| \approx 2^{14}$
even if we only reveal $< |E|$ evaluation points.

[^attack-lit]: For a survey of algebraic attacks on arithmtization-orientated
    cipher (AOC), start with Zellic's
    [blog post](https://www.zellic.io/blog/algebraic-attacks-on-zk-hash-functions/),
    then Section 4.2 of [MiMC](https://ia.cr/2016/492),
    Appendix E of [HADES](https://ia.cr/2019/1107),
    Appendix C.2 of [Poseidon](https://ia.cr/2019/458), and
    a detailed [SoK on Gröbner basis algorithm](https://ia.cr/2021/870).

<a id="gcd">**GCD Attack.**</a>
The GCD attack recovers the key by computing the GCD of two polynomials.
We view $f_k(X)$ as a bivariate polynomial $g(K, X)$. Given only two evaluations,
we can establish:

$$
\begin{cases}
h_1(k) = g(k, x_1) - y_1 = 0\\
h_2(k) = g(k, x_2) - y_2 = 0\\
\end{cases} \Longrightarrow
\mathsf{GCD}(h_1(K), h_2(K)) = (K - k)
$$

The complexity of GCD over two polynomial of degree $d$ is $O(d\log^2 d)$.
The quasilinear cost dictates that $\lambda=128$-bit security requires
$2^\lambda \leq d\log^2 d$, thus $d \geq 2^{118}$. $\blacksquare$


### Attempt 2a

An appealing candidate is:

$$
f_k(X) = \prod_{i=0}^{\log d} (X^{2^i} + b_i)
\quad\text{where } \{b_i\}\leftarrow \mathsf{XOF}(k, \log d + 1)
$$

This family of polynomial is attractive because it only requires $\log d$
coefficients in description while the expanded expression is **dense** (i.e.,
monomials of all degrees are present). Heuristically, sparse polynomials are
usually more vulnerable to distinguishers due to [linearization attack](#lin1).

Another attractive profile is its $O(\log d)$ evaluation cost. By keeping two
running values: `x_pow` and `result`, each steps only requires `x_pow = x_pow^2`
and `result = result * (x_pow + b_i)` involving two multiplications per-step or
$2\log d$ multiplications in total.

Unfortunately, the prohibiting cost resides in binding $\log d + 1$ coefficients
to $\cm$. Instead of forcing each nullifier derivation to re-derive $\{b_i\}$
which requires $\lfloor \frac{\log d + 1}{\mathsf{Rate}=4} \rfloor \geq 30$
Poseidon permutations, we can amortize the cost by asking the sender to set
$\psi = \mathsf{Commit}(\{b_i\})$, and later re-commit the witnessed $\{b_i\}$.
The Poseidon-based commitment only takes $\lfloor \frac{30}{\mathsf{Rate}}
\rfloor\geq 8$ permutations per-nullifier. Even with the amortization, the cost
already exceeds that of [the GGM's](#ggm-cost).

As a side note, the following construction is equivalent for all algebraic
attackers; yet worse in efficiency due to the doubled number of coefficients:

$$
\begin{aligned}
f_k(X) &= \prod_{i=0}^{\log d} (a_i \cdot X^{2^i} + b_i)
\quad\text{where } \{a_i, b_i\}\leftarrow \mathsf{XOF}(k, 2\log d + 2)\\
&= B \cdot \prod_{i=0}^{\log d} (\frac{a_i}{b_i}\cdot X^{2^i} + 1)
\quad\text{where } B = \prod_i b_i \approx_s B'\leftarrow \F_p
\end{aligned}
$$

### Attempt 2b

The primary cost of Attempt 2a comes from deriving or binding its $\log d + 1$
coefficients. Naturally, we wonder if we can drop just *a few* factors while
maintaining the same highest degree to remain resilient to [GCD attack](#gcd).

$$
\begin{aligned}
\text{original}: f_k(X) = (X - b_0)\cdot(X^2 - b_1)\cdot(X^4 - b_2)\cdot\,\ldots\,\cdot (X^{117} - b_{117})\cdot(X^{118} - b_{118})\\
\text{modified}: f_k(X) = (X - b_0)\cdot\cancel{(X^2 - b_1)}\cdot(X^4 - b_2)\cdot\, \ldots\, \cdot\cancel{(X^{117} - b_{117})}\cdot(X^{118} - b_{118})\\
\end{aligned}
$$

The dropped set $S \subseteq [\log d]$ could be arbitrarily picked and fixed at
system setup. By tuning the dropped set size $|S|$, we balance the trade-off
between circuit efficiency and security. Larger $|S|$ linearly reduces the
circuit cost thanks to fewer coefficients to derive and bind to; but the
resulting $f_k(X)$ also becomes more sparse, thus more vulnerable to a class
of statistical and algebraic attacks. We discuss one such attack below.

<a id="lin1">**Linearization Attack.**</a>
The linearization attack is an algebraic attack that *linearize* a set of
non-linear equations before applying Gaussian elimination.
Take a concrete example of $\log d = 4$, $S = \{1, 3\}$, namely
$f_k(X) = (X - b_0)(X^4 - b_2)(X^{16} - b_4)$. There are only 7 unique monomials
$f_k(X) = \sum_{j\in \{1, 4, 5, 16, 17, 20, 21\}} c_j \cdot X^j$ where $c_j$ are
linear combination of $\{b_0, b_2, b_4\}$. By replacing $Y_j = X^j$, we linearize
an evaluation equation:

$$
f_k(X) = \sum_j c_j\cdot X^j \;\overset{\text{linearize}}{\Longrightarrow}
g(Y_0, Y_1, \ldots, Y_6) = \sum_j c_j\cdot Y_j
$$

Given just 7 evaluations, we have a system of equation ready to be solved using
Gaussian elimination.

$$
\begin{cases}
\sum_{j=0}^{6} c_j\cdot y_j^{(0)} = f_k(x_0)\\
\qquad\ldots \\
\sum_{j=0}^{6} c_j\cdot y_j^{(6)} = f_k(x_6)\\
\end{cases} \;\overset{\text{GE}}{\Longrightarrow}
\{c_j\}
$$

With all $c_j$ solved, the attacker obtain the full description of
$g(Y_0,\ldots,Y_6) = f_k(X)$ which can be used to compute any nullifier value
$\nf_e = f_k(e)$ without recovering the key $k$ per-se. $\blacksquare$

The exponential decay in security with only linear benefit in circuit efficiency
rules out this attempt 2b.

## Attempt 3: ZK-friendly Hash

## Attempt 4: AOC with Reduced Rounds
