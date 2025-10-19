# revdot reduction

Common inputs:

* $a(X) \in \mathbb{F}[X] = \sum_{i=0}^{4n - 1} X^i \v{a}_i$
* $b(X) \in \mathbb{F}[X] = \sum_{i=0}^{4n - 1} X^i \v{b}_i$
* $c \in \mathbb{F}$

The claim: $\revdot{\v{a}}{\v{b}} = c$.

The tool:

* $a(X) \cdot b(X) = t(X)$
* Claim reduces to: the $4n - 1$ degree coefficient of $t(X) = c$
* $t(X) = X^{4n - 1} p(1/X) + X^{4n - 1} q(X)$ for some $p(X), q(X) \in \mathbb{F}[X]$ of maximal degree $4n - 1$.

The protocol:

* Prover computes $t(X)$ (requires FFT)
* Prover computes unique $p(X), q(X)$ given $t(X)$
* Prover commits to $P, Q$
* Verifier samples $x$
* Prover sends $p' = p(x^{-1}), q' = q(x)$
* Verifier checks $x^{4n - 1} p' + x^{4n - 1} q'$
* Verifier queries
    * $p(x^{-1}) = p'$
    * $q(x) = q'$
    * $p(0) = c$