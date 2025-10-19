# Circuit Reduction

Arithmetic circuits in Ragu are expressed as a set of $n$ multiplication constraints and $4n$ linear constraints, where some (small) quantity of the linear constraints are used to relate the _witness_ with the _public inputs_ that encode the _instance_ of the satisfiability problem. As a simplification, we assume that all circuits over a particular field use the same parameterization of $n = 2^k$ for some positive integer $k$, even though circuits will vary in the number of multiplication and linear constraints that are actually needed for the reduction.

Specifically, the witness is defined by $\v{a}, \v{b}, \v{c} \in \F^n$, the $i$th multiplication constraint takes the form $\v{a}_i \cdot \v{b}_i = \v{c}_i$, and the $j$th linear constraint takes the form

$$
\sum_{i = 0}^{n - 1} \big( \v{u}_{i,j} \cdot \mathbf{a}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{v}_{i,j} \cdot \mathbf{b}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{w}_{i,j} \cdot \mathbf{c}_i \big) =
\v{k}_j
$$

for some (sparse) public input vector $\v{k}$ and fixed matrices $\v{u}, \v{v}, \v{w} \in \F^{n \times 4n}$. Because $n$ is fixed, individual circuits vary only by these matrices after this reduction.

### Wires

Individual elements of the witness $\v{a}, \v{b}, \v{c}$ are known as _wires_—specifically, _allocated_ wires, because they are the inputs and outputs of multiplication gates (constraints) and thus exist at a cost. _Virtual wires_ are fixed linear combinations of wires. Because the left hand side of all linear constraints are linear combinations of wires, virtual wires come at little to no cost.

Circuits always have the specially-labeled `ONE` wire $\v{c}_0$ constrained by the linear constraint $\v{c}_0 = \v{k}_0 = 1$, enforced in the verification equation.

### Enforcing Linear Constraints

Given a choice of witness $\v{a}, \v{b}, \v{c}$, if for some random choice of $y \in \F$ the equality

$$
\sum_{j=0}^{4n - 1} y^j \Bigg(
    \sum_{i = 0}^{n - 1} \big( \v{u}_{i,j} \cdot \mathbf{a}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{v}_{i,j} \cdot \mathbf{b}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{w}_{i,j} \cdot \mathbf{c}_i \big)
\Bigg) =
\sum_{j=0}^{4n - 1} y^j \v{k}_j
$$

holds, then with high probability the above $4n$ linear constraints are all satisfied as well. After some trivial manipulation, it is possible to define a vector $\v{s}_Y \in \F[Y]^{4n}$ such that this is equivalent to

$$
\revdot{\v{r}}{\v{s}_y} = \dot{\v{k}}{\v{y^{4n}}}
$$

where the witness vector $\v{r} \in \F^{4n}$ is defined by the concatenation $\v{c} || \v{\hat{b}} || \v{a} || \v{0^n}$.

### Enforcing Multiplication Constraints

Given some $z \in \F$ there exists a vector $\v{t_z}$ such that

$$
\revdot{\v{r}}{\v{t_z}} = \sum_{i = 0}^{n - 1} \v{c}_i \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}.
$$

Observe the expansion

$$\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}} =

\sum\limits_{i = 0}^{n - 1}
  \big( \v{a}_i \v{b}_i \big) \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}
+ \big( \v{c}_i \v{d}_i \big) \big( z^{i} + z^{4n - 1 - i} \big)

$$

and therefore, given a random choice of $z$ if

$$
\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} - \v{t_z}} = 0
$$

holds, then $\v{a}_i \cdot \v{b}_i = \v{c}_i$ holds for all $i$ with high probability.

### Consolidated Verification Equation

The two equations can be combined into a single equation

$$
\revdot{\v{r}}{\v{s_y} + \v{r} \circ{\v{z^{4n}}} - \v{t_z}} = \dot{\v{k}}{\v{y^{4n}}}
$$

because $\v{r} \circ \v{z^{4n}} - \v{t_z}$ is made independent of $\v{s_y}$ by random $z$ except at $\v{r}_0$, where $\v{s}_0 = 0$.

### Example Protocol

Given the common input $\v{k}$, the prover commits to the polynomial $r(X)$ defined by the coefficient vector $\v{r}$. The verifier responds with random challenge $y, z \in \F$. Let $s(X, y)$ be defined by the coefficient vector $\v{s_y}$, let $t(X, z)$ be defined by the coefficient vector $-\v{t_z}$, and let $k(Y)$ be defined by the coefficient vector $\v{k}$. If the $4n - 1$ degree coefficient of

$$
d(X) = r(X) \cdot \big ( r(Xz) + s(X, y) + t(X, z) \big)
$$

is equal to $k(y)$, then with high probability the prover knows a satisfying witness. Let us rewrite

$$
d(X) = X^{4n - 1} p(1/X) + X^{4n} q(X)
$$

for polynomials $p, q \in \F[X]$ of maximal degree $4n - 1$. The prover sends $p, q$ to the verifier and the verifier checks

$$
r(x) \cdot \big ( r(xz) + s(x, y) + t(x, z) \big) = x^{4n - 1} p(x^{-1}) + x^{4n} q(x)
$$

for a random challenge point $x \in \F$, establishing the claim with high probability.

## Circuit Synthesis

Circuit implementations in Ragu describe themselves using the algebraic structure above, and the process of **synthesis** involves executing or interpreting this circuit code. As an example, the circuit code may be responsible for 

# Circuit Polynomials



-----



During circuit synthesis the driver is asked to perform two operations that influence the ultimate reduction to $s(X, Y)$:

1. `mul` _allocates_ an $(a, b, c) = (X^i, X^j, X^k)$ triple for which $a \cdot b = c$ is enforced. The actual enforcement of this multiplication constraint is not achieved by the $s(X, Y)$ polynomial, but the allocation (or choice) of the triple $(a, b, c)$ does influence the polynomial.
2. `enforce_zero` takes a linear combination


 are the `mul` step (which _allocates_ an $(a, b, c)$ triple for which $a \cdot b = c$ is enforced) and 



Each individual circuit is reduced to a bivariate polynomial $s(X, Y)$ where
$X^i$ corresponds to wire $i$ of the witness assignment, $Y^j$ corresponds to
linear constraint $j$, and $c_{i,j}$ corresponds to the coefficient of the
$i$th wire in the $j$th linear constraint:

$$
\begin{array}{ll}
s(X, Y) &= \sum_j Y^j \Big( \sum_i \underline{c_{i, j}} X^i \Big) \\
&= \sum_{i,j} \underline{c_{i, j}} X^i Y^j
\end{array}
$$

During circuit synthesis there are _two_ operations that affect the composition of this polynomial: the allocation of the wires in the witness assignment (which happens during each `mul` step) and the creation of linear constraints (which happens during each `enforce_zero` step).

* **`mul`** In this step, an unused $i$ value is chosen and $(X^{2n + i}, X^{2n - 1 - i}, X^i)$ is returned, corresponding to the $(a, b, c)$ wires of a fresh multiplication gate.[^mulgates] [^simple_i] In the case that $s(X, Y)$ is being evaluated at the restriction $X = x$ then the `mul` step actually returns $(x^{2n + i}, x^{2n - 1 - i}, x^i)$. Otherwise, this step effectively returns indices $(2n + i, 2n - 1 - i, i)$.
* **`enforce_zero`** In this step, a linear combination $\ell(X)$ of wires produced in the `mul` step is enforced to equal zero. This involves the creation of a linear constraint: an unused value $j$ is chosen, and $\ell(X) Y^j$ is added as a term of the $s(X, Y)$ polynomial.

[^mulgates]: The proving system ensures that $a \cdot b = c$, but this constraint is not enforced by (or influencing of) the $s(X, Y)$ polynomial.
[^simple_i]: The _simplest_ approach is to start at $i = 0$ and increment continually as new `mul` calls are made throughout circuit synthesis.
