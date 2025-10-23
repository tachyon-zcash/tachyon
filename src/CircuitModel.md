# Circuit Model

Arithmetic circuits in Ragu are reduced into a set of constraints over a witness assignment $\v{r} \in \F^{4n}$ where $n = 2^k$ is parameterized by a positive integer $k$. As a simplification, we assume all circuits are parameterized over the same value of $k$ even though individual circuits will vary by the minimum value of $k$ necessary for their reduction.

The prover demonstrates knowledge of a witness for a given public input vector $\v{k}$ that encodes the instance of the satisfiability problem.

### Witness Structure

The prover's witness $\v{r}$ is defined by $\v{a}, \v{b}, \v{c} \in \F^n$, where $n = 2^k$. Individual elements of this witness are known as _wires_—specifically, _allocated_ wires, because the prover must commit to them and thus they exist at a cost. They are referred to as "wires," rather than "variables," because they principally behave as inputs and outputs to multiplication gates.

Ragu defines the witness $\v{r}$ as the concatenation $\v{c} || \v{\hat{b}} || \v{a} || \v{0^n}$, which is an example of what Ragu calls a [structured vector](StructuredVector.md).

### Constraints

The witness vectors $\v{a}, \v{b}, \v{c} \in \F^n$ must satisfy $n$ [multiplication constraints](MultiplicationConstraints.md), where the $i$th such constraint takes the form $\v{a}_i \cdot \v{b}_i = \v{c}_i$. In addition, the witness must satisfy a set of $4n$ [linear constraints](LinearConstraints.md), where the $j$th such constraint is of the form

$$
\sum_{i = 0}^{n - 1} \big( \v{u}_{i,j} \cdot \mathbf{a}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{v}_{i,j} \cdot \mathbf{b}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{w}_{i,j} \cdot \mathbf{c}_i \big) =
\v{k}_j
$$

for some (sparse) public input vector $\v{k}$ and fixed matrices $\v{u}, \v{v}, \v{w} \in \F^{n \times 4n}$. Because $n$ is fixed, individual circuits vary only by these matrices after this reduction.

### Virtual Wires

The left hand side of all linear constraints are linear combinations of elements within $\v{a}, \v{b}, \v{c}$. Any linear combination of wires can itself be considered a _virtual_ wire (as opposed to an allocated wire) which impose no cost on the protocol.

### Special Constraints

Circuits always have the specially-labeled `ONE` wire $\v{c}_0 = 1$. This is enforced with the special linear constraint $\v{c}_0 = \v{k}_0 = 1$.

# OLD:::::

---



Given a formal indeterminate $Z$, it is possible to reduce these $n$ claims into the single polynomial identity test

$$
\left(\sum\limits_{i=0}^{n - 1} Z^i \v{a}_i \v{b}_i\right) - \left(\sum\limits_{i=0}^{n - 1} Z^i \v{c}_i\right) = 0.
$$

$$
\revdot{\v{r}}{\v{t}} = -\sum_{i = 0}^{n - 1} \v{c}_i \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}.
$$

<!-- ### Example Protocol

Given the common input $\v{k}$, the prover commits to the polynomial $r(X)$ defined by the coefficient vector $\v{r}$. The verifier responds with random challenge $y, z \in \F$. Let $s(X, y)$ be defined by the coefficient vector $\v{s}$, let $t(X, z)$ be defined by the coefficient vector $-\v{t_z}$, and let $k(Y)$ be defined by the coefficient vector $\v{k}$. If the $4n - 1$ degree coefficient of

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
[^simple_i]: The _simplest_ approach is to start at $i = 0$ and increment continually as new `mul` calls are made throughout circuit synthesis. -->
