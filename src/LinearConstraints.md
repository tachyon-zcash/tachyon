# Enforcing Linear Constraints

Given a choice of witness $\v{a}, \v{b}, \v{c}$, if for some random choice of $y \in \F$ the equality

$$
\sum_{j=0}^{4n - 1} y^j \Bigg(
    \sum_{i = 0}^{n - 1} \big( \v{u}_{i,j} \cdot \mathbf{a}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{v}_{i,j} \cdot \mathbf{b}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{w}_{i,j} \cdot \mathbf{c}_i \big)
\Bigg) =
\sum_{j=0}^{4n - 1} y^j \v{k}_j
$$

holds, then with high probability the above $4n$ linear constraints are all satisfied as well. After some trivial manipulation, it is possible to define a vector $\v{s}$ such that this is equivalent to

$$
\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}
$$

where the witness vector $\v{r} \in \F^{4n}$ is defined by the concatenation $\v{c} || \v{\hat{b}} || \v{a} || \v{0^n}$.
