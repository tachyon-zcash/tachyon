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

holds, then with high probability the $4n$ linear constraints ([mentioned previously](ArithmeticCircuits.md#constraints)) are all satisfied as well. After some trivial manipulation, it is possible to define a vector $\v{s}$ such that this is equivalent to

$$
\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}
$$

for the [witness](ArithmeticCircuits.md#witness-structure) vector $\v{r}$.