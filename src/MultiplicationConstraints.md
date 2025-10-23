# Enforcing Multiplication Constraints

Given some $z \in \F$ there exists a vector $\v{t}$ such that

$$
\revdot{\v{r}}{\v{t}} = -\sum_{i = 0}^{n - 1} \v{c}_i \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}.
$$

Observe the expansion

$$\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}} =

\sum\limits_{i = 0}^{n - 1}
  \big( \v{a}_i \v{b}_i \big) \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}
+ \big( \v{c}_i \v{d}_i \big) \big( z^{i} + z^{4n - 1 - i} \big)

$$

and therefore, given a random choice of $z$ if

$$
\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} + \v{t}} = 0
$$

holds, then $\v{a}_i \cdot \v{b}_i = \v{c}_i$ holds for all $i$ with high probability.