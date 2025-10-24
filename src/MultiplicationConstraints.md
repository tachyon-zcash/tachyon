# Enforcing Multiplication Constraints

The multiplication constraints over the witness can be rewritten as $\v{a} \circ \v{b} = \v{c}$. It is possible to probabilistically reduce this to a dot product claim using a random challenge $z \in \F$. Observe the expansion

$$
\dot{\v{a}}{\v{z^{4n}} \circ \v{b}} - \dot{\v{c}}{\v{z^{4n}}} = 0.
$$

By the [definition](ArithmeticCircuits.md#witness-structure) of $\v{r}$ (as a [structured vector](StructuredVector.md)) we can do something mathematically identical. Observe the expansion

$$\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}} =

\sum\limits_{i = 0}^{n - 1} \left(
  \v{a}_i \v{b}_i  \big( \underline{z^{2n - 1 - i} + z^{2n + i} } \big)
+ \v{c}_i \v{d}_i  \big( z^{i} + z^{4n - 1 - i} \big)
\right)

$$

and notice that a vector $\v{t}$ exists such that

$$
\revdot{\v{r}}{\v{t}} = -\sum_{i = 0}^{n - 1} \v{c}_i \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}.
$$

and so if for a random challenge $z$

$$
\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} + \v{t}} = 0
$$

holds, then $\v{a}_i \cdot \v{b}_i = \v{c}_i$ holds for all $i$ with high probability.