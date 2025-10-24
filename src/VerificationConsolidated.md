# Consolidated Verification Equation

The equation for enforcing [multiplication constraints](MultiplicationConstraints.md) (using random challenge $z$) and [linear constraints](LinearConstraints.md) (using random challenge $y$) can be combined into a single equation

$$
\revdot{\v{r}}{\v{s} + \v{r} \circ{\v{z^{4n}}} - \v{t}} = \dot{\v{k}}{\v{y^{4n}}}
$$

because $\v{r} \circ \v{z^{4n}} - \v{t}$ is made independent of $\v{s}$ by random $z$ except at $\v{r}_0$, where $\v{s}_0 = 0$.
