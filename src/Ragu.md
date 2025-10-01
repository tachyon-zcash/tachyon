## Ragu (WIP)

## Preliminaries

We write a vector $\v{a} \in \F^n$ in bold type, and generally use capital
letters like $\v{G} \in \mathbb{G}^n$ to represent vectors of group elements.
Similarly, individual field and group elements are written in a normal type face
like $a \in \F$ or $H \in \mathbb{G}$. All vectors are zero-indexed.

Given a univariate polynomial $p \in \F[X]$ of maximal degree $n - 1$ there exists a (canonical) coefficient vector $\v{p} \in \F^n$ ordered such that $\v{p}_{n
- 1}$ is the leading coefficient. Given $z \in \F$ the evaluation $p(z)$ is thus
given by the inner (dot) product $\langle \v{p}, \v{z^n} \rangle$ where $\v{z^n}$
denotes the power vector $(z^0, z^1, \cdots, z^{n - 1})$. We write the
_dilation_ $p(zX)$ using the Hadamard (pair-wise) product $\v{z^n} \circ \v{p}$.

The coefficients of the product of two polynomials are discrete convolutions,
and so if $\v{p}, \v{q} \in \F^n$ are the respective coefficient vectors of $p,
q \in \F[X]$ then the $n-1$ degree coefficient of the product $p \cdot q$ is
$\langle \v{p}, \hat{\v{q}} \rangle$ where $\hat{\v{q}}$ denotes the _reversal_
such that $\hat{\v{q}}_i = \v{q}_{n - 1 - i} \forall i$. It will be very useful
to reduce inner product claims of this form to claims about low degree
polynomials, so we'll use the special notation $\conv{\v{a}}{\v{b}} = \langle
\v{p}, \hat{\v{q}} \rangle = \langle \hat{\v{p}}, \v{q} \rangle$.

### Arithmetic Circuit Protocol

In the following we will consider a **structured polynomial** $r \in \F[X]$
defined by the coefficient vector $\v{r} = \v{c} \mathbin\Vert \hat{\v{b}} \mathbin\Vert \v{a} \mathbin\Vert
\hat{\v{d}}$ for some vectors $\v{a}, \v{b}, \v{c}, \v{d} \in \F^n$ without loss
of generality. This definition conveniently allows $\hat{\v{r}}$ to be written
as the same concatenation but with $\v{a}$ swapped with $\v{b}$ and $\v{c}$
swapped with $\v{d}$.<sup>[[sage]](http)</sup>

In our core protocol the prover will commit to the witness $\v{a}, \v{b}, \v{c}$
using this structured polynomial. In order to encode multiplication gates we
will establish the claim $\v{a} \circ \v{b} = \v{c}$. Let's begin with the
expansion

$$
\conv{\v{r}}{\v{z^n} \circ \v{r}} = 
\sum\limits_{i = 0}^{n - 1}
  \big( \v{a}_i \v{b}_i \big) \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}
+ \big( \v{c}_i \v{d}_i \big) \big( z^{i} + z^{4n - 1 - i} \big)
$$

for $z \in \F$.<sup>[[sage]](http)</sup> Let $\v{t} \in \F^n$ be a special vector determined by $z$ such
that $\conv{\v{r}}{\v{t}} = \sum_{i = 0}^{n - 1} \v{c}_i \underline{\big( z^{2n - 1 - i} + z^{2n + i} \big)}$.<sup>[[sage]](http)</sup> (The underlined terms are used to highlight the intended relationship.) If for a random choice of $z$ we have 

$$\conv{\v{r}}{\v{z^n} \circ \v{r} - \v{t}} = 0$$
then with high probability we have $\v{a} \circ \v{b} = \v{c}$ and $\v{c} \circ \v{d} = \v{0}$.<sup>[[sage]](http)</sup>

In order to encode addition gates and relate the witness to the instance we
allow $q \leq 4n$ linear constraints to be imposed on $\v{a}, \v{b}, \v{c}$ as
well. The $j$th such constraint is of the form

$$
\langle \v{a}, \v{u}_\mathbf{j} \rangle + \langle \v{b}, \v{v}_\mathbf{j} \rangle + \langle \v{c}, \v{w}_\mathbf{j} \rangle = \v{k}_j
$$

for fixed vectors $\v{u}_\mathbf{j}, \v{v}_\mathbf{j}, \v{w}_\mathbf{j} \in
\mathbb{F}^n$ and public input vector $\v{k} \in \mathbb{F}^n$. Let us define a
special vector $\v{s}$ such that for some $y \in \F$ we have the expansion

$$
\conv{\v{r}}{\v{s}} = \sum\limits_{j=0}^{q} y^j \Big( \langle \v{a}, \v{u}_\mathbf{j} \rangle + \langle \v{b}, \v{v}_\mathbf{j} \rangle + \langle \v{c}, \v{w}_\mathbf{j} \rangle \Big)
$$

which gives us that $\conv{\v{r}}{\v{s}} = \langle \v{y^q}, \v{k} \rangle$
implies satisfaction of the linear constraints with high probability for an
independently random choice of $y$. We will assume $n$ is fixed for many
different circuits so that circuits vary only by their choice of the matrices
$\v{u}, \v{v}, \v{w} \in \mathbb{F}^{n \times q}$.

The two sets of constraints can then be safely combined into a single equation

$$
\conv{\v{r}}{\v{z^n} \circ \v{r} + \v{s} - \v{t}} = \langle \v{y^q}, \v{k} \rangle
$$

because all entries of $\v{z^n} \circ \v{r} - \v{t}$ are linearly independent
from their corresponding entries in $\v{s}$.

#### Polynomials

##### Instance polynomial $k(Y)$

The vector $\v{k}$ represents the coefficient vector of a low degree polynomial $k(Y)$ which encodes the public inputs. This is evaluated at $y$ for the computation of $\langle \v{y^q}, \v{k} \rangle$. Due to the constraint $\v{c}_0 = 1$ this polynomial always has a constant term of $1$.

##### Circuit polynomial $s(X, Y)$

The vector $\v{s}$ represents the coefficient vector of the bivariate polynomial

$$
s(X, Y) = \sum\limits_{j=0}^{q - 1} Y^j \Big(
      \sum_{i = 0}^{n - 1} (\v{u_j})_i X^{2n - 1 - i}
    + \sum_{i = 0}^{n - 1} (\v{v_j})_i X^{2n + i}
    + \sum_{i = 0}^{n - 1} (\v{w_j})_i X^{4n - 1 - i}
\Big)
$$

restricted at $Y = y$. This polynomial has the property that $s(X, 0) = X^{4n - 1}$ and $s(0, Y) = 0$.

##### Constraint polynomial $t(X, Z)$

The vector $\v{t}$ represents the coefficient vector of the bivariate polynomial

$$t(X, Z) = \sum_{i=0}^{n - 1} X^{4n - 1 - i} (Z^{2n - 1 - i} + Z^{2n + i})$$

restricted at $Z = z$. This polynomial is a geometric series that can be
evaluated efficiently at random points. This polynomial has zeroes at $X = 0$
and $Z = 0$.

##### Witness polynomial $r(X)$

The prover's witness polynomial

$$
r(X) = \sum_{i = 0}^{n - 1} c_i X^{i} + \sum_{i = 0}^{n - 1} b_i X^{2n - 1 - i} + \sum_{i = 0}^{n - 1} a_i X^{2n + i}
$$

is defined by the coefficient vector $\v{r}$ described before, and the value
$\v{z^n} \circ \v{r}$ can be obtained through the dilation $r(Xz)$. Due to the
constraint $c_0 = 1$, all (valid) witnesses yield a witness polynomial with a
constant term of $1$ (and so $r(0) = 1$).

### Simple PIOP

The prover begins by sending an oracle for their witness polynomial $r$. The
verifier then chooses $y, z \in \F$ at random and asks the prover to supply
oracles $p, q$ defined such that

$$
r(X) \cdot \big( r(Xz) + s(X, y) - t(X, z) \big) = X^{4n - 1} p(1 / X) + X^{4n} q(X)
$$

Note that $k(Y), s(X, Y)$ and $t(X, Z)$ are known to the verifier. The verifier
can thus query $p, q, r$ at a random point to check that this identity holds
with high probability. Finally, the verifier queries $p(0)$ and accepts if $p(0)
= k(y)$.

This protocol works, but it requires the prover to compute $p, q$ by decomposing the product of two polynomials, which involves a Fast-Fourier Transformation (FFT) in practice. We can create a relaxed instance of this protocol that can be folded.
