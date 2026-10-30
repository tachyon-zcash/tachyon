# Dynamic Fee

A wallet signs a maximum fee once. A prover chooses the fee later, at or below
that maximum, without signing again. The difference returns to the wallet as a
fee change note.

Each Tachyon bundle has its own fee. The signatures cover only its maximum.

## Terms

- **Max fee note**: the note whose value $\maxfee$ is the maximum fee. It is
  published only as `cvFeeMaxTachyon` and is never spent.
- **Fee change note**: the spendable note that pays $\maxfee - \fee$ back to
  the max fee note's owner. It is published only as its commitment $\cm_\chg$
  (`cmChange`), a [tachygram](./tachygrams.md).
- **Fee descriptor**: the pair $(\cv_\maxfee, \fee)$ on the bundle, published
  as `cvFeeMaxTachyon` and `vFeeTachyon`.
- **Fee digest**: the Poseidon digest $d_\fee$ of a fee descriptor. It is a
  member of the stamp's action set.

## Max Fee Note

Every bundle carries one max fee note $(\pk, \maxfee, \psi, \rcm)$ with the
fields of any [note](./notes.md). Its value $\maxfee$ is the maximum fee and
may be zero. Its payment key $\pk$ owns the fee change note. The bundle
publishes only its value commitment

$$
\cv_\maxfee = [-\maxfee]\,\mathcal{V} + [r]\,\mathcal{R},
\qquad
r = \mathsf{Poseidon}_\texttt{Tachyon-FeeBlind}(\pk, \psi, \rcm),
$$

with $r$ embedded in the scalar field.
The blind binds the fee change note's owner fields into the commitment. Each
max fee note takes a fresh secret $\rcm$ because reusing an opening reuses the
blind.

[Bundles](./bundle.md#wire-format) gives the wire layout. Consensus requires a
bundle with no actions to have a zero value balance. With no actions, the
[binding signature](./authorization.md#binding-signature) verifies only if
$v^{bal} + \maxfee$ is zero. The maximum fee is then zero.

## Signing

The [bundle commitment](./authorization.md#bundle-commitment) absorbs
$\cv_\maxfee$. The fee stays out of it. Signing
fixes the maximum fee and the fee change note's owner.

The value balance counts the max fee note as an output:

$$
v^{bal} = \sum v_{in} - \sum v_{out} - \maxfee.
$$

The binding keys take the max fee note's blind and commitment as one more
output:

$$
\bsk = \sum_i \rcv_i + r,
\qquad
\bvk = \sum_i \cv_i + \cv_\maxfee - [v^{bal}]\,\mathcal{V} = [\bsk]\,\mathcal{R}.
$$

Neither key involves the fee.
[Authorization](./authorization.md#binding-signature) gives the full binding
signature.

## Fee Change Note

The fee $0 \leq \fee \leq \maxfee$ is chosen after signing. The fee change note
$(\pk, \maxfee - \fee, \psi, \rcm)$ takes the max fee note's other fields. Its
[note commitment](./notes.md#commitment) $\cm_\chg$ appears only as a
tachygram. A fee equal to the maximum leaves a zero-valued fee change note,
which still has its tachygram.

## Fee Steps

The [proof tree](./proof-tree.md) gives action content before the fee the
`Actions` header, and fee-bearing content the `Stamp` header. Both carry an
action set commitment, a [tachygram set](./tachygrams.md#tachygram-sets)
commitment and an [anchor](./anchor.md).
$\mathsf{FeeFuse}$ and $\mathsf{FeeSeed}$ are the only steps that output a
`Stamp` without taking one as input. Every stamp descends from one of them.

$\mathsf{FeeFuse}$ transforms actions. It takes `Actions` as its left input,
has no right input, and outputs a `Stamp`. It adds $d_\fee$ to the action set
and $\cm_\chg$ to the tachygram set. Its witness is

- the max fee note opening
- the fee $\fee$
- the left set polynomials $A$ and $T$
- the output set polynomials $A'$ and $T'$
- the fee singleton set polynomials $S_A$ and $S_T$

The step derives $r$ and $\cv_\maxfee$ from the opening, and rejects an
identity commitment. It checks that the maximum fee is at most
$\mathsf{MAX\_MONEY}$ and that the change $\maxfee - \fee$ is between zero and
$\mathsf{MAX\_MONEY}$ inclusive. It derives a nonzero $\cm_\chg$ and the fee
digest

$$
d_\fee = \mathsf{Poseidon}_\texttt{Tachyon-FeeDg}\bigl(x(\cv_\maxfee), y(\cv_\maxfee), \fee\bigr),
$$

where $x$ and $y$ are the affine coordinates of the commitment.

It checks the commitments to $A$ and $T$ against the left header, and enforces

$$
S_A = X - d_\fee,
\qquad
S_T = X - \cm_\chg,
\qquad
A' = A \cdot S_A,
\qquad
T' = T \cdot S_T.
$$

The output header carries the commitments to $A'$ and $T'$ and the left
actions' anchor.

$\mathsf{FeeSeed}$ proves a zero-action bundle's zero fee. It has no
predecessors. It witnesses the max fee note opening, the anchor and the two
fee singleton set polynomials. It enforces $\maxfee = 0$. It derives the max
fee commitment, the fee digest and the fee change note commitment as
$\mathsf{FeeFuse}$ does, at a zero fee. The fee change note is then the max fee
note itself. The step checks the two singleton relations, and its `Stamp`
carries the singleton commitments and the witnessed anchor.

The fee steps prove that $d_\fee$ and $\cm_\chg$ come from one max fee note
opening and one fee. Funding comes from the bundle's actions, the binding
signature over the signed max fee commitment, and transaction accounting.

The prover applies $\mathsf{FeeFuse}$ after proving and merging a bundle's
actions, or $\mathsf{FeeSeed}$ when the bundle has none. The proved stamp
carries the applied fee and writes it to `vFeeTachyon` in its trailer.
Changing the fee rebuilds the stamp.

## Coverage

A stamp covers actions and fee descriptors, one fee descriptor for each
covered bundle. The action set holds the action digests and the fee digests.
The tachygram set holds two tachygrams per action and one fee change note
commitment per bundle. A stamp covering $N$ actions in $B$ bundles therefore
publishes $2N + B$ tachygrams. A zero-action bundle stamped on its own has
$N = 0$ and $B = 1$ and publishes one tachygram.

The stamp does not publish its action set commitment. Consensus rebuilds the
action set from the published action descriptors and fee descriptors,
recomputes the commitment, and checks the proof against it. Consensus rejects a
repeated fee descriptor, as it rejects a repeated action. An accepted proof
therefore covers each signed $\cv_\maxfee$ at its published fee.
[Bundles](./bundle.md#stamp-trailer) defines `hStampCoverageTachyon`, which
digests the same action descriptors and fee descriptors.

$\mathsf{FeeFuse}$ accepts only `Actions`. It applies at most once in any
lineage. Merging and lifting carry fee digests and fee change
note commitments like any other set members. A merge keeps the receiving
stamp's fee. Stripping carries the fee into the stripped trailer. An innocent
aggregate proves its own zero fee with $\mathsf{FeeSeed}$ and merges the
adjuncts' stamps into that stamp, as
[Aggregation](./aggregation.md#merge-to-produce-aggregate) describes.

## Balance

A bundle contributes $v^{bal} + \fee$ to the transaction balance.
The fee steps prove that the fee change note keeps $\maxfee - \fee$ in
the pool. The pool's net outflow is therefore

$$
\sum v_{in} - \sum v_{out} - (\maxfee - \fee) = v^{bal} + \fee.
$$

At the transaction level, pool balances sum to a non-negative total fee.
