# Dynamic Fee

A wallet signs a maximum fee once. The fee is chosen later, at or below that
maximum, without signing again. The difference returns to the wallet as a
fee change note.

The fee is local to the Tachyon bundle, and only its maximum is signed.

## Terms

- **Max fee note**: the note that reserves $\maxfee$. It is published only as
  `cvFeeMaxTachyon` and is never spent.
- **Fee change note**: the spendable note worth $\maxfee - \fee$, paid to the
  max fee note's owner. It is published only as its commitment $\cm_\chg$
  (`cmChange`), a tachygram.
- **Fee descriptor**: the pair $(\cv_\maxfee, \fee)$ on the bundle, published
  as `cvFeeMaxTachyon` and `vFeeTachyon`.
- **Fee digest**: the Poseidon digest $d_\fee$ of a fee descriptor.

## Max Fee Note

Every bundle carries one max fee note, an opening $(\pk, \maxfee, \psi, \rcm)$.
Its value $\maxfee$ is the maximum fee and may be zero, and its payment key
$\pk$ owns the fee change note. The bundle publishes only its value commitment

$$
\cv_\maxfee = [-\maxfee]\,\mathcal{V} + [r]\,\mathcal{R},
\qquad
r = \mathsf{Poseidon}_\texttt{Tachyon-FeeBlind}(\pk, \psi, \rcm),
$$

with $r$ embedded in the scalar field.
The blind binds the fee change note's owner fields into $\cv_\maxfee$. Each
max fee note takes a fresh secret $\rcm$, because reusing an opening reuses
$r$.

[Bundles](./bundle.md#wire-format) gives the wire layout. A bundle with no
actions has a zero value balance and a zero $\maxfee$.

## Signing

The bundle commitment absorbs $\cv_\maxfee$ and not the fee. Signing fixes the
maximum fee and the fee change note's owner.

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

## Fee Change Note

The fee $\fee \leq \maxfee$ is chosen after signing. The fee change note
$(\pk, \maxfee - \fee, \psi, \rcm)$ takes the max fee note's other fields. Its
[note commitment](./notes.md#commitment) $\cm_\chg$ appears only as a
tachygram. A fee equal to $\maxfee$ leaves a zero-valued fee change note, which
still has its tachygram.

$\mathsf{FeeValueCommit}$ consumes the private three-stage R certificate
for $r$ and witnesses $\maxfee$. It bounds the maximum, computes the 17
negative-value windows, and adds the certified R product. Its private
$\mathtt{FeeValueOpening}$ carries $(\maxfee, \mathsf{lo}, \mathsf{hi}, \cv_\maxfee)$.
The commitment is finite.

$\mathsf{FeeBind}$ consumes this opening and witnesses the max fee note and
$\fee$. It requires the note's maximum to match the header, bounds
$\maxfee$, $\fee$ and $\maxfee-\fee$ to $[0,\mathsf{MAX\_MONEY}]$, and
derives $r$ from the note's owner fields. It compares both canonical integer
limbs of that hash to the opening. From the same owner fields it derives
$\cm_\chg \neq 0$ and the fee digest

$$
d_\fee = \mathsf{Poseidon}_\texttt{Tachyon-FeeDg}\bigl(x(\cv_\maxfee), y(\cv_\maxfee), \fee\bigr),
$$

where $x$ and $y$ are the affine coordinates of $\cv_\maxfee$.
The output is private $\mathtt{FeeReady}$ carrying
$(\maxfee,\fee,d_\fee,\cm_\chg)$.
These preparation steps have no polynomial relations.

$\mathsf{FeeFuse}$ transforms actions. It adds the two certified roots to
their respective sets:

- Left: $\mathtt{Actions}$
- Right: $\mathtt{FeeReady}$
- Output: $\mathtt{Stamp}$
- Witness: the left set polynomials $A$ and $T$ and output set polynomials
  $A'$ and $T'$

It checks the commitments to $A$ and $T$ against the left header, and enforces

$$
A'(z) = A(z)\,(z - d_\fee),
\qquad
T'(z) = T(z)\,(z - \cm_\chg).
$$

The challenge $z$ absorbs all four set commitments. Each polynomial is
queried once. The right-input roots are authenticated before $z$.
The output header carries the commitments to $A'$ and $T'$ and the left
actions' anchor. Builders construct the set polynomials outside steps.

$\mathsf{FeeSeed}$ proves a zero-action bundle's zero fee. Its left input
is the private R certificate and its right input is empty. It witnesses
the max fee note opening, the anchor and both output singleton polynomials.
It enforces $\maxfee = 0$, derives $r$ and compares both limbs to the
certificate. It uses the finite certified R product as $\cv_\maxfee$ and
checks both singleton relations at constant $\fee = 0$. The fee change
note is the max fee note itself. Its $\mathtt{Stamp}$ carries the singleton
commitments and the witnessed anchor.

Applying a fee to existing actions executes six local steps. A zero-action
fee executes four. Both counts include the three R stages.
Scalar limbs and fee preparation headers stay private to the prover.
An aggregator constructs these R stages for its own zero-action fee.
The native mock evaluates owner fields and hashes directly through its
single-stage witness API.

The fee steps prove a local relation, not funding. Funding comes from
the bundle's actions, the binding signature over the signed $\cv_\maxfee$,
and transaction accounting.

The prover applies $\mathsf{FeeFuse}$ after proving a bundle's actions, or
$\mathsf{FeeSeed}$ when it has none. The proved stamp carries the applied fee
and writes it into `vFeeTachyon` in its trailer. Every stamp has its bundle's
fee applied.
**Consensus rebuilds the stamp's action set from the published action
descriptors and fee descriptors, recomputes the action accumulator, and checks
the proof against it.** The stamp does not publish the action accumulator. A
stamp that doesn't cover its bundle's fee descriptor fails, as
[Coverage](#coverage) details. Changing the fee rebuilds the stamp.

## Coverage

A stamp covers actions and fee descriptors, one fee descriptor for each
covered bundle. Consensus rejects a repeated fee descriptor, as it rejects a
repeated action. The action set holds the action digests and the fee digests.
The tachygram set holds two tachygrams per action and one fee change note
commitment per bundle. A stamp covering $N$ actions in $B$ bundles therefore
publishes $2N + B$ tachygrams. [Bundles](./bundle.md#stamp-trailer) defines
`hStampCoverageTachyon`. Consensus rebuilds the coverage and $d_\fee$ from the
published bundles. An accepted proof therefore covers the signed $\cv_\maxfee$
at the published fee. $\mathsf{FeeFuse}$ accepts only $\mathtt{Actions}$, so it
cannot be applied twice to the same lineage. Merging and lifting carry fee
digests and fee change note commitments like any other set members. A merge
keeps the receiving stamp's fee. An unmerge undoes a merge and keeps the
dividend's fee. Stripping carries the fee into the stripped trailer.

## Balance

A bundle contributes $v^{bal} + \fee$ to the transaction balance.
The fee steps prove that the fee change note keeps $\maxfee - \fee$ in
the pool. The pool's net outflow is therefore
$\sum v_{in} - \sum v_{out} - (\maxfee - \fee) = v^{bal} + \fee$. At the
transaction level, pool balances sum to a non-negative total fee.
