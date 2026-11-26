# Dynamic Fee

A wallet signs a maximum fee once. A prover with the max fee note opening and
the bundle's proving inputs can choose any fee up to that maximum and prove it
without another signature. A published stamp alone is not enough to change the
fee. The difference returns to the wallet as a fee change note.

Each Tachyon bundle has its own fee. The signatures bind the maximum, not the
fee itself.

## Terms

- **Max fee note**: the note whose value $\feemax$ sets the maximum fee. It is
  represented by its value commitment `cvFeeMaxTachyon`, not published as a
  separate spendable output.
- **Fee change note**: the spendable note that returns the unspent portion of
  the maximum fee to the max fee note's owner. Its commitment $\cm_\chg$ is
  published as `cmChangeTachyon` in the bundle body's proving section.
- **Fee descriptor**: the bundle's pair $(\cv_\feemax, \fee)$ comprising
  `cvFeeMaxTachyon` in the effecting section and `vFeeTachyon` in the proving
  section.
- **Fee digest**: the Poseidon digest $d_\fee$ that binds a fee descriptor to
  its fee change commitment. It is a member of the stamp's action set.

## Max Fee Note

Every bundle has one max fee note with the opening $(\pk, \feemax, \psi, \rcm)$
and the fields of a [note](./notes.md).
The fee steps require a nonzero trapdoor $\rcm$ in this opening.
The maximum fee can be zero. Its
payment key $\pk$ owns the fee change note. The bundle publishes only the max
fee note's value commitment:

$$
\cv_\feemax = [-\feemax]\,\mathcal{V} + [r]\,\mathcal{R},
\qquad
r = \mathsf{Poseidon}_\texttt{Tachyon-FeeBlind}(\pk, \psi, \rcm),
$$

with $r$ embedded in the scalar field.
At $r \geq 2^{254}$, no 254 bits recompose to the derived digest; at $r = 0$, the blind point is the identity.
In either case the fee step has no satisfying assignment, so the prover cannot produce a valid stamp for that opening.
A uniform $r$ is at least $2^{254}$ with probability about $2^{-129}$ and steering one there takes about $2^{129}$ hashes.
The caller constructs the max fee note and chooses inputs that give $0 < r < 2^{254}$. The planner does not reselect $\rcm$.
The blind binds the fee change note's owner fields into the commitment. Each
max fee note takes a fresh secret $\rcm$ because reusing an opening reuses the
blind.

Consensus requires a bundle with no actions to have a zero
[value balance](./bundle.md#wire-format). With no actions, the
[binding signature](./authorization.md#binding-signature) verifies only if
the value balance plus the maximum fee is zero:

$$
v^{bal} + \feemax = 0
$$

The maximum fee is therefore zero.

## Signing

The [bundle commitment](./authorization.md#bundle-commitment) absorbs
$\cv_\feemax$ but not the fee. Signing fixes the maximum fee and the fee
change note's owner.

The value balance counts the max fee note as an output:

$$
v^{bal} = \sum v_{in} - \sum v_{out} - \feemax.
$$

The binding keys include the max fee note's blind and commitment as one more
output:

$$
\bsk = \sum_i \rcv_i + r,
\qquad
\bvk = \sum_i \cv_i + \cv_\feemax - [v^{bal}]\,\mathcal{V} = [\bsk]\,\mathcal{R}.
$$

Neither key depends on the fee itself.

## Fee Change Note

The fee lies in the range $0 \leq \fee \leq \feemax$ and the fee change note
takes the max fee note's other fields:

$$
(\pk, \feemax - \fee, \psi, \rcm)
$$

Its [note commitment](./notes.md#commitment) $\cm_\chg$ is published as a
[tachygram](./tachygrams.md). A fee equal to the maximum leaves a zero-valued
fee change note, which still has its tachygram. At zero fee, the fee change
note has the same opening as the max fee note.

## Fee Steps

In the [proof tree](./proof-tree.md), `Actions` carries only an
[anchor](./anchor.md) in its header. `Transaction` carries the tachygram
accumulator's [bridge hash](./anchor.md#stamp-absorption) and the anchor in
its header. Both hold the action set as an `ActionSetPoly` and the
[tachygram set](./tachygrams.md#tachygram-sets) as a `TachygramSetPoly`. `FeeFuse` and
`FeeSeed` are the only steps that emit a `Transaction` without taking one as
input. Every stamp descends from one of them.

`FeeFuse` takes `Actions` as its left input, has no right input, and
emits a `Transaction`. It witnesses the max fee note opening and the fee along
with $(A', T')$ for the resulting set polynomials.

The step derives $r$ and $\cv_\feemax$ from the opening and rejects the
identity commitment. It enforces $\feemax \leq \mathsf{MAX\_MONEY}$ and
splits the maximum fee into the fee and the change, enforcing the range
$[0, \mathsf{MAX\_MONEY}]$ for both. It derives the nonzero fee change
commitment $\cm_\chg$ and the fee digest:

$$
d_\fee = \mathsf{Poseidon}_\texttt{Tachyon-FeeDg}\bigl(x(\cv_\feemax), y(\cv_\feemax), \fee, \cm_\chg\bigr),
$$

where $x$ and $y$ give the affine coordinates of the max fee commitment.
The step opens the action and tachygram set polynomials $A$ and $T$ from
the left input's slots and enforces:

$$
A' = A \cdot (X - d_\fee),
\qquad
T' = T \cdot (X - \cm_\chg).
$$

The digest absorbs the same $\cm_\chg$ wire used to form the linear factor in
the resulting tachygram set polynomial. The emitted `Transaction` carries the bridge
hash of the commitment to $T'$ and the left input's anchor.

`FeeSeed` proves a zero-action bundle's zero fee. It has no
predecessors and witnesses the max fee note opening, the anchor, and the two
singleton set polynomials $S_A$ and $S_T$ for the fee. It requires a
zero maximum fee and uses a zero fee, so the fee change note is the max fee
note itself. It derives the max fee commitment, the nonzero fee change
commitment, and the fee digest as `FeeFuse` does. The step checks the
singleton relations:

$$
S_A = X - d_\fee,
\qquad
S_T = X - \cm_\chg.
$$

The emitted `Transaction` carries the bridge hash of the commitment to $S_T$ and
the witnessed anchor.

The fee steps prove that the fee digest and fee change commitment come from
one max fee note opening and one fee. Funding comes from the bundle's
actions, the binding signature, and transaction accounting.

At the level of stamp multisets, replacing a fee adds the new fee leaf and
removes the old one. The holder of the max fee note opening can use `FeeFuse`
to pair each fee leaf with the same auxiliary `Actions` proof at the stamp's
anchor. Adding the new-fee stamp and subtracting the old-fee stamp cancels the
auxiliary leaves. For the temporary merge, the added stamp's action digests
and tachygrams must be disjoint from the original stamp's sets.

The prover applies `FeeFuse` after proving and merging a bundle's
actions, or `FeeSeed` when the bundle has none. The bundle body's
proving section carries the applied fee in `vFeeTachyon` and the fee change
commitment in `cmChangeTachyon`.

## Coverage

A stamp covers one fee descriptor per covered bundle, in addition to the
actions. The action set holds the action and fee digests. The tachygram set
holds two tachygrams per action and one fee change commitment per bundle. A
standalone zero-action bundle has no actions and one covered bundle, so its
stamp covers exactly one tachygram.

The stamp does not carry its action accumulator as a separate wire field.
Consensus rebuilds the stamp's action set from the published action
descriptors and pairs, fee descriptors, and fee change commitments,
recomputes the action accumulator, and checks the proof against it. Consensus
rejects repeated action descriptors, fee descriptors, or tachygrams. Two
fee descriptors with the same max fee commitment and fee count as repeated
even if their change commitments differ. An accepted proof therefore covers
each signed max fee commitment at its published fee and binds the published
fee change commitment.

`FeeFuse` accepts only `Actions`, so it applies at most once per
lineage. Merging and lifting carry fee digests and fee change commitments
like other set members. An innocent aggregate proves its own zero fee with
`FeeSeed` and merges the adjuncts' stamps into that stamp, as
[Aggregation](./aggregation.md#merge-to-produce-aggregate) describes.

Merging, unmerging, lifting, and stripping change only the stamp, leaving
each bundle body's `vFeeTachyon` and `cmChangeTachyon` unchanged. Re-proving
at another fee updates those two fields along with the stamp. For an
unchanged plan and epoch, the action pairs do not depend on the fee.

## Balance

The fee steps prove that the fee change note keeps the unused portion of the
maximum fee in the pool. The pool's net outflow is the bundle's contribution
to the transaction balance:

$$
\sum v_{in} - \sum v_{out} - (\feemax - \fee) = v^{bal} + \fee.
$$

At the transaction level, pool balances sum to a non-negative total fee.
