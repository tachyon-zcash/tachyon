# Dynamic Fee

A wallet signs a maximum fee once. The fee is chosen later, at or below that
maximum, without signing again. The difference returns to the wallet as a
fee change note.

The fee is local to the Tachyon bundle, and only its maximum is signed.
A negative fee pays a claim to the max fee note's owner, normally an
aggregator. [Funding](#funding) relates it to the transaction-wide fee and the
other transactions its stamp covers.

## Terms

- **Max fee note**: the note that reserves $\maxfee$. It is published only as
  `cvFeeMaxTachyon` and is never spent.
- **Fee change note**: the spendable note worth $\maxfee - \fee$, paid to the
  max fee note's owner. It is published only as its commitment $\cm_\chg$
  (`cmChange`), a tachygram.
- **Fee descriptor**: the pair $(\cv_\maxfee, \fee)$ on the bundle, published
  as `cvFeeMaxTachyon` and `vFeeTachyon`. Its fee may be negative.
- **Fee digest**: the Poseidon digest $d_\fee$ of a fee descriptor.
- **Claim**: the amount $\claim=-\fee>0$ paid through a negative fee.
- **Deficit**: $e_T=\max(0,-s_T)$ for a non-coinbase transaction with fee $s_T$.
- **Claim allowance**: $q_T=\min(f_T,s_T)$ when its Tachyon fee $f_T\geq0$,
  and zero otherwise.
- **Coverage group**: a top-level stamped transaction and the stripped
  transactions that name its final `wtxid`. An autonome forms a singleton group.

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

The fee $\fee \leq \maxfee$ is chosen after signing. A negative fee
[claims](#aggregator-claims). The fee change note
$(\pk, \maxfee - \fee, \psi, \rcm)$ takes the max fee note's other fields. Its
[note commitment](./notes.md#commitment) $\cm_\chg$ appears only as a
tachygram. A fee equal to $\maxfee$ leaves a zero-valued fee change note, which
still has its tachygram.

$\mathsf{FeeFuse}$ applies a bundle's fee to its actions. It adds $d_\fee$ to the action
set and $\cm_\chg$ to its tachygram set:

- Left: $\mathtt{Actions}$
- Right: empty
- Output: $\mathtt{Stamp}$
- Witness: the max fee note opening, $\fee$, the left set polynomials $A$ and
  $T$, the output set polynomials $A'$ and $T'$, and the fee singleton set
  polynomials $S_A$ and $S_T$

The step derives $r$ and $\cv_\maxfee$ from the opening, and rejects an
identity $\cv_\maxfee$. It checks $\maxfee \leq \mathsf{MAX\_MONEY}$ and
$\maxfee - \fee \in [0, \mathsf{MAX\_MONEY}]$, and derives $\cm_\chg \neq 0$
and the fee digest

$$
d_\fee = \mathsf{Poseidon}_\texttt{Tachyon-FeeDg}\bigl(x(\cv_\maxfee), y(\cv_\maxfee), \bar\fee\bigr),
$$

where $x$ and $y$ are the affine coordinates of $\cv_\maxfee$. The signed fee
maps to the field as $\bar\fee=\fee$ for $\fee\geq0$, and $\bar\fee=p-|\fee|$
otherwise. This map is injective on
$[-\mathsf{MAX\_MONEY},\mathsf{MAX\_MONEY}]$ because $2\mathsf{MAX\_MONEY}<p$.

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

$\mathsf{FeeSeed}$ is a zero-action bundle's fee. It has no predecessors and
witnesses the max fee note, fee, anchor, $S_A$ and $S_T$. It enforces
$\maxfee = 0$, computes $\cv_\maxfee = [r]\mathcal{R}$ directly, and checks the
same opening and singleton relations. The signed fee and the change range
give $\fee\in[-\mathsf{MAX\_MONEY},0]$. Its $\mathtt{Stamp}$ carries the
singleton commitments and the
witnessed anchor: $N = 0$, $B = 1$, one tachygram.

The fee steps prove a local relation, not funding. Funding comes from
the bundle's actions, the binding signature over the signed $\cv_\maxfee$,
and transaction accounting.

The prover applies $\mathsf{FeeFuse}$ after proving a bundle's actions, or
$\mathsf{FeeSeed}$ when it has none. Proving returns the stamp and the applied fee together, and attaching
writes that fee into `vFeeTachyon`. Every stamp has its bundle's fee applied.
**Consensus rebuilds the stamp's action set from the published action
descriptors and fee descriptors, recomputes the action accumulator, and checks
the proof against it.** The stamp does not publish the action accumulator. A
stamp that doesn't cover its bundle's fee descriptor fails, as
[Coverage](#coverage) details. To reprice, prove again with the new fee. A
based aggregate also retains the merged stamp of the bundles it covers and
reruns one root merge.

$\mathtt{Actions}$ and $\mathtt{Stamp}$ make the pre-fee and post-fee states
proof-enforced. Coverage comes from the consensus reconstruction above.

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
cannot be applied twice to the same lineage. $\mathsf{StampMerge}$ combines
fee-bearing lineages. Two lineages that each apply the same bundle's fee merge
into a stamp whose second fee digest and fee change note no published bundle
accounts for. Merging and lifting carry fee digests and fee change note commitments
like any other set members. Stripping keeps the fee descriptor in the bundle body.

Duplicate detection compares pairs $(\cv_\maxfee,\fee)$, not commitments alone.
Two distinct fees at the same commitment require separate proof factors.
Wallets use fresh max fee openings: reusing an opening reuses the payout's
nullifier identity. Coverage counts each payout once per accepted aggregate;
the block's tachygram replay check still applies across aggregates.

## Balance

A bundle contributes $v^{bal} + \fee$ to the transaction balance.
The fee steps prove that the fee change note keeps $\maxfee - \fee$ in
the pool. The pool's net outflow is therefore
$\sum v_{in} - \sum v_{out} - (\maxfee - \fee) = v^{bal} + \fee$.
The signed $v^{bal}+\fee$ enters the Tachyon pool accounting once per bundle,
including stripped bundles. The aggregate's stamp does not charge its adjuncts again.
At the transaction level, a fee may be negative only as [Funding](#funding) permits.

## Aggregator Claims

An aggregator claims with $\fee=-\claim$ on its own bundle. Its fee change
note is worth $\maxfee+\claim$ and pays the owner fixed by the signed
$\cv_\maxfee$ through $r=\mathsf{Poseidon}_\texttt{Tachyon-FeeBlind}(\pk,\psi,\rcm)$.
The change range requires $\claim\leq\mathsf{MAX\_MONEY}-\maxfee$.
Max fee and change ranges give the integer equation
$\maxfee=\fee+\mathsf{change}$ for either sign, since $3\mathsf{MAX\_MONEY}<p$.

A based aggregator runs `FeeFuse` on its own actions at the negative fee.
An innocent runs `FeeSeed` with $\maxfee=0$, so its payout is exactly $\claim$.
Both then merge their stamp with the stamps of the bundles they cover. The fee
descriptor and the fee change note commitment record the claim.
To change the fee, prove again and rerun the aggregate's root merge.

### Funding

For a non-coinbase transaction $T$, let $f_T$ be its Tachyon fee, or zero
without a Tachyon bundle. Let $s_T$ be the transaction fee: its Tachyon
contribution $v^{bal}+f_T$ plus all other pools' balances, including
transparent inputs minus outputs. Every transaction independently satisfies

$$
s_T\geq\min(0,f_T).
$$

Its deficit and claim allowance are

$$
e_T=\max(0,-s_T),\qquad
q_T=\begin{cases}\min(f_T,s_T)&f_T\geq0,\\0&f_T<0.\end{cases}
$$

Every final coverage group $G$ satisfies

$$
\sum_{T\in G}e_T\leq\sum_{T\in G}q_T,
$$

over non-coinbase transactions only. A deficit needs a negative fee; an
allowance needs a positive fee. The stamp covers both through their descriptors.
The cap at $s_T$ prevents spending a payer's fee twice, on other-pool outputs
and on a claim. A group uses no other group's allowances.

Write $b_T=s_T-f_T$ for the balance before the fee. A claimant has $b_T\geq0$
and deficit $e_T=\max(0,\claim-b_T)$. Its own transaction can fund part or all
of its payout. A self-funded negative-fee autonome needs no other transaction.
An innocent with no other-pool activity has $b_T=0$, so its group funds the
whole claim. A zero-fee innocent gives no allowance and runs no deficit.
Other-pool surplus with $f_T=0$ gives no allowance: $q_T=\min(0,s_T)=0$.

Payers with fees 7 and 5 and $b=0$ fund an innocent claim 9; the miner receives 3.
An inner group with payer 7 and claim 9 fails funding alone. With an outer
payer 5 and claim 3, the final flattened group passes at equality; an outer
claim 4 fails. Intermediate proofs remain valid: funding checks the published
group, not each proof subtree.

For the cross-pool attack, a payer has $v^{bal}=0$, $f=10$ and an other-pool
output of 10. It has $s=0$ and $q=0$. It is valid alone, but cannot also fund
an innocent claim 10, whose deficit is 10. An unfunded max fee note with
$v^{bal}=-10$, $f=10$ and no other-pool activity likewise gives no allowance.
A claimant cannot use group funding for an unrelated other-pool deficit:
$s\geq f$ requires its $b\geq0$.

For each group the value leaving all pools is

$$
\sum_T s_T = \sum_{s_T\geq0}s_T-\sum_T e_T
\geq\sum_T q_T-\sum_T e_T\geq0.
$$

The binding signature gives $\sum v_{in}-\sum v_{out}-\maxfee=v^{bal}$; the fee proof gives the
change note $\maxfee-f_T$. Together these give actual Tachyon outflow
$v^{bal}+f_T$. Adding the other pools gives $s_T$, so the group creates no
unfunded value. Consensus sums with checked wide signed arithmetic.

The block fee total is the signed sum of its non-coinbase transaction fees.
The coinbase reward limit uses that total plus subsidy. Coinbase supplies no
allowance; its outputs, including its fee change note, count against that
limit. Whether coinbase may use a negative fee under the limit is a
transaction-layer decision.

These checks belong to node consensus. `Bundle::verify` checks the top-level
bundle's signatures, the adjunct pointers, coverage, tachygrams and proof. The node also validates every
adjunct's signatures, other-pool activity, transaction balance, group funding
and block accounting. A proof by itself establishes no funding.

### Encoding and Activation

`vFeeTachyon` is a little-endian i64 in
$[-\mathsf{MAX\_MONEY},\mathsf{MAX\_MONEY}]$, like `valueBalanceTachyon`.
It is authorization data in the bundle body, retained after stripping.
The descriptor and auth digest use those same eight bytes; the Poseidon fee
digest uses $\bar\fee$.

The consuming node activates signed decoding and these funding rules together
at the network upgrade. The crate decodes only the signed form.
