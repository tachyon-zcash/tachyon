# Dynamic Fee

## Motivation

Block space is limited. Zcash should adjust its network fee to keep demand and
supply in balance. When demand is high, blocks are oversubscribed and the
mempool fills with pending transactions. The fee should then increase to
prevent DOS. Beyond eventual inclusion, a transaction should also be able to bid
for *earlier inclusion* with a higher fee.

The current fee mechanism ([ZIP-317](https://zips.z.cash/zip-0317)) uses a
simple formula, `fee = marginal_fee * max(2, num_actions)`, with a flat
per-action fee `marginal_fee = 5000 zatoshi`. The fee is set implicitly as
$v^{bal} = \sum v_{in} - \sum v_{out}$. It is enforced explicitly by the
binding signature over $\bvk$, which is derived from all value commitments
$\{\cv_i\}$ in the bundle.

Ideally, a wallet authorizes a **max fee** once. A lower actual fee is then
chosen dynamically at spend-time *without re-signing*.

## Design Rationale

First, we should agree that the goal is *possible*. We can change the consensus
rule to interpret the signed message differently: as a ceiling instead of a
fixed fee.

Second, the fundamental challenge of the dynamic fee is this:
*the transaction is authorized before the fee-change output note is created*.
Readers should pause and let the challenge sink in.
The authorization signature signs over `SIGHASH`, which includes all *effecting
data* of the transaction. This effecting data binds, indirectly, to the
commitments $\{\cm\}$ of all spend and output notes. The note commitment of the
fee-change is unknown at authorization time. Obviously, we cannot bind it into
the `SIGHASH`.

The implicit fee no longer works, because it specifies only a value. The
fee-change note also needs the owner's $\pk$, among other fields. This motivates
us to externalize the max fee into an output note with an explicit max fee and
an explicit fee-change owner. This differs from
[ZIP-2002](https://zips.z.cash/zip-2002). Its explicit fee is transaction-wide
and committed to `SIGHASH`. Ours is Tachyon-local, and only its ceiling is
signed. How to reconcile the two is left open.
We immediately run into another challenge. This "max fee note" is consumed in
the same block it is created in. We therefore cannot treat it as a normal note,
whose commitment enters the tachygram accumulator before we prove its existence
against it. Instead, we bypass the inclusion integrity mechanism entirely. We
make `cm` public when we "spend" the max-fee note into a fee-change note.

## Tachyon Background

We recall the relevant background and terminology from
[the Tachyon design](./revisit.md#tx).

A tachyon note is a tuple:

$$
\mathsf{Note}^\mathsf{Tachyon} := (\pk, v, \psi, \rcm)
$$

where $\pk$ is the payment key, $v$ is the value of the note,
$\psi$ is a pseudo-random note identity that binds to the note nullifier value
as an input to its derivation, and $\rcm$ is a random commitment trapdoor.

Each Tachyon action, spend or output, is uniformly represented by a pair
$(\rk, \cv)$. Here $\rk$ is the randomized spend validating key, whose
derivation *binds to the underlying note*, and $\cv$ is a blinding commitment to
the net value. Tachyon does not keep $\cm$ in the action description. Instead,
it binds the note to $\rk$ through its randomizer $\alpha$:

$$
\begin{cases}
\rk = [\ask + \alpha]\,\G \;\;\text{(spend)}
\qquad
\rk = [\alpha]\,\G \;\;\text{(output)}\\
\alpha = \PRF(\cm \| \theta)  \quad\theta\text{: arbitrary entropy}
\end{cases}
$$

All non-malleable parts of a transaction, known as *the effecting data*, hash
into a stable identifier `txid`. Each authorization signature signs over
`SIGHASH`. The `SIGHASH` commits to the same transaction-wide effecting data,
across all pools, that derives each pool-specific `txid`.

Specifically, `txid` commits to
$(\actacc \| v^{bal} \| \mathsf{da\_digest})$.
Here $\mathsf{da\_digest}$ is the digest of opaque data-availability bytes, and
$\actacc$ commits to all Action descriptions $\{(\rk_i, \cv_i)\}$ as follows:

$$
\actacc = \mathsf{Com}\left(\prod_i (X-a_i) \right)
\quad\text{where }
a_i = \mathsf{Poseidon}(\rk_i, \cv_i).
$$

## Proposal

Every Tachyon bundle, consisting of Spend and Output actions, should contain a
dedicated **fee note**. Its payment key $\pk$ is the intended fee-change owner.
Its note value $v = \maxfee$ is the maximum fee.
For a Tachyon-only transaction, an honestly constructed bundle then has
$v^{bal} = 0$.

### Changes to signing

The new identifier `txid` covers the same Tachyon-specific effecting data that
underlies the `SIGHASH`. It now commits to:

$$
(\underbrace{\quad \actacc \quad}_{\text{excluding fee note}} \|\,
\underbrace{\cm_\maxfee \,\|\, \cv_\maxfee}_{\text{fee note's effecting data}} \|\quad
\underbrace{v^{bal}}_{\text{fee note counted as output}} \|\,
\underbrace{\mathsf{da\_digest}}_{\text{unchanged}})
$$

Notice that we single out the fee note from $\actacc$ and reveal its
$\cm_\maxfee$ directly. A consensus node can then check it against the same
field in the public input of the PCD proof. There is another reason to
externalize $(\cm_\maxfee, \cv_\maxfee)$: they never show up in the final
$\actacc$. The fee note is authorized but _ephemeral_. As for $v^{bal}$, it is
the pool's net balance with the fee note counted as an output. It is $0$ for a
Tachyon-only transaction. It has either sign in a cross-pool transaction:
negative when shielding into Tachyon, positive when value leaves it. The
transaction-level rule is unchanged: pool balances sum to a non-negative total
fee.

Therefore, an authorization signature over these preimages should be
interpreted as:

> I authorize all actions accumulated in $\actacc$ and a fee note $\cm_\maxfee$
> carrying the maximum fee I'm willing to pay and the return payment key for any
> future fee-change. All actions, assuming maximum fee spent, amounts to a value
> balance of $v^{bal}$.

### Changes to proving

Our current PCD tree culminates in a proof-carrying header:

$$
\mathtt{Stamp} \{\actacc,\tgacc,\anchor\}
$$

Every valid spend or output action produces the same $\mathtt{Stamp}$ header.
When we assemble a Tachyon bundle, we merge the stamps of all picked actions
into a final $\mathtt{Stamp}$ proof with the $\mathsf{StampMerge}$ step, as
[shown here](./revisit.md#same-epoch-spend).

At spend-time, the wallet dynamically chooses a $\fee \leq \maxfee$. It
prepares a **fee-change note** with $v^\chg = \maxfee - \fee$. The other fields
are identical to those of the **fee note** we created earlier.
The PCD proof for all actions except the fee-change note is prepared as before.
To roll in the fee-change note, we introduce a new PCD step
$\mathsf{MergeFeeStamp}$:

- Left: $\mathtt{Stamp}$ for the rest of the Tachyon bundle
- Right: empty
- Output: a new header
  $$
  \mathtt{StampWithFeeChg}(\actacc, \tgacc, \anchor, \cm_\maxfee, \cv_\maxfee, \fee)
  $$
- The step circuit enforces:
  - folds the left and right child PCD proofs
  - integrity of $\cm_\maxfee$ and $\cv_\maxfee$, by re-committing the fee note
    opening
  - integrity of $\cm_\chg$, by re-committing the fee-change note opening
    - the fee-change's $\pk, \psi, \rcm$ are the same as the fee note's.
    - $\fee = \maxfee - v^\chg$ with $0 \leq v^\chg \leq \maxfee$,
      so $\fee$ cannot wrap negative in the field and mint value.
  - the action description accumulator passes through unchanged:
    $\mathtt{Output}.\actacc = \mathtt{Left}.\actacc$
  - correct update of the tachygram accumulator:
    - with Ragu's poly oracles, given that $\mathtt{Left}.\tgacc$ and
    $\mathtt{Output}.\tgacc$ are the commitments to $f_\tg(X)$ and $f_\tg'(X)$
    respectively:
    $$
    f_\tg'(X) = f_\tg(X) \cdot \Big( X - \cm_\chg \Big)
    $$
    Notice that we do not need to dummy-pad the tachygram count for the
    fee-change output. It is a universal output, so it does not leak arity.

The fee-change note is *not* an action. It carries no $(\rk, \cv)$ pair and
never enters $\actacc$. An action description exists to be signed and to feed
the binding signature. Neither applies here. The fee-change is unsigned by
design. Its funding is already authorized through $\cv_\maxfee$. Its value
commitment follows from public data as $\cv_\maxfee + [\fee]\,\G$. The only new
public facts are $\cm_\chg$, bound through $\mathtt{Output}.\tgacc$, and $\fee$
on the header.

### Changes to consensus validation

During authorization signature verification, validators take the fields
$\actacc, \cm_\maxfee, \cv_\maxfee$ from the stamp $\mathtt{StampWithFeeChg}$
and assemble the `SIGHASH` preimage.

During binding signature verification, the effective value balance is
$v^{bal} + \fee$. Here $v^{bal}$ is the value used in `SIGHASH` (and `txid`),
and $\fee$ comes from the header $\mathtt{StampWithFeeChg}$. Equivalently,
given all $\{\cv_i\}$ of the published actions accumulated in $\actacc$ and
the implied fee-change commitment $\cv_\maxfee + [\fee]\,\G$:

$$
\bvk = \sum_i \cv_i + \cv_\maxfee + [\fee]\,\G - [v^{bal} + \fee]\,\G
= \sum_i \cv_i + \cv_\maxfee - [v^{bal}]\,\G
$$

The right-hand side is exactly the key the wallet signed under at
authorization time. The binding signature is therefore produced once, together
with the authorization signatures, and needs no update when $\fee$ is chosen.
Only the effective balance $v^{bal} + \fee$ depends on $\fee$. Consensus feeds
it into the transaction-level fee and turnstile accounting.

After successful verification of the PCD proof for $\mathtt{StampWithFeeChg}$,
the validator absorbs the $\tgacc$ field into the anchor chain state. This
field includes the spend-time fee-change commitment $\cm_\chg$.
