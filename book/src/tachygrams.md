# Tachygrams

A tachygram is an opaque Poseidon $\mathbb{F}_p$ commitment to the creation or destruction of a note[^notes].

A Tachyon transaction publishes each action's tachygram pair alongside its value commitment and action key, and its fee change note commitment beside the fee in the stamp trailer.

Every action publishes exactly two tachygrams, whichever kind it is.

An output action publishes its note commitment and a padding tachygram.

$$
\mathsf{tg}_0 = \mathsf{cm} =
    \mathsf{Poseidon}_\texttt{Tachyon-CmDerive}(
        \mathsf{rcm}, \mathsf{pk}, v, \psi
    )
$$

$$
\mathsf{tg}_1 = \mathsf{tg}_\bot =
    \mathsf{Poseidon}_\texttt{Tachyon-CmOutPad}(
        \mathsf{rcm}, \mathsf{pk}, v, \psi
    )
$$

The pad commits to the note opening rather than to $\mathsf{cm}$. A pad derived as $\mathsf{tg}_\bot = H^\mathsf{pad}(\mathsf{cm})$ would let an observer test the published pair for that relation and identify an output. Deriving both from the opening hides which member is the commitment and whether the action is an output.

A spend action publishes a nullifier for the present epoch and one for the next[^nullifiers].

$$
\mathsf{tg}_0 = \mathsf{nf}_e, \qquad \mathsf{tg}_1 = \mathsf{nf}_{e+1}
$$

Each action digest absorbs the pair as $(\mathsf{tg}_0 + \mathsf{tg}_1, \mathsf{tg}_0 \mathsf{tg}_1)$, binding its members without their order. The wire encodes the pair in strictly ascending order by bytewise comparison of the 32-byte little-endian encodings. Both action kinds publish two members, concealing the split between spends and outputs in one version of a transaction.

An observer learns which two tachygrams belong to each action and which tachygram is each bundle's fee change. Re-proving a spend at another epoch replaces its pair, while an output keeps its pair. Comparing two versions therefore identifies the spend and output actions. A fee change alone leaves the action pairs unchanged.

## Tachygram sets

An intermediate `Actions` proof, built from actions and merges before the bundle's fee is applied, contains the two tachygrams of every action it covers.

A published stamp has every covered bundle's fee applied. Its tachygram set is the union of the covered actions' pairs and each covered bundle's [fee change note](./fee.md#fee-change-note) commitment. These members are read from the covered bundles[^bundle]; the stamp carries only their set commitment. Ideally, the consensus chain contains aggregated[^aggregation] bundles.

The stamp proof binds a commitment to the unordered set of those tachygrams.

$$
\mathsf{tachygram\_acc}(X) =
   \prod_i \left(
      X - \mathsf{tg}_i
   \right)
$$

This set is the atomic unit which folds into pool state to contribute to the anchor[^anchor].

## Consensus validation

Consensus derives the union from the covered bundles, rejects any member repeated within it, and checks its commitment against the stamp's carried commitment. It also checks that every member is absent from every block of the current epoch and the immediately preceding epoch. A duplicate within that two-epoch window is rejected.

The window spans two epochs because a stamp can republish a tachygram in two distinct ways.

A stamp's anchor may have been advanced within its epoch via `ActionLift` or `StampLift`[^proof-tree], so the stamp could have been built at any earlier height in the same epoch. Consensus therefore scans every block in the anchor's epoch, not just blocks after the anchor.

A spend publishes a nullifier for the current epoch and one for the next epoch[^nullifiers-pair]. The next-epoch nullifier published in epoch $e$ is the present-epoch nullifier that any later spend of the same note would have to publish in epoch $e+1$. Including the previous epoch in the check catches that collision.

[^notes]: See [Notes](./notes.md) for the note's field structure: $\mathsf{pk}$, $v$, $\psi$, $\mathsf{rcm}$.

[^nullifiers]: [Nullifiers](./nullifiers.md) gives the derivation of $\mathsf{nf}_e$ from the note's master key, and why a spend publishes the pair rather than one value.

[^aggregation]: See [Aggregation](./aggregation.md) for how stamps merge their tachygram sets.

[^bundle]: See [Bundle](./bundle.md) for the on-wire encoding of bundles and the layout of a stamp trailer.

[^anchor]: See [Anchor](./anchor.md) for the Poseidon chain that absorbs each stamp's tachygram-set commitment.

[^proof-tree]: See [Proof Tree](./proof-tree.md) for how `ActionLift` and `StampLift` advance an anchor within an epoch.

[^nullifiers-pair]: See [Nullifiers](./nullifiers.md) for the present/future nullifier pair published with each spend.
