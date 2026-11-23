# Tachygrams

A tachygram is an opaque Poseidon $\mathbb{F}_p$ commitment to the creation or destruction of a note[^notes].

A Tachyon transaction publishes each action's tachygram pair in `vActionTachygramsTachyon`, in action order, and its fee change note commitment in `cmChangeTachyon`. Both are in the bundle body's proving section and remain when the stamp is stripped.

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

Each action digest absorbs the pair as $(\mathsf{tg}_0 + \mathsf{tg}_1, \mathsf{tg}_0 \mathsf{tg}_1)$, binding its members without their order. The prover writes each pair smaller tachygram first, so the published order reveals neither member's role; the encoding does not require it. Both action kinds publish two members, concealing the split between spends and outputs in one version of a transaction.

An observer learns which two tachygrams belong to each action and which tachygram is each bundle's fee change. Re-proving a spend at another epoch replaces its pair, while an output keeps its pair. Comparing two versions therefore identifies the spend and output actions. A fee change alone leaves the action pairs unchanged.

## Tachygram sets

An intermediate `Actions` proof, built from actions and merges before the bundle's fee is applied, contains the two tachygrams of every action it covers.

A published stamp has every covered bundle's fee applied. Its tachygram set is the union of the covered actions' pairs and each covered bundle's [fee change note](./fee.md#fee-change-note) commitment. These members are read from the covered bundle bodies[^bundle], each of which carries its own bundle's pairs and fee change; the covering stamp carries only the set commitment, not the members. Ideally, the consensus chain contains aggregated[^aggregation] bundles.

The stamp proof binds a commitment to the unordered set of those tachygrams.

$$
\mathsf{tachygram\_acc}(X) =
   \prod_i \left(
      X - \mathsf{tg}_i
   \right)
$$

This set is the atomic unit which folds into pool state to contribute to the anchor[^anchor].

## Consensus validation

Consensus derives the union from the covered bundles, rejects any member repeated within it, and checks its commitment against the stamp's carried commitment. Consensus also enforces [anchor recency and chain membership](./anchor.md#intra-block-state-vs-end-of-block-anchor), and checks that every member of the union is absent from every earlier stamp of the current epoch and the immediately preceding epoch, including earlier stamps of the same block. A duplicate within that two-epoch window is rejected.

A spend anchored at epoch $a$ publishes $\mathsf{nf}_a$ and $\mathsf{nf}_{a+1}$ and its spendable lineage proves $\mathsf{nf}_x$ unpublished in each epoch $x$ from the note's creation up to $a$ excluding $a$ itself. Anchor recency requires a stamp published in epoch $p$ to anchor at epoch $p$ or its predecessor[^anchor].

If a second spend of the same note anchors after the first spend's publication epoch $p_1$ then its lineage tests $\mathsf{nf}_{p_1}$ against epoch $p_1$ and rejects because recency places $p_1$ in

$$
\{a_1, a_1 + 1\}
$$

so epoch $p_1$ holds $\mathsf{nf}_{p_1}$ already. Otherwise its anchor epoch $a_2$ and publication epoch $p_2$ satisfy

$$
a_2 \leq p_1, \qquad p_2 \leq a_2 + 1 \leq p_1 + 1, \qquad a_2 \in \{a_1 - 1, a_1, a_1 + 1\}
$$

by recency, so the two spends share $\mathsf{nf}_{a_1}$ or $\mathsf{nf}_{a_1+1}$ within the two-epoch window[^nullifiers-pair].

Scanning every earlier stamp of the current epoch, not just those after the anchor, catches a second spend anchored in the same epoch as the first, because neither lineage covers its own anchor epoch. Including the preceding epoch catches the cases where recency places the two publications in consecutive epochs, whether both spends anchor in $e$ with the second published in the next epoch or the first anchors in $e$ and is published in the next epoch while the second anchors in that epoch and is published one epoch later.

[^notes]: See [Notes](./notes.md) for the note's field structure: $\mathsf{pk}$, $v$, $\psi$, $\mathsf{rcm}$.

[^nullifiers]: [Nullifiers](./nullifiers.md) gives the derivation of $\mathsf{nf}_e$ from the note's master key, and why a spend publishes the pair rather than one value.

[^aggregation]: See [Aggregation](./aggregation.md) for how stamps merge their tachygram sets.

[^bundle]: See [Bundle](./bundle.md) for the phase-ordered body and the stamp trailer.

[^anchor]: See [Anchor](./anchor.md) for the Poseidon chain that absorbs each stamp's tachygram-set commitment and the anchor-recency rule.

[^nullifiers-pair]: See [Nullifiers](./nullifiers.md) for the present/future nullifier pair published with each spend.
