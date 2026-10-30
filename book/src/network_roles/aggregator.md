# Aggregator

Several aggregators can work on the same [autonomes](../aggregation.md#bundle-states) at once, and a miner can include parts of several aggregates in one block.
Blocks keep landing while aggregates are being built.
This page describes how an aggregator works in that environment so that its proving work survives, other aggregators can reuse it, and nobody depends on a builder who keeps proofs to itself.
It relies on `StampUnmerge`, described in [Stamp construction](../proof-tree.md#stamp-construction), to remove mined bundles from an aggregate.

## The life of an aggregate

Wallets publish autonomes $X$ and $Y$ to the mempool.
An aggregator proves its own bundle $A$, which carries its own actions and fee, or only a fee if it has no actions of its own.
It merges the three stamps.
The merged stamp sits on $A$ and covers the actions and fees of $A$, $X$ and $Y$.

The aggregator publishes $A$ with that stamp.
A miner that includes it also includes $X$ and $Y$ as [adjuncts](../aggregation.md#strip-to-produce-adjuncts), with their stamps stripped and replaced by pointers to $A$.
If another aggregator merges $A$ into something larger first, $A$ becomes one of its adjuncts in turn.

Folding its own actions into $A$ is one of the reasons to aggregate.
The aggregate carries finished proving work.
That makes it a more attractive thing for the next aggregator or miner to take on than a bare autonome, and $A$'s own actions get mined along with it.

## Publish, relay and cache

Publish complete autonomes and aggregates to the mempool.
An aggregator that receives an autonome directly relays it to the mempool before or when it merges it.
Direct submission to a miner is for a specific operational reason, and it does not stop anyone from regrouping what was sent.

Anyone who holds $A$'s stamp and the stamps of $X$ and $Y$ can divide $X$ and $Y$ out and get a stamp for $A$'s own actions and fee, even though $A$'s builder never published one.
That is intended.
Others can then include $A$'s bundle on its own or inside their own aggregate.
The signed actions are unchanged, and getting them mined is what $A$'s builder wanted.
The grouping is not something it keeps.

Call an aggregate transparent to a participant when that participant holds, or can derive, a stamp for each of the other bundles it covers at the fee the aggregate selected.
A transparent aggregate can be split into any subset of its bundles by that participant without asking the builder for anything.

Two things make aggregates transparent in practice.

- Keep every input you merged and the order you merged them in, with the signed bundles, their descriptors and the fee each was merged at.
- Cache recent mempool autonomes and aggregates.

Hold both until the end of the epoch after the working aggregate's anchor epoch.
After that the aggregate can no longer be published.

Keep quotients and partial merges to yourself.
Publish only complete autonomes and aggregates.
A released intermediate is a divisor someone else can use.

## Choosing what to merge

Work at a current-epoch [anchor](../anchor.md) and lift every input to it before merging.
Lifts cannot cross an [epoch boundary](../anchor.md#epoch-boundary).
An aggregate started in one epoch is finished within the following epoch or rebuilt.

Compare candidates' [tachygrams](../tachygrams.md) with each other and with the working aggregate, and merge a disjoint set.
Keep the stamps of the overlapping candidates you passed over.
The block may include one of those instead.

Merge another aggregator's aggregate only if it is transparent to you, or if you are willing to drop it whole later.
Its builder may hold back a component proof, and then it can split its aggregate in ways nobody else can reproduce.
If cooperative aggregators decline to stack such aggregates, the cost of withholding falls on the one withholding.

## When a block lands

Call the working stamp $W$.
Find which of $W$'s bundles the block includes by comparing action descriptors, which are public on both sides.
Compare fees separately, because the block may carry a bundle at a different fee than $W$ holds it at.
Compare tachygrams too, because a conflicting spend of the same note has a different descriptor and the same nullifiers.
Every match has to come out of $W$ before $W$ can be published, because consensus rejects a tachygram published twice within [two epochs](../tachygrams.md#consensus-validation).

What comes out is the bundle as it was merged into $W$, at the fee $W$ holds.
The stamp in the block may cover other bundles or carry a different fee.
It is the right divisor only when it covers exactly what $W$ holds.

The simple case is a block that includes $X$ as an autonome.
The cached stamp of $X$, or the one in the block, divides $W$:

$$
Q = \frac{W}{\operatorname{stamp}(X)}, \qquad Q \text{ covers } A \text{ and } Y.
$$

$Q$ replaces $A$'s stamp and building continues.
The next publication covers $A$ and $Y$.

In general there are three cases, decided by one question.
Is there a stamp in hand, or in the block, that covers exactly the bundles to remove?

- **Easy.** Yes. Divide once.
- **Medium.** No, but one can be built by merging stamps you hold or can derive. Build it and divide. Another route is to merge into $W$ a stamp for whatever the block's aggregate covers beyond $W$, and then divide by the block's stamp.
- **Hard.** Neither. Divide out a larger input you kept that contains the mined bundles, losing its unmined bundles with it, or rebuild from cached autonomes and the inputs that are still good.

| Merged into $W$ | Block includes | Case |
| --- | --- | --- |
| autonome $X$ | $X$ as an autonome | easy, divide by $X$ |
| autonomes $X, Y, Z$ | an aggregate covering exactly $X, Y, Z$ | easy, divide by that aggregate |
| aggregate $G$ | $G$ unchanged | easy, divide by $G$ |
| aggregate $G$ | $X$, one of $G$'s adjuncts, as an autonome | easy, divide by $X$ |
| aggregate $G$ | $G$ and all it covers, inside a larger aggregate | easy, divide by $G$ |
| autonomes $X, Y$ | aggregate $Z$ covering $Z, X, Y$, with $Z$ not in $W$ | medium, merge $X$ and $Y$ and divide |
| aggregate $G$ covering $G, X, Y, Z$ | $G$ regrouped with $X$ and $T$, maybe at a new fee | medium if $Y$ and $Z$ are cached, hard otherwise |
| aggregate $G$ | some of $G$'s bundles, with a needed stamp withheld | hard |
| inputs whose stamps were discarded | no exact divisor in the block | hard |
| anything anchored in epoch $e$ | a block past the end of epoch $e + 1$ | $W$ is dead, rebuild in the new epoch |

The regrouped row is the common way to end up in the medium case.
$G$'s builder kept going and the block includes $G$'s bundle with a different set of adjuncts.
What has to come out of $W$ is $G$'s bundle at its old fee, plus $X$.
Divide the $G$ stamp you kept by the cached stamps of $Y$ and $Z$, and the result covers exactly that.
Divide $W$ by it.
The new fee in the block plays no part.

Prefer an exact divisor, then a built one, then dropping a larger input.
Rebuild instead when that is less work than the divisions and merges needed.

$Q$ can go back on $A$ only if it still covers $A$'s own actions and fee.
If the block included $A$'s bundle too, the remaining work has to go into a different complete aggregate.
Dividing $A$ out does not undo a merge into $A$, so $Q$ still carries $A$'s fee and no bundle it covers can carry it.
Merge $Q$ into the stamp of a bundle outside it, such as a new bundle of the aggregator's own, and the merged stamp keeps that bundle's fee.

## At the miner

Include eligible, disjoint public aggregates as they are, together with every bundle they cover, stripped to point at the aggregate version in the block.

Where two candidate aggregates overlap, remove the overlap from one of them with cached autonomes or a divisor built from stamps you hold, instead of rebuilding either.
Spend the saved proving time on an aggregate of your own.
