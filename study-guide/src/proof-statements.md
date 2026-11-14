# What Each Proof Shows

A shielded transaction carries a zero-knowledge proof. The proof shows facts
about the notes that the transaction spends and creates, and it reveals nothing
else about them. Each shielded protocol asks its proof to show a different set
of facts. This page lists those facts and compares them.

## Sources

The Sprout, Sapling, and Orchard columns come from section 4.18, "Zk-SNARK
Statements", of the
[Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf),
version v2026.9.0-13-gde3d90. The Sprout column is the JoinSplit statement. The
Sapling column joins the Spend statement and the Output statement. The Orchard
column is the Action statement.

Ironwood is the NU6.3 network upgrade, and the Ironwood pool is the shielded
value pool that the upgrade introduces. The Ironwood pool has no statement of
its own. Its proofs use the Orchard Action statement, so the Ironwood column
differs from the Orchard column in one cell only.

The Tachyon column comes from the "Output Action Statement" and "Spend Action
Statement" sections of the Deep Dive page of The Tachyon Book. The
specification does not yet define Tachyon, so this column describes a draft.

## All Five Protocols

A check mark means that the proof shows the fact. A dash means that the proof
does not show it. The notes below the table explain every other entry.

| The proof shows that… | Sprout | Sapling | Orchard | Ironwood | Tachyon |
| --- | --- | --- | --- | --- | --- |
| the spent note is in the pool | ✓ | ✓ | ✓ | ✓ | ✓ |
| a zero-value note may skip that check | ✓ | ✓ | ✓ | ✓ | – |
| the nullifier is correctly derived | ✓ | ✓ | ✓ | ✓ | ✓ ×2 |
| the nullifier is absent from past epochs | – | – | – | – | ✓ |
| the spender has authority, through | $\mathsf{a_{sk}}$ | $\mathsf{rk}$ | $\mathsf{rk}$ | $\mathsf{rk}$ | $\mathsf{rk}$ |
| the note's address derives from the spender's keys | ✓ | ✓ | ✓ | ✓ | ✓ |
| the randomizer of $\mathsf{rk}$ is bound to the note | – | – | – | – | ✓ |
| the new commitment opens to a note | ✓ | ✓ | ✓ | ✓ | ✓ |
| the value commitment is correct | – | ✓ | ✓ | ✓ | ✓ |
| each value is in range | ✓ | ✓ | ✓ | ✓ | ✓ |
| the values balance | ✓ | – | – | – | – |
| the proof binds to this transaction | ✓ | – | – | – | – |
| the new note's $\rho$ is unique | ✓ | – | ✓ | ✓ | – |
| the output returns to the spender's address | – | – | ✓ | flag | – |
| flags enable nonzero spends and outputs | – | – | ✓ | ✓ | – |
| key points are not of small order | – | ✓ | – | – | – |
| the sender knows $\mathsf{esk}$ for $\mathsf{epk}$ | – | ✓ | – | – | – |
| the published tachygrams are nonzero | – | – | – | – | ✓ |
| an output's dummy tachygram is well formed | – | – | – | – | ✓ |

## Ironwood and Tachyon

This table holds the same facts for the two newest pools, with one column for
each provable property. The column names shorten the row names of the table
above, in the same order.

| Pool | In pool | Zero-value skip | Nullifier derived | Past exclusion | Authority | Address from keys | Randomizer bound | New commitment | Value commitment | Value range | Balance | Transaction binding | Unique $\rho$ | Same address | Enable flags | Small order | Knows $\mathsf{esk}$ | Nonzero tachygrams | Dummy tachygram |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ironwood | ✓ | ✓ | ✓ | – | $\mathsf{rk}$ | ✓ | – | ✓ | ✓ | ✓ | – | – | ✓ | flag | ✓ | – | – | – | – |
| Tachyon | ✓ | – | ✓ ×2 | ✓ | $\mathsf{rk}$ | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | – | – | – | – | – | ✓ | ✓ |

## Notes on the Entries

**In the pool.** Sprout, Sapling, Orchard, and Ironwood prove a Merkle path
from the note commitment to an anchor. Each of them lets a zero-value note skip
the path, which is how a dummy note passes. Tachyon proves instead that the
commitment is a root of its creation stamp's accumulator, and that an
authenticated anchor chain links that stamp to the target anchor.

**Nullifier.** Each older pool publishes one nullifier for each spent note. A
Tachyon spend publishes two, $\mathsf{nf}_e$ and $\mathsf{nf}_{e+1}$, for the
target epoch and the epoch after it.

**Past exclusion.** Only Tachyon proves that a nullifier was absent from
history. Its proof covers every completed epoch from the note's creation to the
target epoch. In the older pools, consensus checks the whole nullifier set, so
the proof has nothing to show.

**Authority.** A Sprout proof shows that the prover knows the spending key
$\mathsf{a_{sk}}$ itself. The later proofs show only that the published key
$\mathsf{rk}$ re-randomizes the note's $\mathsf{ak}$. A signature under
$\mathsf{rk}$, outside the proof, then shows consent.

**Address from keys.** Sprout shows
$\mathsf{a_{pk}} = \mathsf{PRF}^{\mathsf{addr}}_{\mathsf{a_{sk}}}(0)$. Sapling,
Orchard, and Ironwood show $\mathsf{pk_d} = [\mathsf{ivk}]\,\mathsf{g_d}$, with
$\mathsf{ivk}$ derived from $\mathsf{ak}$ and $\mathsf{nk}$. Tachyon shows
$\mathsf{pk} = \mathsf{Com}(\mathsf{ak}, \mathsf{nk})$.

**Randomizer bound.** Tachyon derives the randomizer as
$\alpha = \mathsf{PRF}(\mathsf{cm} \,\|\, \theta)$. This binds $\mathsf{rk}$ to
the note, because a Tachyon action description does not carry the nullifier or
the commitment. The older pools choose $\alpha$ freely.

**Value commitment and balance.** Sprout has no value commitment; its proof
shows the balance directly. Every later pool commits to the value in the proof
and shows the balance with a binding signature outside the proof.

**Value range.** The four specified pools constrain the type of the witnessed
value. Tachyon adds an explicit check against `MAX_MONEY`.

**Transaction binding.** A Sprout proof shows
$h_i = \mathsf{PRF}^{\mathsf{pk}}_{\mathsf{a_{sk}}}(i, h_{\mathsf{Sig}})$, which
ties the proof to one transaction. The later pools leave this to the spend
authorization signature.

**Unique $\rho$.** Sprout derives each new $\rho$ from $h_{\mathsf{Sig}}$.
Orchard and Ironwood set the new note's $\rho$ to the nullifier of the note
spent in the same action. Sapling needs no such fact, because its nullifier
depends on the note's position in the tree. Tachyon leaves the check to the
recipient's wallet.

**Same address.** From NU6.3 the Action statement can require the output note
to go to the address of the spent note. The Orchard pool always sets this
restriction. The Ironwood pool sets or clears it with the `enableCrossAddress`
flag of the transaction.

**Small order.** Sapling checks that $\mathsf{g_d}$ and $\mathsf{ak}$ are not
of small order, because the Jubjub curve has a cofactor. The Pallas curve has
prime order, so Orchard, Ironwood, and Tachyon need only that their points are
not the identity.

**Tachygrams.** A tachygram is a nullifier or a note commitment that a Tachyon
stamp publishes. The proof shows that each one is nonzero. A Tachyon output
also publishes a dummy tachygram, and the proof shows that it is the hash of a
value the prover knows.
