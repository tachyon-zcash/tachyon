# Authorization

A Tachyon bundle requires three layers of authorization.
Per-action signatures bind each tachyaction to its tachygram, value commitments hide individual values while preserving their algebraic sum, and a binding signature proves the declared balance is correct.
This chapter covers each layer, then shows the complete flow from action creation through consensus.

## Actions

Each tachyaction requires a fresh randomized key pair.

The planner begins authorization by choosing a note, the action's entropy `theta` and a value commitment trapdoor `rcv` for each action. The custody device receives each note, `theta` and `rcv`. It derives `cm` from each note, `alpha` from `theta` and `cm`, `rk` from `alpha`, and `cv` from the note's value and `rcv`. Custody checks none of these against planned values.

```mermaid
flowchart TB
    theta["theta (per-action entropy)"]
    cm["cm (note commitment)"]
    hash(("hash(theta, cm)"))

    theta & cm --- hash

    hash -->|"Tachyon-Spend"| spend_alpha
    hash -->|"Tachyon-Output"| output_alpha

    spend_alpha -->|"rk = ak + [alpha]G"| descriptor
    output_alpha -->|"rk = [alpha]G"| descriptor

    descriptor["descriptor { cv, rk }"]
    descriptor ===|"bundle digest"| sighash((sighash))

    spend_alpha -->|"rsk = ask + alpha"| sign
    sighash ==> sign
    output_alpha -->|"rsk = alpha"| sign

    sign(("sign(rsk, sighash)"))
    sign --- action["action { cv, rk, sig }"]
```

The arbitrary entropy `theta` which combines with note commitment `cm` to deterministically produce the randomizer `alpha`:

$$ \alpha_{\text{spend}} = \text{Poseidon}_\text{Tachyon-Spend}(\theta, \mathsf{cm}) $$
$$ \alpha_{\text{output}} = \text{Poseidon}_\text{Tachyon-Output}(\theta, \mathsf{cm}) $$

`theta` and the Poseidon output are elements of $\mathbb{F}_p$, and `alpha` is that output read as a scalar in $\mathbb{F}_q$, which is larger.

Actions are signed with a unique per-action `rsk` signing key.
Spends and outputs have different relationships between `alpha` and `rsk`, but in both cases,
the action's published `rk` validating key is the public counterpart of `rsk`.

$$ \mathsf{rk} = [\mathsf{rsk}]\,\mathcal{G} $$

### Spend

Derivation of spend `rsk` is rerandomization of spending authority `ask`:

$$ \mathsf{rsk} = \mathsf{ask} + \alpha $$
$$ \mathsf{rk} = [\mathsf{ask} + \alpha]\,\mathcal{G}$$

Conveniently, `rk` is also possible to derive from validating `ak`.
The rerandomization of a validating key is equivalent to derivation of a validating key from the rerandomized authority:

$$ \mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G} $$

A device that holds `ak` and `theta` therefore computes the same `rk` without `ask`.
The planner uses this to know each `rk`, and the sighash, before custody signs. The spend proof derives `rk` the same way.
Custody derives `rk` and signs the spend action with `rsk`.

### Output

An output `rsk` is simply equal to `alpha`. No authority needed:

$$ \mathsf{rsk} = \alpha $$
$$ \mathsf{rk} = [\alpha]\,\mathcal{G} $$

Custody derives `rk` and signs the output action with `rsk`.

## Bundle commitment

The bundle commitment is a digest of the bundle's effect.

$$
\mathsf{hActionsTachyon} =
    \text{BLAKE2b-256}_\text{Tachyon-Actions}\bigl( \mathsf{cv}_i \| \mathsf{rk}_i \bigr)
$$

$$
\mathsf{hMemoTachyon} =
    \text{BLAKE2b-256}_\text{Tachyon-Memo}( \mathsf{vMemoTachyon} )
$$

$$
\text{BLAKE2b-256}_\text{ZTxIdTachyonHash}\bigl(
    \mathsf{hActionsTachyon} \| \mathsf{valueBalanceTachyon} \| \mathsf{hMemoTachyon}
\bigr)
$$

The action digest hashes every action's $(\mathsf{cv}, \mathsf{rk})$ in wire order, so the commitment fixes the actions and their order. Hashing the memo to a fixed width is what lets the outer digest absorb a variable-length payload without a length prefix.

The stamp proof binds the same action set by a different construction.
It uses a Pedersen commitment to the polynomial whose roots are the Poseidon action digests,

$$ d_i = \text{Poseidon}_\text{Tachyon-ActionDg}(\mathsf{cv}_i \| \mathsf{rk}_i) $$
$$ \mathsf{action\_acc} = \text{Commit}\Bigl(\prod_i \bigl(X - d_i\bigr)\Bigr) $$

which is order-independent, as a set commitment must be to survive [aggregation](./aggregation.md). The two digests are computed over the same actions and are not interchangeable.

The stamp is excluded from the bundle commitment because it is stripped during aggregation.

### Transaction sighash

All signatures (action and binding) sign the same transaction-wide sighash.
The sighash is computed at the transaction layer, incorporating the bundle commitment from each pool (transparent, sapling, orchard, tachyon).
The tachyon crate contributes its bundle commitment.
A transaction-level crate computes the sighash and passes it in as opaque bytes.

This binds every signature to the complete set of effecting data across all pools.
The stamp steps derive `alpha` in-circuit from the witnessed `theta` and the `cm` their left header certifies, so `rk` is itself a commitment to `cm`, and the signature transitively binds each action to its tachygram without the tachygram appearing in the action.

Tachyon also contributes to the transaction-level `auth_digest` that backs `wtxid`. See [Transaction Identifiers](./transaction-identifiers.md) for the formula and how aggregation changes the authorization form.

## Value Balance

Tachyon uses Pedersen commitments on the Pallas curve for value hiding:

$$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$

where $v$ is the signed integer value (positive for spends, negative for outputs) and `rcv` is a random[^rcv-note] trapdoor in $\mathbb{F}_q$.

[^rcv-note]: `rcv` is currently sampled as a uniformly random scalar (`Fq::random`). This derivation may be revised in the future to incorporate a hash of the note commitment or other action-specific data.

The generators $\mathcal{V}$ and $\mathcal{R}$ are shared with Orchard, derived from the domain `z.cash:Orchard-cv`.[^generator-todo]

[^generator-todo]: The binding signature scheme uses `reddsa::orchard::Binding` which hardcodes $\mathcal{R}$ as its basepoint. We should consider defining a unique personalization.

### Binding signature

The sum of value commitments preserves the algebraic structure:

$$\sum_i \mathsf{cv}_i = \bigl[\sum_i v_i\bigr]\,\mathcal{V} + \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$

This enables the binding signature scheme to prove value balance without revealing individual values.

The binding signature proves that the bundle's value commitments are consistent with the declared `value_balance`.

**Signer** holds every `rcv` and computes `bsk`:

$$\mathsf{bsk} = \sum_i \mathsf{rcv}_i$$

The planner chose every `rcv` and sent each one to custody, so either device can sign.
Custody may sign `binding_sig` in the same exchange as the actions.
Otherwise the planner signs it, before or after custody answers.

**Validators** know the claimed `value_balance` and each published action `cv`. Validators reconstruct the corresponding public key:

$$\mathsf{bvk} = \sum_i \mathsf{cv}_i - [\mathsf{value\_balance}]\,\mathcal{V}$$

Expanding the commitments $\mathsf{cv}_i = [v_i]\,\mathcal{V} + [\mathsf{rcv}_i]\,\mathcal{R}$:

$$\mathsf{bvk} = \bigl[\sum_i v_i - \mathsf{value\_balance}\bigr]\,\mathcal{V} + \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$

When $\sum_i v_i = \mathsf{value\_balance}$, the $\mathcal{V}$ component vanishes:

$$\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$$

If the values don't balance, the $\mathcal{V}$ term survives. So,

- If the sum of committed values doesn't truly equal the public balance, the signer cannot produce a valid signature.
- If a valid signature was produced and then the committed values or the public balance were modified, the validator can't confirm the valid signature.

## Simplified Flow

A request feeds three paths that converge in the final bundle.
Each path produces a different component of the bundle:

- **Authorizing**: custody derives each action's `rk` and `cv`, and signs every action over the transaction sighash.
- **Binding**: the bundle commitment (from the action descriptors, `value_balance` and the memo) feeds the transaction sighash, which the binding key signs. Custody or the planner holds the binding key.
- **Proving**: each action yields a leaf stamp from its note, `theta` and `rcv`, and the leaves merge into a single Ragu PCD stamp. Proving needs nothing from custody.

```mermaid
flowchart LR
    style proving fill:#ff000010,stroke:none
    style authorization fill:#ff000010,stroke:none
    style binding fill:#ff000010,stroke:none

    style custody fill:#00ff0010
    style prover fill:#00ff0010

    style pczt fill:#0000ff10
    style tx fill:#0000ff10


    subgraph pczt[partial tx]
        subgraph request
            request_action@{ shape: st-rect, label: "request action" }
            memo
        end
        other1@{ shape: st-doc, label: "other tx data" }
    end

    subgraph tx[complete tx]
        subgraph bundle["stamped bundle"]
            value_balance
            action@{ shape: st-rect }
            binding_sig
            stamp
        end
        other2@{ shape: st-doc, label: "other tx data" }
    end

    subgraph authorization["authorizing flow"]
        subgraph custody["custody device"]
            derive((derive))
            rsk@{ shape: st-rect }
            sign_action((("sign")))
        end
    end
    request_action --> derive
    derive --> descriptor@{ shape: st-rect, label: "descriptor" }
    derive --> value_balance
    descriptor & value_balance & memo & other1 === sighash{sighash}
    derive --- rsk --- sign_action ==> action
    sighash === sign_action

    subgraph binding["binding flow"]
        bsk
        sign_binding_sig(("sign"))
    end
    request_action --- bsk --- sign_binding_sig ==> binding_sig
    sighash === sign_binding_sig

    subgraph proving["proving flow"]
        leaf@{ shape: st-rect, label: "leaf" }
        subgraph prover["proving device"]
            merge((merge))
        end
    end
    request_action & derive -.- leaf -.- merge -.- stamp

    other1 --> other2
```

Consensus recomputes the actions from the visible bundle and checks them against both the sighash (via the bundle commitment's ordered BLAKE2b digest) and the stamp (via the polynomial commitment in the PCD header).

A modified action breaks both checks.

## Detailed Sequence

The user sends one request to custody.
Custody derives every value it signs and validates nothing.

```mermaid
sequenceDiagram

actor User

activate User

    note over User: select/create notes { pk, psi, rcm, v }

rect rgb(100, 149, 237, 0.1)
    loop per action
        note over User: random theta
        note over User: random rcv
        note over User: request_action { note, theta, rcv, effect }
    end
    note over User: request { request_action[], memo }
end

create participant Custody@{ type: "boundary" }
User ->> Custody: request, tx etc

rect rgb(255, 165, 0, 0.1)
    loop per action
        note over Custody: cm = Poseidon(pk, psi, rcm, v)
        note over Custody: alpha = Poseidon(theta, cm)
        alt spend
            note over Custody: rk = ak + [alpha]G
            note over Custody: cv = Pedersen(v, rcv)
        else output
            note over Custody: rk = [alpha]G
            note over Custody: cv = Pedersen(-v, rcv)
        end
    end
    note over Custody: value_balance = Sum v_spend - Sum v_output
    note over Custody: hActionsTachyon = Blake2b(cv_i || rk_i)
    note over Custody: bundle_commitment = Blake2b(hActionsTachyon || value_balance || hMemoTachyon)
    note over Custody: compute sighash

    loop per action
        alt spend
            note over Custody: rsk = ask + alpha
        else output
            note over Custody: rsk = alpha
        end
        note over Custody: sig = Sign(rsk, sighash)
    end

    opt custody signs binding
        note over Custody: bsk = Sum rcv_i
        note over Custody: binding_sig = Sign(bsk, sighash)
    end
end

destroy Custody
Custody -->> User: actions { cv, rk, sig }, binding_sig?

opt user signs binding
    note over User: compute sighash
    note over User: bsk = Sum rcv_i
    note over User: binding_sig = Sign(bsk, sighash)
end

rect rgb(138, 43, 226, 0.1)
    note over User: select anchor

    loop per action
        critical anchor, action { cv, rk }, note, theta, rcv, pak { ak, nk }
            alt spend
                note over User: mk = Poseidon(psi, nk)
                note over User: nf_e0 = PRF^nfTachyon(mk, e)
                note over User: nf_e1 = PRF^nfTachyon(mk, e+1)
                note over User: tg_roots = nf_e0, nf_e1
            else output
                note over User: cm = Poseidon(pk, psi, rcm, v)
                note over User: tg_root = cm
            end
            note over User: action_root = Poseidon(cv || rk)
            note over User: action_poly = (X - action_root)
            note over User: tg_poly = product over tg_roots of (X - tg_root)
            note over User: pcd: leaf stamp(Commit(action_poly), Commit(tg_poly), anchor)
        end
    end

    create participant Stamper
    User ->> Stamper: leaf stamps, tachygrams

    loop while stamps > 1
        critical left(action_poly, tg_poly, anchor), right(action_poly, tg_poly, anchor)
            note over Stamper: assert left.anchor == right.anchor
            note over Stamper: merged_action = left.action_poly * right.action_poly
            note over Stamper: merged_tg = left.tg_poly * right.tg_poly
            note over Stamper: pcd: stamp(Commit(merged_action), Commit(merged_tg), anchor)
        end
    end
    destroy Stamper
    Stamper ->> User: stamp(tachygrams, anchor, proof)

    break
        note over User: reconstruct polynomials from roots, commit, verify
    end
end

create participant Consensus
note over User: transaction { actions[], value_balance, binding_sig, stamp } 
deactivate User
destroy User
User ->> Consensus: transaction
break
    note over Consensus: action_digest_i = Poseidon(cv_i || rk_i)
    note over Consensus: hActionsTachyon = Blake2b(cv_i || rk_i)
    note over Consensus: bundle_commitment = Blake2b(hActionsTachyon || value_balance || hMemoTachyon)
    note over Consensus: compute sighash
    note over Consensus: check action sigs against sighash
    note over Consensus: check binding sig against sighash
    note over Consensus: action_acc = Commit(poly from action roots)
    note over Consensus: tachygram_acc = Commit(poly from tachygram roots)
    note over Consensus: verify stamp(action_acc, tachygram_acc, anchor)
end
```

## Signing outside custody

Some signers return only signatures.
A FROST group and a hardware device that never sees the notes are two examples.
For these, the planner derives each action's `rk` from `ak` and `theta`, and `cv` from `rcv`.
It computes the bundle commitment and the sighash, and sends the descriptors and the sighash to the signers.
The signers return one signature for each action.
The planner attaches them to the descriptors it derived and signs the binding signature itself.
A signed descriptor that differs from a derived one is rejected.
