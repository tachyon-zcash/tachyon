# Authorization

A Tachyon bundle requires three layers of authorization: per-action signatures that bind each tachyaction to its tachygram, value commitments that hide individual values while preserving their algebraic sum, and a binding signature that proves the declared balance is correct. This chapter covers each layer, then shows the complete flow from action creation through consensus.

## Per-action Signing

Each tachyaction requires a fresh randomized key pair. The authorization flow starts with per-action entropy $\theta$ and diverges based on whether the action is a spend or output.

```mermaid
flowchart LR
    theta["theta (ActionEntropy)"]
    cmx["cmx (note commitment)"]
    hash(("derive(theta, cmx)"))

    theta & cmx --- hash --> spend_alpha & output_alpha

    spend_alpha["alpha (SpendRandomizer)"]
    output_alpha["alpha (OutputRandomizer)"]

    spend_alpha -->|"rsk = ask.derive(alpha)"| rsk

    output_alpha -->|"rsk = alpha"| rsk -->|"rsk.sign(cv, rk)"| action(cv, rk, sig)
```

### ActionEntropy ($\theta$)

32 bytes of randomness chosen by the signer. Combined with a note commitment to deterministically derive the randomizer $\alpha$:

$$\alpha = \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-AlphaDrv"},\; \theta \| \mathsf{cmx}))$$

This design enables **hardware wallet signing without proof construction**: the hardware wallet holds $\mathsf{ask}$ and $\theta$, signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$, and a separate device constructs the proof later using $\theta$ and $\mathsf{cmx}$ to recover $\alpha$.

### Spend vs Output

Both paths produce $(\mathsf{rk}, \text{sig})$ — the per-action verification key and its signature. The randomizer $\alpha$ is retained separately as a proof witness. Internally, $\mathsf{rsk}$ is derived and used for signing, but never exposed.

**Spend** — requires spending authority:

$$\mathsf{rsk} = \mathsf{ask} + \alpha$$

The resulting $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ is a re-randomization of the spend validating key. The custody device derives $\alpha$ from $(\theta, \mathsf{cmx})$, computes $\mathsf{rsk}$, signs, and returns $(\mathsf{rk}, \text{sig})$. The user device independently derives the same $\alpha$ for the proof witness.

**Output** — no spending authority needed:

$$\mathsf{rsk} = \alpha$$

The resulting $\mathsf{rk} = [\alpha]\,\mathcal{G}$ is a re-randomization of the generator itself. No custody device is involved.

Both produce an $\mathsf{rk}$ that can verify a signature, but only the spend's $\mathsf{rk}$ requires knowledge of $\mathsf{ask}$. This unification lets consensus treat all tachyactions identically.

### Action sighash

Each tachyaction carries a RedPallas signature over a domain-separated hash of the action's public data:

$$\text{sighash} = \text{BLAKE2b-512}(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$$

The signature binds ($\mathsf{cv}$, $\mathsf{rk}$) together. Since $\mathsf{rk}$ is itself a commitment to $\mathsf{cmx}$ (via $\alpha$'s derivation from $\theta$ and $\mathsf{cmx}$), the signature transitively binds the action to its tachygram without the tachygram appearing in the action.

| Key | Lifetime | Can sign? | Can verify? |
| --- | -------- | --------- | ----------- |
| $\mathsf{ask}$ | Long-lived | No | — |
| $\mathsf{ak}$ | Long-lived | — | No |
| $\mathsf{rsk}$ | Per-action | **Yes** | — |
| $\mathsf{rk}$ | Per-action | — | **Yes** |

## Value Balance

Tachyon uses Pedersen commitments on the Pallas curve for value hiding:

$$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$

where $v$ is the signed integer value (positive for spends, negative for outputs) and $\mathsf{rcv}$ is a random trapdoor in $\mathbb{F}_q$.

The generators $\mathcal{V}$ and $\mathcal{R}$ are shared with Orchard, derived from the domain `z.cash:Orchard-cv`. This reuse is intentional — the binding signature scheme uses `reddsa::orchard::Binding` which hardcodes $\mathcal{R}$ as its basepoint.

### Homomorphic property

The sum of value commitments preserves the algebraic structure:

$$\sum_i \mathsf{cv}_i = \bigl[\sum_i v_i\bigr]\,\mathcal{V} + \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$

This enables the binding signature scheme to prove value balance without revealing individual values.

### Binding signature

The binding signature proves that the transaction's value commitments sum to the declared balance.

The signer knows all value commitment trapdoors and computes their sum:

$$\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$$

This is the discrete log of $\mathsf{bvk}$ with respect to $\mathcal{R}$:

$$\mathsf{bvk} = \bigl(\bigoplus_i \mathsf{cv}_i\bigr) \ominus \text{ValueCommit}_0(\mathsf{v\_balance})$$

$$= \bigl[\sum_i v_i - \mathsf{v\_balance}\bigr]\,\mathcal{V} + \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$

$$= [0]\,\mathcal{V} + [\mathsf{bsk}]\,\mathcal{R} \qquad (\text{when } \sum_i v_i = \mathsf{v\_balance})$$

The binding signature proves knowledge of $\mathsf{bsk}$, which is an opening of the Pedersen commitment $\mathsf{bvk}$ to value 0. By the binding property of the commitment scheme, it is infeasible to find another opening to a different value — so value balance is enforced.

The validator recomputes $\mathsf{bvk}$ from public data (action value commitments and declared value balance) and verifies:

$$\text{BindingSig.Validate}_{\mathsf{bvk}}(\text{sighash}, \text{bindingSig}) = 1$$

### Binding sighash

Tachyon signs:

$$\text{sighash} = \text{BLAKE2b-512}(\text{"Tachyon-BindHash"},\; \mathsf{v\_balance} \| \mathsf{sig}_1 \| \cdots \| \mathsf{sig}_n)$$

This differs from Orchard's `SIGHASH_ALL` transaction hash because:

- Action signatures already bind $\mathsf{cv}$ and $\mathsf{rk}$ via $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$
- The binding signature must be computable without the full transaction
- The stamp is excluded because it is stripped during [aggregation](./aggregation.md)

## End-to-end Flow

The following diagram traces the complete authorization pipeline across trust boundaries: action construction and signing on the user device (with custody device involvement for spends), proof construction and stamping, and finally binding and submission to consensus.

A single user device may act as custody and stamper, but the trust boundary is only required to cover custody and the user device.

```mermaid
sequenceDiagram

box Trust Boundary
    participant Custody
    participant User
end

rect rgb(255, 0, 255, 0.1)
activate User

loop per action

    note over User: random rcv

    alt spend
      note over User: use note { pk, psi, rcm, v }
      note over User: cv = rcv.commit(v)
    else output
      note over User: select rcm
      note over User: create note { pk, psi, rcm, v }
      note over User: cv = rcv.commit(-v)
    end
    note over User: cmx = rcm.commit(pk, psi, v)

    note over User: random theta
    alt spend
        User ->> Custody: cv, theta, cmx
        note over Custody: alpha = theta.derive(cmx)
        note over Custody: rsk = ask.randomize(alpha)
        note over Custody: rk = public(rsk)
        note over Custody: sig = rsk.sign(digest(cv, rk))
        destroy Custody
        Custody ->> User: rk, sig
    else output
        note over User: alpha = theta.derive(cmx)
        note over User: rk = public(alpha)
        note over User: sig = alpha.sign(digest(cv, rk))
    end
    note over User: rcv, alpha, action { cv, rk, sig }
end

note over User: select anchor

loop per action
  critical anchor, rcv, alpha, action { cv, rk, sig }, pak { ak, nk }, note { pk, psi, rcm, v }
        note over User: is_spend = cv == rcv.commit(v)
        note over User: is_output = cv == rcv.commit(-v)
        User --> User: is_spend XOR is_output
        alt rk == ak.randomize(alpha)
            User --> User: rk == ak.randomize(alpha)
            note over User: flavor = epoch(anchor)
            note over User: nf = nk.derive(psi, flavor)
            note over User: tachygram_acc = nf
        else output
            User --> User: rk == public(alpha)
            note over User: cmx = rcm.commit(pk, psi, v)
            note over User: tachygram_acc = cmx
        end
        note over User: action_acc = digest(cv, rk)
        note over User: pcd: leaf stamp(action_acc, tachygram_acc, anchor)
    end
end

participant Stamper

User ->> Stamper: leaf stamps, actions { cv, rk, sig }, tachygrams
loop while stamps > 1
  critical left(action_acc, tachygram_acc, anchor), right(action_acc, tachygram_acc, anchor)
      note over Stamper: action_acc = union(left.action_acc, right.action_acc)
      note over Stamper: tachygram_acc = union(left.tachygram_acc, right.tachygram_acc)
      note over Stamper: anchor = intersect(left.anchor, right.anchor)
      note over Stamper: pcd: stamp(action_acc, tachygram_acc, anchor)
  end
end
destroy Stamper
Stamper ->> User: stamp(tachygram_acc, action_acc, anchor)

break
    note over User: verify stamp(tachygram_acc, action_acc, anchor)
end
note over User: bsk = sum(rcv_i)
note over User: binding_sig = bsk.sign(actions, value_balance)
deactivate User
end

participant Consensus
destroy User
User ->> Consensus: actions[], value_balance, binding_sig, tachygrams, anchor, stamp
break
    note over Consensus: check action_sigs
    note over Consensus: check binding_sig
    note over Consensus: verify stamp(tachygram_acc, action_acc, anchor)
end
```
