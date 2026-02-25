# Authorization Diagram

This diagram shows how Tachyon shielded data is constructed: action authorization, proving, stamping, and finally binding.

A single user device may act as custody and stamper, but the trust boundary is only required to cover custody and the user device.

See [Keys and Authorization](./keys.md) for the key hierarchy and [Bundle](./bundle.md) for more details.

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
