# Overview

Without Tachyon, the ZCash transaction lifecycle is similar to other blockchains:

```mermaid
sequenceDiagram
    participant Wallet
    box ZCash Network
        participant Mempool
        participant Miner
    end
    participant Chain

    note over Wallet: Create transaction
    Wallet ->> Mempool: Wallet RPC
    Mempool -->> Miner: Gossip
    note over Miner: Select transactions
    Miner ->> Chain: Mine Block
```

Tachyon introduces shielded transaction aggregates, which introduce a new network role, called an _aggregator_:

```mermaid
sequenceDiagram
    participant Wallet
    box ZCash Network
        participant Mempool
        participant Aggregator
        participant Miner
    end
    participant Chain

    note over Wallet: Create transaction
    Wallet ->> Mempool: Wallet RPC
    Mempool -->> Aggregator: Gossip
    note over Aggregator: Aggregate transactions
    Aggregator -->> Mempool: Gossip
    Mempool -->> Miner: Gossip
    note over Miner: Select transactions
    Miner->>Chain: Mine Block
```
