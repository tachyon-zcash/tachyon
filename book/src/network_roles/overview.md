# Overview

Without Tachyon, the ZCash transaction lifecycle is similar to other blockchains:

```mermaid
sequenceDiagram
    participant Wallet as User's Wallet
    participant RPC
    participant Network as ZCash Network
    participant Miner as ZCash Miner

    Wallet->>RPC: Transaction
    RPC->>Network: Transaction propagated to<br/>network via gossip
    Network->>Miner: Miner builds block with<br/>transactions from mempool
```

Tachyon introduces shielded transaction aggregates, which introduce a new network role, called an _aggregator_:

```mermaid
sequenceDiagram
    participant Wallet as User's Wallet
    participant RPC as Aggregation RPC
    participant Network as Aggregation Network
    participant Aggregator
    participant Miner as ZCash Miner
    participant Legacy as Legacy P2P

    Wallet->>RPC: Sends Tachyon Transaction
    RPC->>Network: Gossips to P2P<br/>Aggregation Network
    Network->>Aggregator: Collects transactions from<br/>P2P network and builds<br/>transaction aggregates
    Aggregator->>Miner: Selects one transaction<br/>aggregate to include per block
    Miner<<->>Legacy: Legacy P2P<br/>connections + logic
```
