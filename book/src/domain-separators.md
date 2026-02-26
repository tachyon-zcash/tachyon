# Domain Separators

| Constant         | Value                       | Purpose                                                            |
| ---------------- | --------------------------- | ------------------------------------------------------------------ |
| PRF expansion    | `Zcash_ExpandSeed`          | Key derivation from $\mathsf{sk}$ (shared with Sapling/Orchard)    |
| Transaction sighash | `Tachyon-TxDigest`       | Unified sighash: $H(\mathsf{cv}_1 \| \mathsf{rk}_1 \| \cdots \| \mathsf{cv}_n \| \mathsf{rk}_n \| \mathsf{v\_balance})$ |
| Spend alpha      | `Tachyon-Spend`             | Spend-side randomizer: $H(\theta \| \mathsf{cm})$                 |
| Output alpha     | `Tachyon-Output`            | Output-side randomizer: $H(\theta \| \mathsf{cm})$                |
| Value commitment | `z.cash:Orchard-cv`         | Generators $\mathcal{V}$, $\mathcal{R}$ (shared with Orchard)      |
| Nullifier        | `z.cash:Tachyon-nf`         | Nullifier PRF domain                                               |
| Note commitment  | `z.cash:Tachyon-NoteCommit` | Note commitment scheme                                             |
| Accumulator      | `z.cash:Tachyon-acc`        | Polynomial accumulator hash-to-curve                               |
