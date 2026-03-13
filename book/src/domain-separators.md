# Domain Separators

| Constant         | Value                       | Purpose                                                            |
| ---------------- | --------------------------- | ------------------------------------------------------------------ |
| PRF expansion    | `Zcash_ExpandSeed`          | Key derivation from $\mathsf{sk}$ (shared with Sapling/Orchard)    |
| Bundle commitment | `Tachyon-BndlHash`         | Bundle commitment: $H(\mathsf{action\_acc} \| \mathsf{value\_balance})$ |
| Spend alpha      | `Tachyon-Spend`             | Spend-side randomizer: $H(\theta \| \mathsf{cm})$                 |
| Output alpha     | `Tachyon-Output`            | Output-side randomizer: $H(\theta \| \mathsf{cm})$                |
| Value commitment | `z.cash:Orchard-cv`         | Generators $\mathcal{V}$, $\mathcal{R}$ (shared with Orchard)     |
| Master key       | `Tachyon-MkDerive`          | Note master key KDF: $mk = \text{Poseidon}(\psi, nk)$             |
| Note commitment  | `Tachyon-NoteCmmt`          | Note commitment: $\text{Poseidon}(rcm, pk, v, \psi)$              |
| Action digest    | `Tachyon-ActnDgst`          | Action digest: $\text{Poseidon}(cv, rk)$                          |
