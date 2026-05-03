# Hash Functions and Domain Separators

Tachyon uses two hash families, chosen by context:

- **BLAKE2b-512** for byte-oriented operations outside circuits: key derivation, alpha randomizers, and the bundle commitment that feeds the transaction sighash.
- **Poseidon** (P128Pow5T3, constant-length) for field-arithmetic operations that must be efficient inside Ragu circuits: nullifier derivation, note commitments, and action digests.

BLAKE2b personalizations are at most 16 bytes (the BLAKE2b personal field width). Most are exactly 16 bytes; the spend and output alpha personalizations are 13 and 14 bytes respectively. Poseidon domain tags are 16-byte strings interpreted as little-endian $\mathbb{F}_p$ elements via `Fp::from_u128`.

## BLAKE2b-512

| Constant | Value | Formula |
| --- | --- | --- |
| PRF expansion | `Zcash_ExpandSeed` | $\text{BLAKE2b-512}(\mathsf{sk} \| t)$ — key derivation (shared with Sapling/Orchard) |
| Spend alpha | `Tachyon-Spend` | $\alpha_\text{spend} = \text{BLAKE2b-512}(\theta \| \mathsf{cm})$ |
| Output alpha | `Tachyon-Output` | $\alpha_\text{output} = \text{BLAKE2b-512}(\theta \| \mathsf{cm})$ |
| Bundle commitment | `Tachyon-BndlHash` | $\text{BLAKE2b-512}(\mathsf{action\_acc} \| \mathsf{value\_balance})$ |

## Poseidon

| Constant | Value | Formula |
| --- | --- | --- |
| Master key | `Tachyon-MkDerive` | $\mathsf{mk} = \text{Poseidon}(\mathsf{tag}, \Psi, \mathsf{nk})$ — per-note master key KDF |
| Nullifier | `Tachyon-NfDerive` | $\text{Poseidon}(\mathsf{tag}, \mathsf{node}, \mathsf{bit})$ — GGM tree steps |
| Note commitment | `Tachyon-NoteCmmt` | $\mathsf{cm} = \text{Poseidon}(\mathsf{tag}, \mathsf{rcm}, \mathsf{pk}, v, \Psi)$ |
| Action digest | `Tachyon-ActnDgst` | $\text{Poseidon}(\mathsf{tag}, \mathsf{cv}_x, \mathsf{cv}_y, \mathsf{rk}_x, \mathsf{rk}_y)$ |
| Payment key | `Tachyon-PkDerive` | $\mathsf{pk} = \text{Poseidon}(\mathsf{tag}, \mathsf{ak}_x, \mathsf{nk})$ |
| Delegation id | `Tachyon-Delegate` | $\text{DelegationId} = \text{Poseidon}(\mathsf{tag}, \mathsf{mk}, \mathsf{cm}, \mathsf{trapdoor})$ — per-delegation note binding |
| Epoch seed | `Tachyon-EpchSeed` | $\text{epoch\_seed} = \text{Poseidon}(\mathsf{tag}, \mathsf{pool\_commit}_x, \mathsf{pool\_commit}_y)$ — seed inserted at epoch boundary |

## Other

| Constant | Value | Purpose |
| --- | --- | --- |
| Value commitment | `z.cash:Orchard-cv` | Hash-to-curve generators $\mathcal{V}$, $\mathcal{R}$ (shared with Orchard) |
| Accumulator generators | `mock_ragu:generators` | Hash-to-curve for Pedersen commitment generators (mock; replaced by Ragu generators) |
