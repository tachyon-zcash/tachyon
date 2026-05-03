# Book FIXME

Deferred issues identified during book review. Use `/book-fixme` to resolve entries.

## Deferred Issues

### Introduction is a stub
`book/src/introduction.md` contains only two lines. Needs a proper project
overview covering what Tachyon is, who it's for, and how the book is organized.

### Network roles chapters are stubs
The Oblivious Sync Service, Aggregator, and ZCash Miner sections in SUMMARY.md
have no content pages. These need at least overview pages explaining each role.

### Missing testnet documentation
The Tachyon Testnet section has no content. Needs documentation on testnet
setup, participation, and current status.

### Extensions section is empty
The Oblivious Message Retrieval extension has no content page.

## Book-Code Consistency Checklist

When modifying code that touches any of the items below, check the corresponding
book page and update it. When modifying book pages, cross-reference the source.

| Code location | Book page | What to verify |
| --- | --- | --- |
| `constants.rs` domain separators | `domain-separators.md` | Names, byte lengths, formulas match |
| `note.rs` `Note` struct fields | `notes.md` | Field names, types (F_p vs F_q), value bounds |
| `note.rs` `Note::commitment()` | `authorization.md`, `tachygrams.md`, `domain-separators.md` | Poseidon argument order matches code |
| `note.rs` `Note::nullifier()` | `notes.md`, `keys.md`, `bundle.md`, `nullifier-derivation.md`, `tachygrams.md` | Two-step derivation (mk then nf), domain tags |
| `keys/note.rs` `PaymentKey::derive()` | `keys.md` | Poseidon argument order, domain tag |
| `keys/ggm.rs` GGM tree | `nullifier-derivation.md`, `notes.md` | Tree depth, derivation steps |
| `value.rs` `CommitmentTrapdoor::commit()` | `authorization.md` | cv formula, sign convention (spend positive, output negative) |
| `entropy.rs` `derive_alpha()` | `authorization.md`, `domain-separators.md` | Personalization strings, input order |
| `primitives/effect.rs` | `authorization.md`, `tachygrams.md` | Spend vs output semantics |

### How to use this checklist

1. Before merging a PR that changes any code location above, verify the book page.
2. Before merging a PR that changes any book page above, verify against the code.
3. Run `grep -rn 'F_nk\|F_{nk}\|F_{\\mathsf{nk}}' book/src/` to catch stale nullifier formulas.
4. Run `grep -rn 'Tachyon-TgrmDgst' book/src/` to catch phantom domain separators.
5. Run `grep -rn 'F_q.*rcm\|rcm.*F_q' book/src/` to catch wrong field annotations for note rcm.
