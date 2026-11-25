import Lake
open Lake DSL

package Tachyon where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩]

@[default_target]
lean_lib Tachyon where
  -- Build every module under `Tachyon/`, not just `Tachyon.lean`'s import
  -- closure, so a `.lean` that no aggregator imports cannot silently escape.
  globs := #[`Tachyon.*]

-- Same pin as ragu's `qa/fv`, so both workspaces share one toolchain.
require mathlib from git "https://github.com/leanprover-community/mathlib4" @ "v4.30.0"
