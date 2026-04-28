use core2::io::{self, Read, Write};
use ff::{Field as _, PrimeField as _};
use mock_ragu::{Commitment, Multiset, Polynomial};
use pasta_curves::{Fp, arithmetic::CurveAffine as _};

use super::{BlockHeight, BlockSet};

/// Pool state at a specific block. Wire format is 32 bytes (compressed
/// Pasta curve point).
///
/// `Anchor` is the Pedersen polynomial commitment to the polynomial whose
/// roots are the previous anchor (as `Fp`) and every tachygram in the latest
/// block, blinded by the block height:
/// $$\mathsf{anchor}_n = \mathsf{Commit}\bigl((X - \mathsf{prev\_fp})
/// \cdot \prod_t (X - t),\;\; \mathsf{height}_n\bigr)$$
/// The Pedersen scheme is binding in both the polynomial (block contents +
/// prior anchor) and the blinding factor (height), so the anchor identifies
/// a unique pool position without any extra hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchor(pub Commitment);

impl Anchor {
    /// Sentinel "anchor at height -1": the prev for the height-0 block.
    /// Only valid in this position; never produced as a real chain
    /// anchor. Defined consistently with the height-as-trapdoor convention
    /// — commitment of the constant polynomial `1` blinded by `-1` (i.e.,
    /// `g_0 - h`).
    #[must_use]
    pub fn pregenesis() -> Self {
        Self(Polynomial::from_roots(&[]).commit(-Fp::ONE))
    }

    /// Compute the anchor produced by extending `prev` with `block` at
    /// `height`: the Pedersen commitment of `(X - prev_fp) · block_polynomial`
    /// blinded by `height`.
    #[must_use]
    pub fn next_poly(&self, block: &BlockSet<Polynomial>, height: &BlockHeight) -> Self {
        let block_poly = block.0.clone();
        let prev_poly = Polynomial::from_roots(&[self.into()]);
        let extended = block_poly.multiply(&prev_poly);
        let height_fp = Fp::from(u64::from(height.0));
        Self(extended.commit(height_fp))
    }

    #[must_use]
    /// Compute the anchor produced by extending `prev` with `block` at
    /// `height`: the Pedersen commitment of `(X - prev_fp) · block_polynomial`
    /// blinded by `height`.
    pub fn next_set(&self, block: &BlockSet<Multiset>, height: &BlockHeight) -> Self {
        let block_set = block.clone();
        let prev = Multiset::new(Polynomial::from_roots(&[self.into()]));
        let extended = block_set.0.merge(&prev);
        let height_fp = Fp::from(u64::from(height.0));
        Self(extended.commit_with(height_fp))
    }

    /// Read a 32-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let commit = Commitment::try_from(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Self(commit))
    }

    /// Write a 32-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let bytes: [u8; 32] = self.0.into();
        writer.write_all(&bytes)
    }
}

/// Convert an anchor to an `Fp` for inclusion as a polynomial root in the
/// next anchor's commitment. Uses the x-coordinate byte reinterpret — the
/// Pedersen binding of the underlying commitment provides chain-level
/// preimage resistance, so a plain x-coordinate is sufficient here.
impl From<&Anchor> for Fp {
    fn from(anchor: &Anchor) -> Self {
        let coords = anchor
            .0
            .inner()
            .coordinates()
            .expect("anchor curve point must not be the identity");
        Self::from_repr(coords.x().to_repr()).expect("x as Fp")
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::Anchor;

    #[test]
    fn anchor_wire_is_32_bytes_round_trip() {
        let anchor = Anchor::pregenesis();
        let mut bytes = Vec::new();
        anchor.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 32, "anchor wire must be 32 bytes");
        let decoded = Anchor::read(bytes.as_slice()).unwrap();
        assert_eq!(decoded, anchor);
    }
}
