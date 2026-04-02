use core::cmp;

use core2::io::{self, Read, Write};
use mock_ragu::Commitment;

use super::{BlockHeight, PoolCommit};

/// Pool state at a specific block: `(block_height, pool_commit)`.
#[derive(Clone, Copy, Debug)]
pub struct Anchor(pub BlockHeight, pub PoolCommit);

impl Anchor {
    /// Read an anchor: `4B height || 32B commitment`.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut height_bytes = [0u8; 4];
        reader.read_exact(&mut height_bytes)?;

        let height = BlockHeight(u32::from_le_bytes(height_bytes));
        let mut commit_bytes = [0u8; 32];
        reader.read_exact(&mut commit_bytes)?;
        let commitment = Commitment::try_from(&commit_bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Self(height, PoolCommit(commitment)))
    }

    /// Write an anchor: `4B height || 32B commitment`.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&u32::from(self.0).to_le_bytes())?;
        let bytes: [u8; 32] = self.1.0.into();
        writer.write_all(&bytes)
    }
}

impl PartialOrd for Anchor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        todo!("should anchor partial_cmp attempt to check pool set relationships?");
        self.0.partial_cmp(&other.0)
    }
}

impl PartialEq for Anchor {
    fn eq(&self, other: &Self) -> bool {
        // check both height and pool commitment
        self.0 == other.0 && self.1 == other.1
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ff::Field as _;
    use mock_ragu::Polynomial;
    use pasta_curves::Fp;

    use super::{Anchor, BlockHeight, PoolCommit};

    #[test]
    fn anchor_wire_is_36_bytes_round_trip() {
        let anchor = Anchor(
            BlockHeight(0x1234_5678),
            PoolCommit(Polynomial::default().commit(Fp::ZERO)),
        );
        let mut bytes = Vec::new();
        anchor.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 36, "anchor wire must be 36 bytes");
        let decoded = Anchor::read(bytes.as_slice()).unwrap();
        assert_eq!(decoded.0, anchor.0);
        assert_eq!(decoded.1, anchor.1);
    }
}
