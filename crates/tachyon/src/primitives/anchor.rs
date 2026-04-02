use core2::io::{self, Read, Write};
use mock_ragu::Commitment;

use super::{BlockHeight, PoolCommit};

/// Pool state at a specific block. Wire format is 64 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(clippy::partial_pub_fields, reason = "todo")]
pub struct Anchor(pub(crate) BlockHeight, pub PoolCommit);

impl Anchor {
    /// Read a 64-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut height_slot = [0u8; 32];
        reader.read_exact(&mut height_slot)?;
        if height_slot[4..].iter().any(|&pad| pad != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "anchor height exceeds u32",
            ));
        }
        let mut height_bytes = [0u8; 4];
        height_bytes.copy_from_slice(&height_slot[..4]);
        let height = BlockHeight(u32::from_le_bytes(height_bytes));

        let mut commit_bytes = [0u8; 32];
        reader.read_exact(&mut commit_bytes)?;
        let commit = PoolCommit(
            Commitment::try_from(&commit_bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
        );

        Ok(Self(height, commit))
    }

    /// Write a 64-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let mut height_slot = [0u8; 32];
        height_slot[..4].copy_from_slice(&u32::from(self.0).to_le_bytes());
        writer.write_all(&height_slot)?;
        let commit_bytes: [u8; 32] = self.1.0.into();
        writer.write_all(&commit_bytes)
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
    fn anchor_wire_is_64_bytes_round_trip() {
        let anchor = Anchor(
            BlockHeight(0x1234_5678),
            PoolCommit(Polynomial::default().commit(Fp::ZERO)),
        );
        let mut bytes = Vec::new();
        anchor.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64, "anchor wire must be 64 bytes");
        let decoded = Anchor::read(bytes.as_slice()).unwrap();
        assert_eq!(decoded, anchor);
    }
}
