//! Compressed stamp payloads carried by a stamped transaction.

use alloc::vec::Vec;

use corez::io::{self, Read};
use ragu::{
    Rank as _, WalletRank, circuits::polynomials, pcd::serialization, udon::curve::Affine as _,
};

use super::{Compressed, Frame, ProofStamp, StateByte, Wire, proof::aggregator, sealed};
use crate::{ActionDigest, ActionSetPoly, pasta::EqAffine};

/// A wallet's padded publication or a miner's compressed working transaction.
#[derive(Clone, Debug)]
pub enum PublicationProof {
    /// A finalized wallet `PublicTransaction`.
    Wallet(Compressed),
    /// An aggregator-rank `Transaction`.
    Aggregator(ragu::CompressedProof<aggregator::Cycle>),
}

impl sealed::Sealed for PublicationProof {}
impl Wire for PublicationProof {
    fn state(&self) -> StateByte {
        match *self {
            Self::Wallet(_) => StateByte::ProofStamp,
            Self::Aggregator(_) => StateByte::AggregatorProofStamp,
        }
    }

    fn frame(state: StateByte) -> io::Result<Frame<Self>> {
        match state {
            StateByte::ProofStamp => {
                let len = Compressed::encoded_len::<WalletRank>();
                Ok(Frame {
                    min: len,
                    max: len,
                    decode: |bytes| Compressed::from_bytes(bytes).map(Self::Wallet),
                })
            },
            StateByte::AggregatorProofStamp => {
                let len = ragu::CompressedProof::<aggregator::Cycle>::encoded_len::<
                    polynomials::AggregatorRank,
                >();
                Ok(Frame {
                    min: len,
                    max: len,
                    decode: |bytes| ragu::CompressedProof::from_bytes(bytes).map(Self::Aggregator),
                })
            },
            StateByte::NoBundle | StateByte::StrippedStamp => Err(super::unexpected_state()),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, serialization::Error<'static>> {
        #[expect(clippy::ref_patterns, reason = "borrow the compressed frame")]
        match *self {
            Self::Wallet(ref proof) => proof.to_bytes(),
            Self::Aggregator(ref proof) => proof.to_bytes(),
        }
    }
}

impl ProofStamp<PublicationProof> {
    /// Read a compressed publication trailer for the supplied bundle state
    /// byte.
    ///
    /// # Errors
    /// Returns an error for a non-publication state or an invalid trailer.
    pub fn read<R: Read>(state: StateByte, reader: R) -> io::Result<Self> {
        Self::read_frame(state, reader)
    }

    /// Verify the publication against all covered action and fee digests,
    /// retaining multiplicity.
    ///
    /// # Errors
    /// Returns a proof-system error if verification cannot run.
    pub fn verify_proof(
        &self,
        app: &aggregator::App<'_>,
        digests: &[ActionDigest],
    ) -> ragu::Result<bool> {
        if digests.len() >= WalletRank::num_coeffs() {
            return Ok(false);
        }
        let header = (
            ActionSetPoly::from_iter(digests.iter().copied()).commit(),
            self.anchor,
        );
        if EqAffine::from(header.0).is_identity() {
            return Ok(false);
        }
        #[expect(clippy::ref_patterns, reason = "borrow the compressed frame")]
        match *self.proof {
            PublicationProof::Wallet(ref proof) => {
                super::verify_wallet(app.context().wallet(), proof, header)
            },
            PublicationProof::Aggregator(ref proof) => aggregator::verify(app, proof, header),
        }
    }
}

#[cfg(test)]
mod tests {
    use corez::io::ErrorKind;

    #[test]
    fn a_hand_built_wrong_rank_hashes_its_frame_but_cannot_write_it() {
        use alloc::{boxed::Box, collections::BTreeSet};

        use ragu::{AcceleratedProver, ApplicationBuilder, pasta::Pasta, udon::field::Field as _};
        use ragu_pcd::pasta::baked_aggregator;
        use rand::{SeedableRng as _, rngs::StdRng};

        use crate::{
            digest::blake2b,
            stamp::{StampState as _, proof::HEADER_SIZE},
        };

        let standard = ApplicationBuilder::<
            '_,
            Pasta,
            polynomials::AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >::new()
        .finalize(baked_aggregator())
        .unwrap();
        let unit = standard.bootstrap_proof().clone().carry::<()>(());
        let proof = standard
            .compress(&unit, &mut StdRng::seed_from_u64(13))
            .unwrap()
            .into_parts()
            .0;
        let raw = proof.to_bytes().unwrap();
        assert_ne!(raw.len(), Compressed::encoded_len::<WalletRank>());
        let stamp = ProofStamp {
            anchor: Fp::from(1).into(),
            tachygram_set: TachygramSetCommit::default(),
            adjuncts: BTreeSet::new(),
            proof: Box::new(PublicationProof::Wallet(proof)),
        };
        assert_eq!(
            stamp.stamp_digest(),
            blake2b::stamp_digest(
                &[],
                &blake2b::stamp_proof_digest(
                    Fp::from(stamp.anchor).to_bytes(),
                    stamp.tachygram_set.as_ref().to_bytes(),
                    &raw
                )
            )
        );
        stamp.write(Vec::new()).unwrap_err();
    }

    use super::*;
    use crate::{Anchor, CompactSize, TachygramSetCommit, pasta::Fp};

    #[test]
    fn only_the_tagged_length_can_request_frame_bytes() {
        let mut prefix = Vec::new();
        Anchor::from(Fp::from(1)).write(&mut prefix).unwrap();
        TachygramSetCommit::default().write(&mut prefix).unwrap();
        prefix.push(0); // no adjuncts
        for (state, len, other) in [
            (StateByte::ProofStamp, 7296usize, 14432usize),
            (StateByte::AggregatorProofStamp, 14432, 7296),
        ] {
            for invalid in [0, len - 1, len + 1, other, 8000, 174_072_896] {
                let mut bytes = prefix.clone();
                CompactSize::try_from(invalid)
                    .unwrap()
                    .write(&mut bytes)
                    .unwrap();
                bytes.push(0x7b);
                let mut reader = bytes.as_slice();
                assert_eq!(
                    ProofStamp::<PublicationProof>::read(state, &mut reader)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::InvalidData
                );
                assert_eq!(reader, [0x7b]);
            }
            let mut missing = prefix.clone();
            CompactSize::try_from(len)
                .unwrap()
                .write(&mut missing)
                .unwrap();
            assert_eq!(
                ProofStamp::<PublicationProof>::read(state, missing.as_slice())
                    .unwrap_err()
                    .kind(),
                ErrorKind::UnexpectedEof
            );
            let mut long = prefix.clone();
            long.push(0xfe);
            long.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
            long.push(0x7b);
            let mut reader = long.as_slice();
            assert_eq!(
                ProofStamp::<PublicationProof>::read(state, &mut reader)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(reader, [0x7b]);
        }
    }
}
