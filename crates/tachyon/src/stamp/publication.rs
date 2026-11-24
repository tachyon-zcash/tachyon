//! Compressed stamp payloads carried by a stamped transaction.

use alloc::vec::Vec;

use ragu::{
    Rank as _, WalletRank, circuits::polynomials, pcd::serialization, udon::curve::Affine as _,
};

use super::{Compressed, ProofStamp, Wire, proof::aggregator, sealed};
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
    fn accepts(len: usize) -> bool {
        len == Compressed::encoded_len::<WalletRank>() || len == Self::bound()
    }

    fn bound() -> usize {
        ragu::CompressedProof::<aggregator::Cycle>::encoded_len::<polynomials::AggregatorRank>()
    }

    fn decode(bytes: &[u8]) -> Result<Self, serialization::Error<'_>> {
        if bytes.len() == Compressed::encoded_len::<WalletRank>() {
            Compressed::from_bytes(bytes).map(Self::Wallet)
        } else if bytes.len() == Self::bound() {
            ragu::CompressedProof::from_bytes(bytes).map(Self::Aggregator)
        } else {
            Err(serialization::Error::Invalid {
                offset: 0,
                bytes,
                reason: "unexpected publication length",
            })
        }
    }

    fn encode(&self) -> Result<Vec<u8>, serialization::Error<'static>> {
        #[expect(clippy::ref_patterns, reason = "borrow the compressed frame")]
        match *self {
            Self::Wallet(ref proof) => proof.to_bytes(),
            Self::Aggregator(ref proof) => proof.to_bytes(),
        }
    }

    fn accepts_encoding(&self, len: usize) -> bool {
        match *self {
            Self::Wallet(_) => len == Compressed::encoded_len::<WalletRank>(),
            Self::Aggregator(_) => len == Self::bound(),
        }
    }
}

impl ProofStamp<PublicationProof> {
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
    fn only_two_public_lengths_can_request_frame_bytes() {
        let wallet = Compressed::encoded_len::<WalletRank>();
        let aggregator = PublicationProof::bound();
        assert_eq!((wallet, aggregator), (7296, 14432));
        let mut prefix = Vec::new();
        Anchor::from(Fp::from(1)).write(&mut prefix).unwrap();
        TachygramSetCommit::default().write(&mut prefix).unwrap();
        prefix.push(0); // no adjuncts
        for len in [
            0,
            wallet - 1,
            wallet + 1,
            8000,
            aggregator - 1,
            aggregator + 1,
            174_072_896,
        ] {
            let mut bytes = prefix.clone();
            CompactSize::try_from(len)
                .unwrap()
                .write(&mut bytes)
                .unwrap();
            bytes.push(0x7b);
            let mut reader = bytes.as_slice();
            assert_eq!(
                ProofStamp::<PublicationProof>::read(&mut reader)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(reader, [0x7b]);
        }
        for len in [wallet, aggregator] {
            let mut missing = prefix.clone();
            CompactSize::try_from(len)
                .unwrap()
                .write(&mut missing)
                .unwrap();
            assert_eq!(
                ProofStamp::<PublicationProof>::read(missing.as_slice())
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
                ProofStamp::<PublicationProof>::read(&mut reader)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(reader, [0x7b]);
        }
    }
}
