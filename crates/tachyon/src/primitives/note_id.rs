use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{constants::NOTE_ID_DOMAIN, keys, note};

/// Identity binding: `H(domain, mk, cm)`.
///
/// Binds the note's identity (via master key) to its value commitment,
/// threading through the proof pipeline. Fuse steps verify that left
/// and right inputs agree on note id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoteId(Fp);

impl NoteId {
    /// TODO: consider adding trapdoor so note_id may be opaque
    pub(crate) fn derive(nk: &keys::NullifierKey, note: &note::Note) -> Self {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let domain = Fp::from_u128(u128::from_le_bytes(*NOTE_ID_DOMAIN));

        let mk = &nk.derive_note_private(&note.psi);
        let cm = note.commitment();

        Self(
            Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
                domain,
                mk.0,
                Fp::from(cm),
            ]),
        )
    }
}

impl From<Fp> for NoteId {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<NoteId> for Fp {
    fn from(id: NoteId) -> Self {
        id.0
    }
}
