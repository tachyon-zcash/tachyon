#![no_main]

//! Fuzz [`Bundle::verify`] with single edits to an honest aggregate and the
//! adjunct it covers.
//!
//! The base is the `verify_pipeline/aggregate_with_adjunct` seed. Its sighash
//! comes from the `fixtures` sidecar the seed writer signed over, and its
//! wtxid from the adjunct's pointer; both stay frozen while the input chooses
//! one edit. An edit bound by a Tachyon check must be rejected at that check's
//! stage. Anchor and proof edits are decided by the proof system, so they run
//! for liveness only. Before fuzzing, the honest base must verify and one
//! fixed edit of every other field must be rejected at its stage.

use std::{io, sync::LazyLock};

use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Action, Anchor, Tachygram, TachygramSetCommit, VerificationError, VerifyTachygramsError,
    action,
    bundle::{self, Bundle},
    stamp::{AggregateId, PointerStamp, ProofStamp},
    value,
};
use zcash_tachyon_fuzz::proof_len;

/// The low value bits an edit flips, enough to span `MAX_MONEY`.
const VALUE_MASK: u64 = (1 << 51) - 1;

/// The encoded length of an action descriptor's `cv`, which `rk` follows.
const CV_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
enum Field {
    ActionCv,
    ActionRk,
    ValueBalance,
    FeeMaxCommitment,
    ActionSignature,
    BindingSignature,
    AdjunctWtxid,
    AdjunctCv,
    AdjunctRk,
    AdjunctFee,
    StampFee,
    StampCoverage,
    DropAdjunct,
    DuplicateAdjunct,
    TachygramCount,
    TachygramValue,
    TachygramSet,
    Anchor,
    Proof,
}

impl Field {
    const ALL: [Self; 19] = [
        Self::ActionCv,
        Self::ActionRk,
        Self::ValueBalance,
        Self::FeeMaxCommitment,
        Self::ActionSignature,
        Self::BindingSignature,
        Self::AdjunctWtxid,
        Self::AdjunctCv,
        Self::AdjunctRk,
        Self::AdjunctFee,
        Self::StampFee,
        Self::StampCoverage,
        Self::DropAdjunct,
        Self::DuplicateAdjunct,
        Self::TachygramCount,
        Self::TachygramValue,
        Self::TachygramSet,
        Self::Anchor,
        Self::Proof,
    ];
}

/// The verifier stage that must reject an edit.
#[derive(Clone, Copy, Debug)]
enum Stage {
    Signatures,
    Pointers,
    Coverage,
    WrongArity,
    WrongSet,
    Liveness,
}

struct Base {
    aggregate: Bundle<ProofStamp>,
    adjunct: Bundle<PointerStamp>,
    sighash: [u8; 32],
    wtxid: [u8; 64],
}

static BASE: LazyLock<Base> = LazyLock::new(|| {
    let mut seed: &[u8] = include_bytes!("../corpus/verify_pipeline/aggregate_with_adjunct");
    let aggregate = Bundle::<ProofStamp>::read(&mut seed).expect("the base aggregate decodes");
    let adjunct = Bundle::<PointerStamp>::read(&mut seed).expect("the base adjunct decodes");
    let base = Base {
        sighash: *include_bytes!("../fixtures/aggregate_with_adjunct.sighash"),
        wtxid: adjunct.stamp.wtxid.into(),
        aggregate,
        adjunct,
    };

    base.aggregate
        .verify(
            &mut StdRng::seed_from_u64(0),
            &base.sighash,
            &base.wtxid,
            &[&base.adjunct],
        )
        .expect("the honest base verifies");
    for field in Field::ALL {
        // Anchor and proof edits have no expected stage.
        if matches!(field, Field::Anchor | Field::Proof) {
            continue;
        }
        let (aggregate, adjuncts, stage) = (1..=u64::from(u8::MAX))
            .find_map(|mask| apply(&base, field, 0, mask))
            .unwrap_or_else(|| panic!("no fixed edit to {field:?} takes effect"));
        assert_stage(&base, field, &aggregate, &adjuncts, stage);
    }

    base
});

fn encode(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> Vec<u8> {
    let mut buf = Vec::new();
    write(&mut buf).expect("an in-memory write succeeds");
    buf
}

/// XOR the bytes of a nonzero `mask` into `bytes` from `index`, wrapping.
fn flip(bytes: &mut [u8], index: usize, mask: u64) {
    for (offset, byte) in mask.to_le_bytes().into_iter().enumerate() {
        let at = (index + offset) % bytes.len();
        bytes[at] ^= byte;
    }
}

/// `mask` restricted to [`VALUE_MASK`], if any bits remain.
fn value_mask(mask: u64) -> Option<u64> {
    let masked = mask & VALUE_MASK;
    (masked != 0).then_some(masked)
}

/// Flip bytes of the descriptor field at `start` and decode the result.
fn edit_descriptor(action: &mut Action, start: usize, index: usize, mask: u64) -> Option<()> {
    let mut bytes = encode(|buf| action.descriptor().write(buf));
    flip(&mut bytes[start..start + CV_LEN], index, mask);
    let descriptor = action::Descriptor::read(bytes.as_slice()).ok()?;
    action.cv = descriptor.cv;
    action.rk = descriptor.rk;
    Some(())
}

/// Apply one edit to a copy of the base, returning the edited aggregate and
/// adjuncts and the stage that must reject them, or `None` if the edited
/// field does not decode.
fn apply(
    base: &Base,
    field: Field,
    index: usize,
    mask: u64,
) -> Option<(Bundle<ProofStamp>, Vec<Bundle<PointerStamp>>, Stage)> {
    let mut aggregate = base.aggregate.clone();
    let mut adjuncts = vec![base.adjunct.clone()];
    let action_index = index % aggregate.actions.len();
    let adjunct_index = index % base.adjunct.actions.len();

    let stage = match field {
        Field::ActionCv => {
            edit_descriptor(&mut aggregate.actions[action_index], 0, index, mask)?;
            Stage::Signatures
        },
        Field::ActionRk => {
            edit_descriptor(&mut aggregate.actions[action_index], CV_LEN, index, mask)?;
            Stage::Signatures
        },
        Field::ValueBalance => {
            let flipped = i64::from(aggregate.value_balance) ^ value_mask(mask)?.cast_signed();
            aggregate.value_balance = value::Balance::try_from(flipped).ok()?;
            Stage::Signatures
        },
        Field::FeeMaxCommitment => {
            let shift = value::Positive::try_from(value_mask(mask)?).ok()?;
            aggregate.fee_max_commitment =
                aggregate.fee_max_commitment + value::Trapdoor::ZERO.commit(shift);
            Stage::Signatures
        },
        Field::ActionSignature => {
            let action = &mut aggregate.actions[action_index];
            let mut bytes = encode(|buf| action.sig.write(buf));
            flip(&mut bytes, index, mask);
            action.sig = action::Signature::read(bytes.as_slice()).ok()?;
            Stage::Signatures
        },
        Field::BindingSignature => {
            let mut bytes = encode(|buf| aggregate.binding_sig.write(buf));
            flip(&mut bytes, index, mask);
            aggregate.binding_sig = bundle::Signature::read(bytes.as_slice()).ok()?;
            Stage::Signatures
        },
        Field::AdjunctWtxid => {
            let mut bytes: [u8; 64] = adjuncts[0].stamp.wtxid.into();
            flip(&mut bytes, index, mask);
            adjuncts[0].stamp.wtxid = AggregateId::try_from(bytes).ok()?;
            Stage::Pointers
        },
        Field::AdjunctCv => {
            edit_descriptor(&mut adjuncts[0].actions[adjunct_index], 0, index, mask)?;
            Stage::Coverage
        },
        Field::AdjunctRk => {
            edit_descriptor(&mut adjuncts[0].actions[adjunct_index], CV_LEN, index, mask)?;
            Stage::Coverage
        },
        Field::AdjunctFee => {
            let fee = &mut adjuncts[0].stamp.fee;
            *fee = value::Positive::try_from(u64::from(*fee) ^ value_mask(mask)?).ok()?;
            Stage::Coverage
        },
        Field::StampFee => {
            let fee = &mut aggregate.stamp.fee;
            *fee = value::Positive::try_from(u64::from(*fee) ^ value_mask(mask)?).ok()?;
            Stage::Coverage
        },
        Field::StampCoverage => {
            flip(&mut aggregate.stamp.coverage, index, mask);
            Stage::Coverage
        },
        Field::DropAdjunct => {
            adjuncts.clear();
            Stage::Coverage
        },
        Field::DuplicateAdjunct => {
            adjuncts.push(base.adjunct.clone());
            Stage::Coverage
        },
        Field::TachygramCount => {
            let tachygrams = &mut aggregate.stamp.tachygrams;
            let removed = *tachygrams.iter().nth(index % tachygrams.len())?;
            tachygrams.remove(&removed);
            Stage::WrongArity
        },
        Field::TachygramValue => {
            let tachygrams = &mut aggregate.stamp.tachygrams;
            let count = tachygrams.len();
            let original = *tachygrams.iter().nth(index % count)?;
            let mut bytes = encode(|buf| original.write(buf));
            flip(&mut bytes, index, mask);
            let edited = Tachygram::read(bytes.as_slice()).ok()?;
            tachygrams.remove(&original);
            tachygrams.insert(edited);
            if tachygrams.len() == count {
                Stage::WrongSet
            } else {
                Stage::WrongArity
            }
        },
        Field::TachygramSet => {
            let mut bytes = encode(|buf| aggregate.stamp.tachygram_set.write(buf));
            flip(&mut bytes, index, mask);
            aggregate.stamp.tachygram_set = TachygramSetCommit::read(bytes.as_slice()).ok()?;
            Stage::WrongSet
        },
        Field::Anchor => {
            let mut bytes = encode(|buf| aggregate.stamp.anchor.write(buf));
            flip(&mut bytes, index, mask);
            aggregate.stamp.anchor = Anchor::read(bytes.as_slice()).ok()?;
            Stage::Liveness
        },
        Field::Proof => {
            let mut bytes = encode(|buf| aggregate.stamp.write(buf));
            let start = bytes.len() - proof_len(&aggregate.stamp);
            flip(&mut bytes[start..], index, mask);
            aggregate.stamp = ProofStamp::read(bytes.as_slice()).ok()?;
            Stage::Liveness
        },
    };

    Some((aggregate, adjuncts, stage))
}

fn assert_stage(
    base: &Base,
    field: Field,
    aggregate: &Bundle<ProofStamp>,
    adjuncts: &[Bundle<PointerStamp>],
    stage: Stage,
) {
    let adjunct_refs: Vec<&Bundle<PointerStamp>> = adjuncts.iter().collect();
    let result = aggregate.verify(
        &mut StdRng::seed_from_u64(0),
        &base.sighash,
        &base.wtxid,
        &adjunct_refs,
    );
    match (stage, &result) {
        (Stage::Liveness, _)
        | (Stage::Signatures, Err(VerificationError::Signatures(_)))
        | (Stage::Pointers, Err(VerificationError::Pointers(_)))
        | (Stage::Coverage, Err(VerificationError::Coverage(_)))
        | (
            Stage::WrongArity,
            Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)),
        )
        | (Stage::WrongSet, Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongSet))) =>
            {},
        _ => {
            panic!("an edit to {field:?} must be rejected at {stage:?}, verify returned {result:?}")
        },
    }
}

fuzz_target!(
    init: {
        LazyLock::force(&BASE);
    },
    |data: &[u8]| {
        let mut input = Unstructured::new(data);
        let (Ok(&field), Ok(index), Ok(mask)) = (
            input.choose(&Field::ALL),
            input.arbitrary::<u16>(),
            input.arbitrary::<u64>(),
        ) else {
            return;
        };
        if mask == 0 {
            return;
        }
        let Some((aggregate, adjuncts, stage)) = apply(&BASE, field, usize::from(index), mask)
        else {
            return;
        };
        assert_stage(&BASE, field, &aggregate, &adjuncts, stage);
    }
);
