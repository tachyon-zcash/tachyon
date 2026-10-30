//! Circuit gadgets for evidence values.

scalar_gadget!(EvidenceTreeRootGadget, "EvidenceTreeRootGadget(..)");

use ragu::pasta::Fp;
use ragu_core::drivers::Driver;

use crate::{digest::poseidon, stamp::headers::qr::QrBucketOutput};

impl<'dr, D: Driver<'dr, F = Fp>> QrBucketOutput<'dr, D> {
    /// Derive the evidence leaf from this bucket's certified fields.
    pub(crate) fn evidence_leaf(
        &self,
        dr: &mut D,
    ) -> ragu_core::Result<EvidenceTreeRootGadget<'dr, D>> {
        let [depth, bits] = self.profile.validate(dr)?;
        let [low, high] = self.contents.encoding.limbs.clone();
        poseidon::evidence_tree_leaf_circuit(
            dr,
            &[
                self.epoch.element.clone(),
                self.anchor_start.element.clone(),
                self.anchor_next.element.clone(),
                self.discriminant.element.clone(),
                depth,
                bits,
                low,
                high,
            ],
        )
        .map(Into::into)
    }
}
