//! Circuit gadgets for evidence values.

scalar_gadget!(EvidenceTreeRootGadget, "EvidenceTreeRootGadget(..)");

use ragu_core::drivers::Driver;

use crate::{digest::poseidon, pasta::Fp, stamp::headers::qr::QrBucketOutput};

impl<'dr, D: Driver<'dr, F = Fp>> QrBucketOutput<'dr, D> {
    /// Derive the evidence leaf from this bucket's certified fields.
    pub(crate) fn evidence_leaf(
        &self,
        dr: &mut D,
    ) -> ragu_core::Result<EvidenceTreeRootGadget<'dr, D>> {
        let [depth, bits] = self.profile.validate(dr)?;
        let digest = &self.contents_digest.limbs;
        poseidon::evidence_tree_leaf_gadget(
            dr,
            [
                &self.epoch.element,
                &self.anchor_start.element,
                &self.anchor_next.element,
                &self.discriminant.element,
                &depth,
                &bits,
            ],
            digest,
        )
        .map(Into::into)
    }
}
