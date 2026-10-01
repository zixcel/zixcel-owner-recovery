//! Secret-free recovery ceremony and source move-receipt lifecycle.

#![forbid(unsafe_code)]

use crowsi_credential_authority_contracts::{
    OwnerRecoveryCustodyReceiptV1, OwnerRecoveryCustodyStateV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zixcel_contracts::{OwnerRecoveryRequestV1, Validate};

pub const OWNER_RECOVERY_CEREMONY_SCHEMA_V1: &str = "zixcel://owner-recovery/ceremony/v1";
pub const OWNER_MOVE_RECEIPT_SCHEMA_V1: &str = "zixcel://owner-recovery/move-receipt/v1";
pub const OWNER_MOVE_PURGE_RECEIPT_SCHEMA_V1: &str =
    "zixcel://owner-recovery/move-purge-receipt/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CeremonyStateV1 {
    AwaitingCustodyProvision,
    AwaitingBackupConfirmation,
    AwaitingMnemonicVerification,
    ReadyForIdentityRecovery,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryCeremonyV1 {
    pub schema: String,
    pub request: OwnerRecoveryRequestV1,
    pub state: CeremonyStateV1,
    pub custody_receipt: Option<OwnerRecoveryCustodyReceiptV1>,
    pub backup_confirmed_at_epoch_s: Option<u64>,
    pub identity_recovery_receipt_ref: Option<String>,
    pub completed_at_epoch_s: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyError {
    InvalidRequest,
    Expired,
    StateConflict,
    CustodyMismatch,
    IdentityReceiptInvalid,
    RetentionActive,
    AlreadyPurged,
}

impl OwnerRecoveryCeremonyV1 {
    /// Starts a secret-free ceremony.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or already-expired Zixcel request.
    pub fn start(request: OwnerRecoveryRequestV1, now_epoch_s: u64) -> Result<Self, CeremonyError> {
        request
            .validate()
            .map_err(|_| CeremonyError::InvalidRequest)?;
        if now_epoch_s < request.issued_at_epoch_s || now_epoch_s >= request.expires_at_epoch_s {
            return Err(CeremonyError::Expired);
        }
        Ok(Self {
            schema: OWNER_RECOVERY_CEREMONY_SCHEMA_V1.into(),
            request,
            state: CeremonyStateV1::AwaitingCustodyProvision,
            custody_receipt: None,
            backup_confirmed_at_epoch_s: None,
            identity_recovery_receipt_ref: None,
            completed_at_epoch_s: None,
        })
    }

    /// Accepts only a matching Crowsi custody state at the exact ceremony step.
    ///
    /// # Errors
    ///
    /// Rejects secret-bearing, stale, mismatched or out-of-order projections.
    pub fn accept_custody(
        &mut self,
        receipt: OwnerRecoveryCustodyReceiptV1,
        now_epoch_s: u64,
    ) -> Result<(), CeremonyError> {
        self.ensure_live(now_epoch_s)?;
        receipt
            .validate()
            .map_err(|_| CeremonyError::CustodyMismatch)?;
        if receipt.recovery_id != self.request.request_id
            || receipt.subject_ref != self.request.subject_ref
            || receipt.custody_provider_ref != self.request.custody_provider_ref
            || receipt.observed_at_epoch_s > now_epoch_s
        {
            return Err(CeremonyError::CustodyMismatch);
        }
        match (self.state, receipt.state) {
            (
                CeremonyStateV1::AwaitingCustodyProvision,
                OwnerRecoveryCustodyStateV1::Provisioned,
            ) => {
                self.custody_receipt = Some(receipt);
                self.state = CeremonyStateV1::AwaitingBackupConfirmation;
            }
            (
                CeremonyStateV1::AwaitingMnemonicVerification,
                OwnerRecoveryCustodyStateV1::Verified,
            ) => {
                let provisioned = self
                    .custody_receipt
                    .as_ref()
                    .ok_or(CeremonyError::StateConflict)?;
                if provisioned.root_fingerprint_sha256 != receipt.root_fingerprint_sha256
                    || provisioned.key_revision != receipt.key_revision
                {
                    return Err(CeremonyError::CustodyMismatch);
                }
                self.custody_receipt = Some(receipt);
                self.state = CeremonyStateV1::ReadyForIdentityRecovery;
            }
            _ => return Err(CeremonyError::StateConflict),
        }
        Ok(())
    }

    /// Records that the owner has stored and rechecked the displayed mnemonic.
    ///
    /// # Errors
    ///
    /// Rejects confirmation outside the provisioned step or after expiry.
    pub fn confirm_backup(&mut self, now_epoch_s: u64) -> Result<(), CeremonyError> {
        self.ensure_live(now_epoch_s)?;
        if self.state != CeremonyStateV1::AwaitingBackupConfirmation {
            return Err(CeremonyError::StateConflict);
        }
        self.backup_confirmed_at_epoch_s = Some(now_epoch_s);
        self.state = CeremonyStateV1::AwaitingMnemonicVerification;
        Ok(())
    }

    /// Records the independently verified iHAT recovery result and creates the
    /// read-only source move receipt.
    ///
    /// # Errors
    ///
    /// Rejects completion before mnemonic re-verification, invalid receipt
    /// references, expiry, or timestamp overflow.
    pub fn complete(
        &mut self,
        identity_recovery_receipt_ref: &str,
        now_epoch_s: u64,
    ) -> Result<OwnerMoveReceiptV1, CeremonyError> {
        self.ensure_live(now_epoch_s)?;
        if self.state != CeremonyStateV1::ReadyForIdentityRecovery
            || !stable_ref(identity_recovery_receipt_ref)
        {
            return Err(CeremonyError::IdentityReceiptInvalid);
        }
        let retained_until_epoch_s = now_epoch_s
            .checked_add(self.request.receipt_retention_seconds)
            .ok_or(CeremonyError::InvalidRequest)?;
        self.state = CeremonyStateV1::Completed;
        self.identity_recovery_receipt_ref = Some(identity_recovery_receipt_ref.into());
        self.completed_at_epoch_s = Some(now_epoch_s);
        Ok(OwnerMoveReceiptV1 {
            schema: OWNER_MOVE_RECEIPT_SCHEMA_V1.into(),
            receipt_id: format!("move-receipt:64:{}", self.request.request_id),
            recovery_request_id: self.request.request_id.clone(),
            subject_ref: self.request.subject_ref.clone(),
            identity_recovery_receipt_ref: identity_recovery_receipt_ref.into(),
            root_fingerprint_sha256: self
                .custody_receipt
                .as_ref()
                .ok_or(CeremonyError::StateConflict)?
                .root_fingerprint_sha256
                .clone(),
            completed_at_epoch_s: now_epoch_s,
            retained_until_epoch_s,
            purged_at_epoch_s: None,
        })
    }

    fn ensure_live(&self, now_epoch_s: u64) -> Result<(), CeremonyError> {
        if now_epoch_s < self.request.issued_at_epoch_s
            || now_epoch_s >= self.request.expires_at_epoch_s
        {
            Err(CeremonyError::Expired)
        } else if matches!(
            self.state,
            CeremonyStateV1::Completed | CeremonyStateV1::Cancelled
        ) {
            Err(CeremonyError::StateConflict)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerMoveReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub recovery_request_id: String,
    pub subject_ref: String,
    pub identity_recovery_receipt_ref: String,
    pub root_fingerprint_sha256: String,
    pub completed_at_epoch_s: u64,
    pub retained_until_epoch_s: u64,
    pub purged_at_epoch_s: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MoveReceiptStateV1 {
    ReadOnly,
    Unreadable,
    Expired,
    Purged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveReceiptProjectionV1 {
    pub receipt_id: String,
    pub state: MoveReceiptStateV1,
    pub readable: bool,
    pub invocable: bool,
    pub reason_id: String,
    pub retained_until_epoch_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerMovePurgeReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub purged_at_epoch_s: u64,
    pub purge_digest_sha256: String,
}

impl OwnerMoveReceiptV1 {
    #[must_use]
    pub fn project(&self, now_epoch_s: u64, material_readable: bool) -> MoveReceiptProjectionV1 {
        let (state, readable, reason) = if self.purged_at_epoch_s.is_some() {
            (
                MoveReceiptStateV1::Purged,
                false,
                "zixcel://reason/move-receipt-purged/v1",
            )
        } else if now_epoch_s >= self.retained_until_epoch_s {
            (
                MoveReceiptStateV1::Expired,
                false,
                "zixcel://reason/move-receipt-expired/v1",
            )
        } else if material_readable {
            (
                MoveReceiptStateV1::ReadOnly,
                true,
                "zixcel://reason/move-receipt-read-only/v1",
            )
        } else {
            (
                MoveReceiptStateV1::Unreadable,
                false,
                "zixcel://reason/move-receipt-unreadable/v1",
            )
        };
        MoveReceiptProjectionV1 {
            receipt_id: self.receipt_id.clone(),
            state,
            readable,
            invocable: false,
            reason_id: reason.into(),
            retained_until_epoch_s: self.retained_until_epoch_s,
        }
    }

    /// Permanently retires the receipt after its selected retention period.
    ///
    /// # Errors
    ///
    /// Rejects early or repeated purge attempts.
    pub fn purge(&mut self, now_epoch_s: u64) -> Result<OwnerMovePurgeReceiptV1, CeremonyError> {
        if self.purged_at_epoch_s.is_some() {
            return Err(CeremonyError::AlreadyPurged);
        }
        if now_epoch_s < self.retained_until_epoch_s {
            return Err(CeremonyError::RetentionActive);
        }
        let mut digest = Sha256::new();
        digest.update(b"zixcel-owner-move-purge-v1\0");
        digest.update(self.receipt_id.as_bytes());
        digest.update(now_epoch_s.to_be_bytes());
        self.purged_at_epoch_s = Some(now_epoch_s);
        Ok(OwnerMovePurgeReceiptV1 {
            schema: OWNER_MOVE_PURGE_RECEIPT_SCHEMA_V1.into(),
            receipt_id: self.receipt_id.clone(),
            purged_at_epoch_s: now_epoch_s,
            purge_digest_sha256: format!("sha256:{:x}", digest.finalize()),
        })
    }
}

fn stable_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crowsi_credential_authority_contracts::{
        OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1, OwnerRecoveryCustodyStateV1,
    };
    use zixcel_contracts::{
        DEFAULT_MOVE_RECEIPT_RETENTION_SECONDS, OWNER_RECOVERY_REQUEST_SCHEMA_V1,
        OwnerRecoveryMethodV1,
    };

    fn request() -> OwnerRecoveryRequestV1 {
        OwnerRecoveryRequestV1 {
            schema: OWNER_RECOVERY_REQUEST_SCHEMA_V1.into(),
            request_id: "recovery-1".into(),
            subject_ref: "owner-1".into(),
            method: OwnerRecoveryMethodV1::MnemonicSeedPhrase,
            custody_provider_ref: "crowsi-owner-recovery".into(),
            receipt_retention_seconds: DEFAULT_MOVE_RECEIPT_RETENTION_SECONDS,
            issued_at_epoch_s: 100,
            expires_at_epoch_s: 1_000,
        }
    }

    fn custody(state: OwnerRecoveryCustodyStateV1) -> OwnerRecoveryCustodyReceiptV1 {
        OwnerRecoveryCustodyReceiptV1 {
            schema: OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1.into(),
            recovery_id: "recovery-1".into(),
            subject_ref: "owner-1".into(),
            custody_provider_ref: "crowsi-owner-recovery".into(),
            root_fingerprint_sha256: format!("sha256:{}", "ab".repeat(32)),
            key_revision: 1,
            state,
            observed_at_epoch_s: 110,
        }
    }

    #[test]
    fn full_ceremony_is_ordered_and_secret_free() {
        let mut ceremony = OwnerRecoveryCeremonyV1::start(request(), 105).expect("start");
        ceremony
            .accept_custody(custody(OwnerRecoveryCustodyStateV1::Provisioned), 120)
            .expect("provision");
        ceremony.confirm_backup(130).expect("backup");
        ceremony
            .accept_custody(custody(OwnerRecoveryCustodyStateV1::Verified), 140)
            .expect("verify");
        let receipt = ceremony
            .complete("ihat:recovery-receipt:1", 150)
            .expect("complete");
        assert_eq!(receipt.retained_until_epoch_s, 150 + 63_072_000);
        let wire = serde_json::to_string(&ceremony).expect("wire");
        for forbidden in [
            "mnemonic_words",
            "private_key",
            "seed_phrase",
            "raw_assertion",
        ] {
            assert!(!wire.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn read_only_unreadable_expired_and_purged_are_exact() {
        let mut ceremony = OwnerRecoveryCeremonyV1::start(request(), 105).expect("start");
        ceremony
            .accept_custody(custody(OwnerRecoveryCustodyStateV1::Provisioned), 120)
            .expect("provision");
        ceremony.confirm_backup(130).expect("backup");
        ceremony
            .accept_custody(custody(OwnerRecoveryCustodyStateV1::Verified), 140)
            .expect("verify");
        let mut receipt = ceremony
            .complete("ihat:recovery-receipt:1", 150)
            .expect("complete");
        assert_eq!(
            receipt.project(151, true).state,
            MoveReceiptStateV1::ReadOnly
        );
        assert_eq!(
            receipt.project(151, false).state,
            MoveReceiptStateV1::Unreadable
        );
        assert_eq!(receipt.purge(151), Err(CeremonyError::RetentionActive));
        let expiry = receipt.retained_until_epoch_s;
        assert_eq!(
            receipt.project(expiry, true).state,
            MoveReceiptStateV1::Expired
        );
        receipt.purge(expiry).expect("purge");
        assert_eq!(
            receipt.project(expiry, true).state,
            MoveReceiptStateV1::Purged
        );
        assert_eq!(receipt.purge(expiry), Err(CeremonyError::AlreadyPurged));
    }

    #[test]
    fn mismatched_or_reordered_custody_fails_closed() {
        let mut ceremony = OwnerRecoveryCeremonyV1::start(request(), 105).expect("start");
        assert_eq!(
            ceremony.confirm_backup(110),
            Err(CeremonyError::StateConflict)
        );
        assert_eq!(
            ceremony.accept_custody(custody(OwnerRecoveryCustodyStateV1::Verified), 120),
            Err(CeremonyError::StateConflict)
        );
        let mut wrong = custody(OwnerRecoveryCustodyStateV1::Provisioned);
        wrong.subject_ref = "other-owner".into();
        assert_eq!(
            ceremony.accept_custody(wrong, 120),
            Err(CeremonyError::CustodyMismatch)
        );
    }
}
