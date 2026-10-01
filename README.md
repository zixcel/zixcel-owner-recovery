# zixcel-owner-recovery

Secret-free orchestration for owner recovery and device movement. Zixcel owns
the user-visible sequence and selectable receipt retention. Crowsi owns the
mnemonic and approval key; iHAT owns identity recovery, replacement-device
registration, epoch advancement and source-device/session revocation.

The state document can be persisted owner-locally, but contains only public
request/receipt metadata. The mnemonic, derived key, WebAuthn assertion and
device private key have no field in this package.

The default move-receipt retention is 730 days and may be selected between one
day and ten years. A completed source receipt is read-only, never invocable.
Expiry makes it unavailable; permanent purge remains an explicit owner action.

## Package integration

The package is an independently consumable unit. Callers reference its documented
interface through a versioned dependency and own application-specific composition
and integration.
