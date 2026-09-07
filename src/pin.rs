//! PIN-related operations: factory-default detection and provisioning
//! enforcement.
//!
//! # Grounding
//!
//! The OpenPGP card protocol has no queryable "is the PIN still the
//! factory default" fact — `PWStatusBytes` (GET DATA tag `C4`) exposes
//! retry *counts*, not a default/changed flag (confirmed against
//! `openpgp-card-0.7.0/src/ocard/data/pw_status.rs`; also documented in
//! `testing.rs`'s own doc comment, section 5, which this module's
//! fake-backed tests below rely on). The only real way to find out is
//! the same way real client software infers it: attempt `VERIFY` with
//! the well-known factory-default PIN values and see whether it
//! succeeds. Those values are taken verbatim from
//! `openpgp-card-0.7.0/src/ocard/data.rs`'s private `PW1_INITIAL`/
//! `PW3_INITIAL` constants (used internally by `KdfDo::iter_salted`, not
//! exported publicly by that crate — confirmed by grepping the vendored
//! source, hence redefined here rather than imported): `"123456"` (User
//! PIN, PW1) and `"12345678"` (Admin PIN, PW3).
//!
//! **Real cost, stated plainly**: every check consumes one of the PIN's
//! 3 real retry attempts if the PIN has already been changed away from
//! the default — a wrong `VERIFY` decrements the card's retry counter
//! same as any other wrong attempt (`ocard/mod.rs`'s
//! `StatusBytes::PasswordNotChecked(n)` mapping, `(0x63, 0xC0..=0xCF) =>
//! PasswordNotChecked(status.1 & 0xf)`). This module calls `VERIFY` with
//! the default exactly once per PIN per call (no internal retry loop,
//! consistent with this crate's design constraint of never silently
//! retrying a PIN — see the design spec's "Error handling & operational
//! behavior" section), but a caller that invokes
//! `is_pin_factory_default`/`require_pin_changed` repeatedly against an
//! already-changed PIN (e.g. on every operator retry of a failed
//! provisioning command) will eventually exhaust that PIN's retries and
//! block it. Provisioning flows should call this once per attempt, not
//! in a loop — this is exercised directly by this module's own
//! `blocked_user_pin_surfaces_as_pin_blocked_not_a_default_verdict` test
//! below.
//!
//! A successful `VERIFY` also leaves the PIN in the "verified" session
//! state on the card — harmless here, since a fresh transaction clears
//! that state again (see `testing.rs`'s doc comment, section 5), and any
//! later provisioning step needing verified access re-verifies via its
//! own call anyway (e.g. `Card<Transaction>::as_admin_card`).

use openpgp_card::{Card, Error as OpenpgpError, ocard::StatusBytes, state::Transaction};
use secrecy::SecretString;

use crate::YubiError;

/// Well-known OpenPGP card factory-default User PIN (PW1). See this
/// module's doc comment for where this is grounded.
pub const FACTORY_DEFAULT_USER_PIN: &str = "123456";

/// Well-known OpenPGP card factory-default Admin PIN (PW3). See this
/// module's doc comment for where this is grounded.
pub const FACTORY_DEFAULT_ADMIN_PIN: &str = "12345678";

/// True if the card's User PIN (PW1) and/or Admin PIN (PW3) is still at
/// its OpenPGP-card factory default. Either being unchanged is treated
/// as "still default": PW3 gates key generation and other admin
/// operations, PW1 gates signing, and this crate's provisioning flow
/// (see [`require_pin_changed`]) needs both changed before it proceeds.
///
/// Attempts one `VERIFY` per PIN against the well-known default value —
/// see this module's doc comment for the real-retry-counter cost of that
/// and why there's no cheaper real-protocol way to ask.
pub fn is_pin_factory_default(tx: &mut Card<Transaction<'_>>) -> Result<bool, YubiError> {
    let user_is_default =
        verify_matches_default(tx.verify_user_pin(SecretString::from(FACTORY_DEFAULT_USER_PIN)))?;
    let admin_is_default =
        verify_matches_default(tx.verify_admin_pin(SecretString::from(FACTORY_DEFAULT_ADMIN_PIN)))?;
    Ok(user_is_default || admin_is_default)
}

/// [`is_pin_factory_default`], but returns a provisioning-blocking
/// [`YubiError::PinStillFactoryDefault`] instead of `Ok(true)` — the
/// entry point provisioning flows should call, per this crate's design
/// constraint: refuse to proceed on a factory-default PIN.
pub fn require_pin_changed(tx: &mut Card<Transaction<'_>>) -> Result<(), YubiError> {
    if is_pin_factory_default(tx)? {
        return Err(YubiError::PinStillFactoryDefault);
    }
    Ok(())
}

/// Interpret the result of a `VERIFY`-with-default attempt: success means
/// the PIN is (still) that default; a plain wrong-PIN rejection
/// (`PasswordNotChecked`, real status word `63 Cx`) means it's been
/// changed away from the default; anything else (blocked, transport
/// failure, ...) is a real error this function can't paper over — it
/// propagates via [`YubiError`]'s `From<openpgp_card::Error>` impl (see
/// `lib.rs`), which maps `AuthenticationMethodBlocked` specifically to
/// [`YubiError::PinBlocked`].
fn verify_matches_default(result: Result<(), OpenpgpError>) -> Result<bool, YubiError> {
    match result {
        Ok(()) => Ok(true),
        Err(OpenpgpError::CardStatus(StatusBytes::PasswordNotChecked(_))) => Ok(false),
        Err(other) => Err(other.into()),
    }
}

#[cfg(test)]
mod tests {
    use openpgp_card::Card;

    use super::*;
    use crate::testing::FakeCard;

    #[test]
    fn factory_default_pins_are_detected() {
        let fake = FakeCard::new();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        assert!(is_pin_factory_default(&mut tx).unwrap());
    }

    #[test]
    fn require_pin_changed_blocks_on_factory_default() {
        let fake = FakeCard::new();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        let err = require_pin_changed(&mut tx).unwrap_err();
        assert!(matches!(err, YubiError::PinStillFactoryDefault));
    }

    #[test]
    fn changed_user_pin_alone_is_still_reported_as_default_via_admin_pin() {
        // Only the User PIN changed; the Admin PIN (PW3) is still
        // default — `is_pin_factory_default` must still report true,
        // since PW3 gates admin operations and provisioning needs both
        // changed.
        let fake = FakeCard::new().with_changed_user_pin(b"000000");
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        assert!(is_pin_factory_default(&mut tx).unwrap());
    }

    #[test]
    fn both_pins_changed_are_reported_as_not_default() {
        let fake = FakeCard::new()
            .with_changed_user_pin(b"000000")
            .with_changed_admin_pin(b"00000000");
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        assert!(!is_pin_factory_default(&mut tx).unwrap());
        assert!(require_pin_changed(&mut tx).is_ok());
    }

    #[test]
    fn blocked_user_pin_surfaces_as_pin_blocked_not_a_default_verdict() {
        // Admin PIN (PW3) is left at its factory default throughout, so
        // only the User PIN (PW1) side of each `is_pin_factory_default`
        // call is a wrong VERIFY here.
        let fake = FakeCard::new().with_changed_user_pin(b"000000");
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        // Each call wrongly VERIFYs the default "123456" against the
        // real (changed) PIN "000000", consuming one of PW1's 3 real
        // retries (see this module's doc comment on the real cost of
        // this check).
        for _ in 0..3 {
            is_pin_factory_default(&mut tx).unwrap();
        }

        let err = is_pin_factory_default(&mut tx).unwrap_err();
        assert!(matches!(err, YubiError::PinBlocked));
    }
}
