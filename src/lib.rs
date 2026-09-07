//! `aivyx-yubi` — hardware-backed Ed25519 signing via a YubiKey's
//! OpenPGP card applet. See `docs/superpowers/specs/
//! 2026-09-07-aivyx-yubi-design.md` for the full design rationale.

pub use openpgp_card::Card;

pub mod discovery;
pub mod pin;

/// Fake `CardBackend`/`CardTransaction` test double standing in for real
/// YubiKey hardware. See the module's own doc comment for how it was
/// grounded in `openpgp-card`'s real vendored source.
///
/// Available under plain `cargo test` (via `cfg(test)`, for this crate's
/// own unit tests) and, for later tasks' integration tests under `tests/`,
/// under the `test-util` Cargo feature (`cargo test --features test-util`).
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

use openpgp_card::ocard::StatusBytes;

/// This crate's public error type — every public function in
/// `discovery`/`pin` (and later tasks' `keygen`/`sign`) returns this,
/// rather than leaking `openpgp_card::Error` or
/// `card_backend::SmartcardError` directly, so downstream callers
/// (`aivyx-federation`, `aivyx-cli`) get a stable, crate-local error type
/// instead of depending on this crate's own dependency versions.
///
/// The variant set starts from the brief's proposal and adds one
/// (`PinBlocked`) found necessary while implementing `pin.rs` — see that
/// variant's own doc comment.
#[derive(Debug, thiserror::Error)]
pub enum YubiError {
    /// No card/reader found, or `pcscd` unreachable. The `String` names
    /// the likely cause (e.g. "is pcscd running?") rather than surfacing
    /// a raw PC/SC error string on its own — see `discovery.rs`.
    #[error("{0}")]
    CardNotFound(String),

    /// Provisioning-blocking: the card's User and/or Admin PIN is still
    /// the OpenPGP-card factory default (`123456`/`12345678`). Returned
    /// by `pin::require_pin_changed`.
    #[error(
        "card PIN is still the factory default (123456/12345678) — change it via the \
         standard OpenPGP-card PIN-change command before proceeding"
    )]
    PinStillFactoryDefault,

    /// The inserted card's serial doesn't match a previously bound one.
    /// Not constructed anywhere in this crate today — `aivyx-yubi` itself
    /// has no concept of a persisted binding record, that lives in
    /// `aivyx-federation` (see the design spec's Task 7) — but defined
    /// here since this is this crate's shared public error type and that
    /// caller needs a variant to map its own "wrong card" check into.
    #[error("wrong YubiKey inserted: expected card serial {expected}, found {found}")]
    WrongCard { expected: String, found: String },

    /// The card's own touch-confirmation timeout elapsed before the
    /// operator tapped the key. Not produced by this task's code (no
    /// signing yet, see Task 4/5) — defined here for that later signing
    /// path, which returns this same error type.
    #[error("timed out waiting for a physical touch confirmation on the card")]
    TouchTimeout,

    /// A PIN was presented and the card rejected it as wrong (but the
    /// PIN is not yet blocked — real status word `63 Cx`,
    /// `StatusBytes::PasswordNotChecked`).
    #[error("PIN incorrect")]
    PinIncorrect,

    /// The PIN's retry counter has hit zero (real status word `69 83`,
    /// `StatusBytes::AuthenticationMethodBlocked`); the card refuses any
    /// further `VERIFY` for it until unblocked via the Admin PIN/Reset
    /// Code. Added beyond the brief's original variant list:
    /// `pin::is_pin_factory_default`'s only real way to check a PIN
    /// (attempting `VERIFY` with the well-known default — see
    /// `pin.rs`'s doc comment) can hit this real card state, and folding
    /// it into `PinIncorrect` would misleadingly suggest a retry could
    /// still succeed.
    #[error(
        "PIN is blocked (too many incorrect attempts) — unblock it via the admin PIN/Reset \
         Code before proceeding"
    )]
    PinBlocked,

    /// Catch-all for every other real error this crate's dependencies can
    /// report (raw APDU status words not covered above, transport
    /// failures unrelated to touch, etc).
    #[error("{0}")]
    Other(String),
}

impl From<openpgp_card::Error> for YubiError {
    fn from(err: openpgp_card::Error) -> Self {
        match err {
            openpgp_card::Error::CardStatus(StatusBytes::PasswordNotChecked(_)) => {
                YubiError::PinIncorrect
            }
            openpgp_card::Error::CardStatus(StatusBytes::AuthenticationMethodBlocked) => {
                YubiError::PinBlocked
            }
            other => YubiError::Other(other.to_string()),
        }
    }
}
