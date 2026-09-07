//! `aivyx-yubi` — hardware-backed Ed25519 signing via a YubiKey's
//! OpenPGP card applet. See `docs/superpowers/specs/
//! 2026-09-07-aivyx-yubi-design.md` for the full design rationale.

pub use openpgp_card::Card;

pub mod discovery;
pub mod pin;
pub mod provision;
pub mod sign;

// Re-exported at the crate root: this is the crate's main external API
// surface (`aivyx-federation`'s `Identity`, Task 7, is the intended
// consumer) — see `sign.rs`'s own doc comment for the full design. A
// caller shouldn't need to know `YubiKeySigner` happens to live in a
// `sign` submodule to reach it.
pub use sign::YubiKeySigner;

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
/// `discovery`/`pin`/`provision` (and a later task's `sign`) returns this,
/// rather than leaking `openpgp_card::Error` or
/// `card_backend::SmartcardError` directly, so downstream callers
/// (`aivyx-federation`, `aivyx-cli`) get a stable, crate-local error type
/// instead of depending on this crate's own dependency versions.
///
/// The variant set starts from the brief's proposal and adds two beyond
/// it: [`PinBlocked`], found necessary while implementing `pin.rs`, and
/// [`AdminAuthRequired`], found necessary while implementing `provision.rs`
/// — see each variant's own doc comment.
///
/// [`PinBlocked`]: YubiError::PinBlocked
/// [`AdminAuthRequired`]: YubiError::AdminAuthRequired
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
    /// further `VERIFY` for it until unblocked. Added beyond the brief's
    /// original variant list: `pin::is_pin_factory_default`'s only real
    /// way to check a PIN (attempting `VERIFY` with the well-known
    /// default — see `pin.rs`'s doc comment) can hit this real card
    /// state, and folding it into `PinIncorrect` would misleadingly
    /// suggest a retry could still succeed.
    ///
    /// Carries which PIN blocked (`pin_kind`, `"User"` or `"Admin"`) and
    /// an accurate recovery hint for that specific PIN, because the two
    /// cases are **not** symmetric: a blocked User PIN (PW1) is
    /// recoverable via the Admin PIN's RESET RETRY COUNTER operation, but
    /// a blocked Admin PIN (PW3) is *not* self-recoverable — only a
    /// pre-configured Reset Code or a full TERMINATE+ACTIVATE (which
    /// erases all keys) can recover from that state. A single fixed
    /// message claiming "unblock it via the admin PIN" would be actively
    /// wrong (circular) for the Admin-PIN-blocked case. See
    /// `pin.rs::PinKind` for where these two variants are constructed.
    #[error("{pin_kind} PIN is blocked (too many failed attempts). {recovery_hint}")]
    PinBlocked {
        /// Which PIN blocked: `"User"` or `"Admin"`.
        pin_kind: &'static str,
        /// Accurate, PIN-kind-specific recovery guidance.
        recovery_hint: &'static str,
    },

    /// An admin-gated card operation (key generation, touch-policy
    /// change, ...) was attempted without the Admin PIN (PW3) having
    /// been verified first (real status word `69 82`,
    /// `StatusBytes::SecurityStatusNotSatisfied`). Added for `provision.rs`
    /// (Task 4): both `provision::generate_signature_key` and
    /// `provision::set_signature_touch_policy_fixed` require a
    /// PW3-authenticated `Card<Admin>` and map this specific status word
    /// to this variant (via `provision.rs`'s own `map_admin_op_error`)
    /// rather than letting it fall through to the generic [`Other`]
    /// catch-all, since "you forgot to verify the Admin PIN" is a much
    /// more actionable message than a raw status-word string.
    ///
    /// [`Other`]: YubiError::Other
    #[error(
        "admin-gated card operation attempted without the Admin PIN (PW3) verified first — \
         verify the Admin PIN (e.g. via `Card<Transaction>::as_admin_card`) before retrying"
    )]
    AdminAuthRequired,

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
                // This blanket conversion has no context on which PIN
                // (User/PW1 or Admin/PW3) was being verified when the
                // card reported it blocked — that distinction matters a
                // lot (see `PinBlocked`'s doc comment) but callers that
                // *do* have that context (e.g. `pin::verify_matches_default`)
                // construct the correctly-labeled `PinBlocked` variant
                // directly instead of going through this `From` impl.
                // This fallback deliberately doesn't guess a pin_kind and
                // gives recovery guidance that's accurate for either case.
                YubiError::PinBlocked {
                    pin_kind: "A",
                    recovery_hint: "Check which PIN blocked: a blocked User PIN can be reset \
                                    via the Admin PIN's RESET RETRY COUNTER operation, but a \
                                    blocked Admin PIN cannot recover itself — that requires a \
                                    pre-configured Reset Code or a full card reset \
                                    (TERMINATE+ACTIVATE, which erases all keys).",
                }
            }
            other => YubiError::Other(other.to_string()),
        }
    }
}
