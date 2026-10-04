//! `aivyx-yubi` — hardware-backed Ed25519 signing via a YubiKey's
//! OpenPGP card applet. See `docs/superpowers/specs/
//! 2026-09-07-aivyx-yubi-design.md` for the full design rationale.
//!
//! # Prefer [`YubiKeySigner`] over calling `discovery`/`provision`/`pin`
//! # directly
//!
//! Those modules' public functions take a caller-supplied
//! `&mut Card<Transaction<'_>>` and do nothing to stop a caller from
//! opening a *second*, overlapping transaction on the same physical
//! reader while the first is still held open. PC/SC has no reentrancy
//! here — doing so deadlocks (`SCardBeginTransaction` blocks forever
//! waiting for the first transaction to end, with no timeout). This is
//! exactly the real bug `aivyx-pa`'s Phase 208 hit in its own CLI
//! provisioning flow: it held one exclusive transaction open through key
//! generation and touch-policy setup, then tried to open a second on the
//! same reader for a "verification pass" — hanging forever, *after* the
//! card had already been irreversibly re-keyed. [`YubiKeySigner`]
//! avoids this whole hazard class by construction (see `sign.rs`'s own
//! "holds no live card session" doc comment); a caller reaching for
//! `discovery`/`provision`/`pin` directly takes on avoiding it the same
//! way `sign.rs` does — one transaction open at a time, closed before
//! the next begins.

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

// Re-exported so a consumer of `YubiKeySigner::new(user_pin: SecretString)`
// (e.g. a future CLI in a different repo) gets the exact `secrecy` type
// this crate's public API expects for free, rather than needing to add
// their own `secrecy` dependency independently pinned to a version
// compatible with what `openpgp-card` 0.7.0 actually uses internally
// (discoverable otherwise only by reading this crate's own `Cargo.toml`)
// (Finding M-5).
pub use secrecy::SecretString;

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
/// `discovery`/`pin`/`provision`/`sign` returns this, rather than leaking
/// `openpgp_card::Error` or `card_backend::SmartcardError` directly, so
/// downstream callers
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
    /// Constructed by `sign::YubiKeySigner::sign` (this crate's own check
    /// that the card it just discovered is the same one it was
    /// constructed against — see `sign.rs`'s doc comment). Also available
    /// for `aivyx-federation` (see the design spec's Task 7) to construct
    /// against its own persisted binding record, a concept `aivyx-yubi`
    /// itself has none of.
    #[error("wrong YubiKey inserted: expected card serial {expected}, found {found}")]
    WrongCard { expected: String, found: String },

    /// The card's own touch-confirmation timeout elapsed before the
    /// operator tapped the key. Produced by `sign`'s private
    /// `map_sign_error` at the `PSO: COMPUTE DIGITAL SIGNATURE` call site,
    /// from either of two real shapes: the OpenPGP applet's own `69 85`
    /// "Condition of use not satisfied" status word (its UIF touch
    /// window, ~15s, expiring while the card is still able to answer), or
    /// the transport-level `"Transmit failed: Timeout"` string a PC/SC
    /// reader produces if it's still blocked in `transmit()` when the
    /// window expires instead — see `sign.rs`'s own doc comment for the
    /// full grounding.
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

    /// The Signature slot's touch-policy is not `Fixed` (physical-touch
    /// confirmation required on every signature) — this crate's entire
    /// reason to exist, checked and enforced at signing time rather than
    /// merely assumed from provisioning having (hopefully) run once.
    /// Returned by `sign::YubiKeySigner::sign`'s private
    /// `sign_with_open_card`, which reads back the Signature slot's live
    /// touch policy (`Card<Transaction>::user_interaction_flag`) on every
    /// call, immediately after the card-serial check and before
    /// presenting the PIN or attempting to sign — see `sign.rs`'s own doc
    /// comment (Finding I-1) for the full grounding and the concrete
    /// failure scenarios this closes (interrupted/failed provisioning, a
    /// key created by other tooling with touch disabled, an
    /// `UnsupportedFeature` card, ...). Never proceed to sign without this
    /// check passing — a silent downgrade to a touch-less, PIN-only
    /// signature is exactly the "weaker guarantee" this crate's design
    /// spec forbids.
    #[error(
        "the Signature slot's touch policy is not set to Fixed (physical touch confirmation) — \
         refusing to sign without touch enforcement; run provisioning \
         (`provision::set_signature_touch_policy_fixed`) against this card first"
    )]
    TouchPolicyNotEnforced,

    /// [`sign::YubiKeySigner::new`]/`from_open_card` was given an empty
    /// User PIN. Found live in `aivyx-pa`'s `yubikey-init`
    /// (`aivyx-cli/.../federation.rs:236`, constructing
    /// `YubiKeySigner::new(SecretString::from(String::new()))`) during the
    /// 2026-10-04 audit: an empty PIN is certain to be rejected by the
    /// card on the first real `sign()` call, so refusing it up front, at
    /// construction, catches the mistake immediately rather than only on
    /// first use (and before it can ever consume a real PIN retry -- see
    /// [`PinIncorrect`]).
    ///
    /// [`PinIncorrect`]: YubiError::PinIncorrect
    #[error("YubiKeySigner was constructed with an empty User PIN -- refusing before touching the card")]
    EmptyPin,

    /// A PIN's retry counter (`PWStatusBytes`, GET DATA tag `C4`) was
    /// already below its maximum *before* this crate attempted anything
    /// PIN-related. Returned by `pin::require_pin_retries_at_maximum`
    /// (called first by `pin::require_pin_changed`, Finding I-4): reading
    /// this counter needs no PIN itself, so checking it first means the
    /// factory-default probe (which does spend a real retry per PIN, see
    /// `pin.rs`'s doc comment) never becomes the attempt that blocks an
    /// already-weakened PIN.
    #[error(
        "{pin_kind} PIN already has reduced retries ({retries_left}/{max_retries} remaining) -- \
         refusing to spend any more of them by probing; check the card with \
         `gpg --card-status` before proceeding"
    )]
    PinRetriesReduced {
        /// Which PIN's counter is reduced: `"User"` or `"Admin"`.
        pin_kind: &'static str,
        /// The counter's current value, read straight from the card.
        retries_left: u8,
        /// The OpenPGP card spec's standard maximum (3) -- see
        /// `pin::MAX_PIN_RETRIES`.
        max_retries: u8,
    },

    /// `provision::generate_signature_key` refused: the Signature slot
    /// already holds a key (Finding I-3). Call
    /// `provision::generate_signature_key_overwriting` instead, once the
    /// operator has explicitly confirmed that losing the existing key is
    /// intended -- generating (or reconfiguring the algorithm for) a new
    /// key irreversibly destroys whatever private key currently occupies
    /// the slot, which may be a GPG signing key the cardholder already
    /// relies on outside this crate.
    #[error(
        "the Signature slot already holds a key -- refusing to overwrite it; call \
         `generate_signature_key_overwriting` instead once the operator has explicitly \
         confirmed losing the existing key is intended"
    )]
    SignatureSlotOccupied,

    /// `sign::YubiKeySigner::sign` found that the Signature slot's
    /// *current* public key no longer matches the one this signer cached
    /// at construction (Finding M-1). This means the slot was re-keyed
    /// (deliberately or otherwise) after this `YubiKeySigner` was built:
    /// continuing to sign would produce signatures from a *different*
    /// private key than the one `public_key()` reports, which a peer
    /// verifying against the stale cached key would silently reject with
    /// no diagnosable cause. Re-construct the signer (`YubiKeySigner::new`)
    /// to re-bind to the slot's current key.
    #[error(
        "the Signature slot's current public key no longer matches the one this signer was \
         constructed against -- the slot was likely re-keyed; re-construct YubiKeySigner to \
         re-bind to its current key before signing"
    )]
    SignatureKeyChanged,

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
                    // "Some" (not a guessed "User"/"Admin", and not the
                    // bare, confusingly letter-like placeholder this used
                    // to say -- see `pin_kind`'s own doc comment and the
                    // audit's M4 finding): this call site genuinely has no
                    // way to know which PIN blocked, and callers that *do*
                    // know (`pin::verify_matches_default`,
                    // `sign::map_signing_pin_error`) construct the
                    // correctly-labeled variant directly instead of
                    // reaching this fallback at all.
                    pin_kind: "Some",
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
