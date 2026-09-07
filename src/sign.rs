//! Hardware-backed Ed25519 signing: [`YubiKeySigner`], this crate's main
//! external API surface (`aivyx-federation`'s `Identity`, Task 7, is its
//! only intended consumer).
//!
//! # Grounding: the real signing call shape
//!
//! `Card<Sign>` (the typestate a naive reading of `openpgp-card`'s API
//! would expect to sign through) is a dead end in 0.7.0 — its
//! `signer()`/`signer_from_public()` methods are commented out with a
//! `// FIXME` in the vendored source, and its `card()` escape hatch is
//! private. See `testing.rs`'s doc comment, section 3, for the full
//! grounding; this module just uses what that investigation found:
//!
//! 1. `Card<Transaction>::verify_user_signing_pin(pin: SecretString)` —
//!    verifies PW1 in signing mode (VERIFY P2 `0x81`, distinct from the
//!    plain-User mode `0x82`).
//! 2. `Card<Transaction>::card(&mut self) -> &mut ocard::Transaction<'a>`
//!    — public (if `// FIXME: remove later?`-flagged) escape hatch to the
//!    low-level transaction object.
//! 3. `ocard::Transaction::signature_for_hash(algo: SigningAlgo, digest:
//!    &[u8])` — a thin wrapper over `pso_compute_digital_signature` that,
//!    for `SigningAlgo::ECC`, passes `digest` straight through unchanged
//!    as the command's data field (confirmed directly against
//!    `openpgp-card-0.7.0/src/ocard/mod.rs` ~1042-1061: the RSA arm
//!    builds a DigestInfo structure, "With ECC the hash data is processed
//!    as is"). This module calls it with the **raw message bytes**, not a
//!    pre-hashed digest: pure EdDSA (which is what the OpenPGP card's
//!    Ed25519 support actually is, per `ocard/algorithm.rs`'s
//!    `EccType::EdDSA`) verifies over the whole message and derives its
//!    per-signature nonce deterministically from it (RFC 8032) — unlike
//!    ECDSA/RSA, there is no meaningful "digest to sign" to compute
//!    upfront, so the crate's own "processed as is" framing is exactly
//!    the right shape for what `sign()` needs to do with an arbitrary
//!    `message: &[u8]`.
//!
//! # Grounding: is a PIN needed before every signature, touch policy aside?
//!
//! Yes, always — this module never skips `verify_user_signing_pin`.
//! `Card<Transaction>::verify_user_signing_pin`'s own doc comment
//! (`openpgp-card-0.7.0/src/lib.rs` ~239-241) says plainly: "depending on
//! the configuration of the card, this may enable performing just one
//! signing operation, or an unlimited amount of signing operations" —
//! i.e. whether a single PW1-signing VERIFY covers one `PSO:CDS` or many
//! is a per-card PW1 "valid once" setting (`PWStatusBytes` byte 0,
//! `ocard/data/pw_status.rs`) this crate never reads or assumes a value
//! for. Re-verifying on every call is correct regardless of which way
//! that setting is configured on the card actually in the reader (a
//! redundant VERIFY on an already-satisfied "valid until reset" card is
//! harmless — the fake models this too: `PinSlot::verify` re-validates
//! and resets `retries_left` to 3 on a correct PIN, it doesn't reject a
//! second correct VERIFY). Touch confirmation (this crate's design-spec
//! requirement, enforced by `provision::set_signature_touch_policy_fixed`
//! setting `TouchPolicy::Fixed` on the card itself) is a wholly separate
//! gate the card applies at the `PSO:CDS` step regardless of PW1 state —
//! nothing in this module needs to special-case it beyond mapping the
//! transport-level failure it produces (see below).
//!
//! # Grounding: detecting a touch timeout
//!
//! A touch timeout is **not** a card status word — the OpenPGP card never
//! gets to answer at all while the reader is still blocked waiting for
//! the physical tap, so it surfaces as a *transport*-level failure from
//! `transmit()` itself (`testing.rs`'s doc comment, section 5, and its
//! `with_touch_timeout` fixture, confirmed directly against real
//! `card-backend-pcsc` behavior below). Concretely, traced through the
//! real dependency chain:
//! - `pcsc` 2.9.0 (`src/lib.rs`): `Error::Timeout = SCARD_E_TIMEOUT`, a
//!   fieldless enum variant, so `format!("{e:?}")` on it renders exactly
//!   `"Timeout"`.
//! - `card-backend-pcsc` 0.5.2 (`src/lib.rs`, `PcscTransaction::transmit`,
//!   line ~274): every `pcsc::Error` other than `NotTransacted` falls
//!   through a catch-all arm, `SmartcardError::Error(format!("Transmit
//!   failed: {e:?}"))` — so a real reader timeout surfaces as
//!   `SmartcardError::Error("Transmit failed: Timeout")` specifically,
//!   with no dedicated timeout variant to match on structurally.
//! - `openpgp-card` wraps that as `Error::Smartcard(SmartcardError::Error(..))`
//!   (confirmed by `testing.rs::tests::touch_timeout_surfaces_as_a_smartcard_error`,
//!   which asserts exactly this against the fake).
//!
//! [`map_sign_error`] therefore maps **any** `Error::Smartcard(_)`
//! encountered specifically at the `PSO:CDS` call site (not elsewhere —
//! see its own doc comment) to [`YubiError::TouchTimeout`], rather than
//! trying to pattern-match or substring-match the message text (which
//! would be fragile: the fake's own fixture text, `"reader timed out
//! waiting for touch confirmation"`, doesn't even contain the literal
//! substring `"timeout"`). This is a deliberate, honestly-documented
//! approximation, not a structurally sound discriminant: with the
//! Signature slot's touch policy fixed to `Fixed` (this crate's design
//! constraint, set once by `provision::set_signature_touch_policy_fixed`),
//! an operator not tapping the key in time is overwhelmingly the real
//! cause of any transport-level failure occurring at exactly this call —
//! but a genuinely different transport fault at that same instant (e.g.
//! the device being physically unplugged mid-signature) would also be
//! misreported as `TouchTimeout` under this mapping. Accepted as the
//! better trade-off: the alternative (falling through to the generic
//! [`YubiError::Other`]) is less actionable for the overwhelmingly common
//! case, and there is no structured PC/SC signal this crate's
//! dependencies expose to distinguish the two.
//!
//! [`YubiError::Other`]: crate::YubiError::Other
//!
//! # Architecture decision: `YubiKeySigner` holds no live card session
//!
//! [`YubiKeySigner::sign`] re-discovers and re-opens the physical card
//! completely fresh on *every* call — it does not hold a `Card<Open>`,
//! `Card<Transaction>`, or any other live PC/SC handle across calls. Two
//! independent reasons converge on this, either one would have been
//! sufficient alone:
//!
//! 1. **It's the practical, physical-device-safe choice.** This crate's
//!    whole design point (Global Constraints, design spec) is a physical
//!    touch gate on *every* signature with no PIN/session-cached
//!    fast-path — the operator is expected to be present and tapping the
//!    key for each call, and the design spec explicitly allows for the
//!    key being unplugged between uses. A long-lived open PC/SC session
//!    held across an unpredictable gap (a daemon's entire uptime,
//!    potentially) risks going stale under the operator's feet with no
//!    clean way for this crate to detect that short of trying and
//!    failing, at which point re-discovering was going to be needed
//!    anyway.
//! 2. **It's close to the only choice the real type signatures actually
//!    allow, safely.** `Card<Transaction<'a>>` *borrows* the `Card<Open>`
//!    it was created from (`fn transaction(&mut self) -> Result<Card
//!    <Transaction<'_>>, Error>`, confirmed against `lib.rs` line ~163) —
//!    a struct that owned both a `Card<Open>` field and a
//!    `Card<Transaction<'_>>` field borrowing *from that same field*
//!    would be self-referential, which safe Rust cannot express without
//!    reaching for an `unsafe`-internally crate like `ouroboros`/
//!    `self_cell`. This crate takes on no such dependency or unsafe code
//!    for this. (A `Card<Open>` alone, with a fresh `.transaction()` per
//!    `sign()` call, *could* in principle be held long-lived without that
//!    problem — but reason 1 above means that's not actually wanted even
//!    though it would compile.)
//!
//! Consequence for Task 7 (`aivyx-federation`'s `Identity`, the intended
//! caller): **`YubiKeySigner` is safe to hold for a daemon's entire
//! lifetime.** It caches only the plain data captured once at
//! construction — the Signature slot's public key, the card's serial
//! string, and the User PIN it was given (kept in memory as a
//! `secrecy::SecretString`, cloned fresh for each `verify_user_signing_pin`
//! call rather than consumed) — none of which requires a live card to be
//! present. Every `public_key()`/`card_serial()` call is a plain,
//! infallible in-memory read (hence their non-`Result` signatures); every
//! `sign()` call independently performs the full discover → open →
//! verify-PIN → touch-gated-sign sequence against whatever card is
//! physically present *at that moment*, and simply fails with
//! [`YubiError::CardNotFound`] if none is. `YubiKeySigner` deliberately
//! does **not** check that the freshly-discovered card's serial matches
//! `self.card_serial` — that "wrong card inserted" binding check is
//! `aivyx-federation`'s job (see [`YubiError::WrongCard`]'s own doc
//! comment in `lib.rs`, "not constructed anywhere in this crate"), which
//! this module respects by construction rather than duplicating.
//!
//! [`YubiError::WrongCard`]: crate::YubiError::WrongCard

#[cfg(test)]
use card_backend::{CardBackend, SmartcardError};
use openpgp_card::{
    Card, Error as OpenpgpError,
    ocard::{
        StatusBytes,
        crypto::{PublicKeyMaterial, SigningAlgo},
    },
    state::Open,
};
use secrecy::SecretString;

use crate::{YubiError, discovery, pin::PinKind};

/// A hardware-backed Ed25519 signer over a YubiKey's OpenPGP card
/// Signature slot. See this module's own doc comment for the full
/// grounding and, in particular, why this type is safe to hold across a
/// long-lived process despite never keeping a card session open.
///
/// Deliberately does not derive/implement `Debug` on its own fields'
/// behalf beyond what `secrecy::SecretString` itself safely provides
/// (`SecretBox<str>([REDACTED])`, never the real PIN) — the derive is
/// otherwise plain field-by-field, not a hand-written impl, since none of
/// `card_serial`/`public_key` are sensitive.
#[derive(Debug)]
pub struct YubiKeySigner {
    card_serial: String,
    public_key: [u8; 32],
    user_pin: SecretString,
}

impl YubiKeySigner {
    /// Discover the (first) connected YubiKey and bind a signer to its
    /// Signature slot's already-provisioned public key.
    ///
    /// `user_pin` is kept in memory (not verified against the card yet —
    /// reading the public key needs no PIN at all, see
    /// [`from_open_card`][Self::from_open_card]) and re-presented fresh on
    /// every later [`Self::sign`] call. A wrong PIN is therefore only
    /// discovered on the first `sign()` call, not here — see this
    /// module's doc comment for why `sign()` always re-verifies rather
    /// than trusting a cached "verified" state anyway.
    ///
    /// Requires the Signature slot to already hold an Ed25519 key (i.e.
    /// this crate's provisioning flow, `provision::generate_signature_key`,
    /// must have already run against this card) — this constructor only
    /// reads the existing public key, it does not generate one.
    pub fn new(user_pin: SecretString) -> Result<Self, YubiError> {
        let card = discovery::discover_real_card()?;
        Self::from_open_card(card, user_pin)
    }

    /// The testable core of [`Self::new`]: given an already-opened
    /// `Card<Open>` (real hardware via [`Self::new`], or
    /// [`crate::testing::FakeCard`] in this module's own tests), reads the
    /// card's serial and the Signature slot's current public key and
    /// builds a [`YubiKeySigner`] bound to them.
    fn from_open_card(mut card: Card<Open>, user_pin: SecretString) -> Result<Self, YubiError> {
        let mut tx = card.transaction()?;
        let card_serial = discovery::read_serial(&mut tx)?;
        let public_key = read_signature_public_key(&mut tx)?;
        Ok(Self {
            card_serial,
            public_key,
            user_pin,
        })
    }

    /// [`Self::new`], but discovers the card from an arbitrary backend
    /// iterator instead of the real `card_backends()` enumeration — the
    /// seam this module's own tests use to exercise discovery failure
    /// (e.g. "card absent") through the *whole* construction path, not
    /// just `discovery::discover_card_from` in isolation.
    #[cfg(test)]
    fn discover_and_construct(
        backends: impl Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
        user_pin: SecretString,
    ) -> Result<Self, YubiError> {
        let card = discovery::discover_card_from(backends)?;
        Self::from_open_card(card, user_pin)
    }

    /// This signer's cached Ed25519 public key point (32 raw bytes),
    /// captured once at construction. A plain in-memory read — no card
    /// I/O, see this module's doc comment.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// This signer's cached card serial (`"MMMM:SSSSSSSS"`, manufacturer
    /// id + serial — see `discovery::read_serial`), captured once at
    /// construction. A plain in-memory read — no card I/O, see this
    /// module's doc comment.
    pub fn card_serial(&self) -> &str {
        &self.card_serial
    }

    /// Sign `message` with the Signature slot's on-card Ed25519 private
    /// key, requiring both the User PIN (verified fresh, every call) and
    /// a physical touch confirmation (enforced by the card itself, per
    /// this crate's fixed touch-policy provisioning).
    ///
    /// Re-discovers and re-opens the physical card from scratch on every
    /// call rather than reusing any state from construction beyond the
    /// cached PIN — see this module's doc comment for why.
    pub fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], YubiError> {
        let card = discovery::discover_real_card()?;
        Self::sign_with_open_card(card, &self.user_pin, message)
    }

    /// The testable core of [`Self::sign`]: given an already-opened
    /// `Card<Open>`, verifies the User PIN for signing and performs the
    /// actual `PSO: COMPUTE DIGITAL SIGNATURE`, mapping every real
    /// failure path to the matching [`YubiError`] variant. See this
    /// module's doc comment for the grounding behind each mapping.
    fn sign_with_open_card(
        mut card: Card<Open>,
        user_pin: &SecretString,
        message: &[u8],
    ) -> Result<[u8; 64], YubiError> {
        let mut tx = card.transaction()?;

        tx.verify_user_signing_pin(user_pin.clone())
            .map_err(map_signing_pin_error)?;

        let signature = tx
            .card()
            .signature_for_hash(SigningAlgo::ECC, message)
            .map_err(map_sign_error)?;

        signature.try_into().map_err(|bytes: Vec<u8>| {
            YubiError::Other(format!(
                "card returned a {}-byte signature, expected exactly 64 (Ed25519)",
                bytes.len()
            ))
        })
    }

    /// [`Self::sign`], but discovers the card from an arbitrary backend
    /// iterator — see [`Self::discover_and_construct`]'s doc comment for
    /// why this seam exists.
    #[cfg(test)]
    fn discover_and_sign(
        backends: impl Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
        user_pin: &SecretString,
        message: &[u8],
    ) -> Result<[u8; 64], YubiError> {
        let card = discovery::discover_card_from(backends)?;
        Self::sign_with_open_card(card, user_pin, message)
    }
}

/// Read the Signature slot's current public key and validate it's
/// actually an Ed25519 point, mirroring the same real-API-grounded check
/// `provision::generate_signature_key` performs on its own `generate_key`
/// result (see that module's doc comment for the full reasoning: a bare
/// "32 bytes" check can't distinguish Ed25519 from Cv25519/X25519, and an
/// `R(..)` RSA result must be rejected rather than silently truncated).
/// Intentionally not shared code with `provision.rs` — this task's brief
/// scopes its changes to `sign.rs`/`lib.rs` only; a later cleanup task
/// could factor the shared predicate out if the duplication becomes a
/// maintenance problem.
///
/// `Card<Transaction>::public_key_material` (confirmed against
/// `openpgp-card-0.7.0/src/lib.rs` line ~733, wrapping `ocard::Transaction::
/// public_key`) needs no PIN verification at all — it's a plain `GET
/// PUBLIC KEY` read-back of already-generated key material, distinct from
/// generating a new one (which does need PW3/Admin, `provision.rs`'s
/// concern, not this one).
fn read_signature_public_key(
    tx: &mut Card<openpgp_card::state::Transaction<'_>>,
) -> Result<[u8; 32], YubiError> {
    use openpgp_card::ocard::{
        KeyType,
        algorithm::{AlgorithmAttributes, Curve},
        crypto::EccType,
    };

    let material = tx.public_key_material(KeyType::Signing)?;
    match material {
        PublicKeyMaterial::E(ecc) => {
            let is_ed25519 = matches!(
                ecc.algo(),
                AlgorithmAttributes::Ecc(attrs)
                    if attrs.ecc_type() == EccType::EdDSA && *attrs.curve() == Curve::Ed25519
            );
            if !is_ed25519 {
                return Err(YubiError::Other(format!(
                    "Signature slot holds a {:?} key, not Ed25519/EdDSA -- has \
                     `provision::generate_signature_key` been run against this card?",
                    ecc.algo()
                )));
            }
            ecc.data().try_into().map_err(|_| {
                YubiError::Other(format!(
                    "Signature slot's public key point is {} bytes, expected exactly 32 (Ed25519)",
                    ecc.data().len()
                ))
            })
        }
        PublicKeyMaterial::R(_) => Err(YubiError::Other(
            "Signature slot holds an RSA key, not Ed25519/EdDSA -- has \
             `provision::generate_signature_key` been run against this card?"
                .to_string(),
        )),
    }
}

/// Map a `verify_user_signing_pin` failure to the correctly-labeled
/// [`YubiError`], upgrading a blocked-PIN status word to a User-PIN-
/// labeled [`YubiError::PinBlocked`] (this call site always knows it's
/// verifying PW1/User, unlike the generic, context-free fallback in
/// `YubiError`'s `From<openpgp_card::Error>` impl — same reasoning
/// `pin::verify_matches_default` already applies, and this function
/// reuses its `PinKind` rather than re-deriving the same recovery-hint
/// wording). A plain wrong-PIN rejection (`PasswordNotChecked`) falls
/// through to that blanket `From` impl, which already maps it to
/// [`YubiError::PinIncorrect`] — no extra arm needed here for that case.
fn map_signing_pin_error(err: OpenpgpError) -> YubiError {
    match err {
        OpenpgpError::CardStatus(StatusBytes::AuthenticationMethodBlocked) => {
            PinKind::User.blocked_error()
        }
        other => other.into(),
    }
}

/// Map a `PSO: COMPUTE DIGITAL SIGNATURE` failure to the matching
/// [`YubiError`], in particular upgrading any transport-level
/// `Error::Smartcard(_)` to [`YubiError::TouchTimeout`] — see this
/// module's doc comment for the full grounding and the honest limits of
/// that mapping. Any other error shape (a card status word this crate
/// doesn't otherwise special-case) falls through to the blanket
/// `From<openpgp_card::Error>` impl.
fn map_sign_error(err: OpenpgpError) -> YubiError {
    match err {
        OpenpgpError::Smartcard(_) => YubiError::TouchTimeout,
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use openpgp_card::Card;

    use super::*;
    use crate::{pin, provision, testing::FakeCard};

    /// Build a [`Card<Open>`] wrapping `fake`, already admin-provisioned
    /// with a generated Ed25519 Signature-slot key (mirroring
    /// `provision.rs`'s own test setup) — the starting point every
    /// signing test below needs, since `YubiKeySigner` only ever *reads*
    /// an existing key, it never generates one.
    fn provisioned_card_from(fake: FakeCard) -> Card<Open> {
        let mut card = Card::new(fake).expect("Card::new should succeed against the fake");
        {
            let mut tx = card.transaction().expect("transaction should start");
            let admin_pin = SecretString::from(pin::FACTORY_DEFAULT_ADMIN_PIN);
            let mut admin = tx
                .as_admin_card(admin_pin)
                .expect("admin PIN should verify against the fake's factory-default PW3");
            provision::generate_signature_key(&mut admin)
                .expect("key generation should succeed against the fake");
        }
        card
    }

    fn provisioned_card() -> Card<Open> {
        provisioned_card_from(FakeCard::new())
    }

    #[test]
    fn successful_sign_returns_the_fakes_fabricated_signature() {
        let card = provisioned_card();
        let user_pin = SecretString::from(pin::FACTORY_DEFAULT_USER_PIN);

        let signature = YubiKeySigner::sign_with_open_card(card, &user_pin, b"hello, aivyx")
            .expect("signing should succeed against the fake");

        assert_eq!(signature, FakeCard::fake_signature());
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn public_key_and_card_serial_reflect_the_fakes_identity() {
        let card = provisioned_card();
        let user_pin = SecretString::from(pin::FACTORY_DEFAULT_USER_PIN);

        let signer = YubiKeySigner::from_open_card(card, user_pin)
            .expect("construction should succeed against the fake");

        assert_eq!(signer.public_key(), FakeCard::fake_public_key());
        // `FakeCard::new()`'s fixed manufacturer (0x0006) and serial
        // (0x00112233) -- see `testing.rs` and `discovery.rs`'s own
        // matching test.
        assert_eq!(signer.card_serial(), "0006:00112233");
    }

    #[test]
    fn card_absent_is_mapped_to_card_not_found_during_construction() {
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> =
            vec![Ok(FakeCard::absent().into())];
        let user_pin = SecretString::from(pin::FACTORY_DEFAULT_USER_PIN);

        let err = YubiKeySigner::discover_and_construct(backends.into_iter(), user_pin)
            .expect_err("construction against an absent card should fail");

        assert!(matches!(err, YubiError::CardNotFound(_)));
    }

    #[test]
    fn card_absent_is_mapped_to_card_not_found_during_sign() {
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> =
            vec![Ok(FakeCard::absent().into())];
        let user_pin = SecretString::from(pin::FACTORY_DEFAULT_USER_PIN);

        let err = YubiKeySigner::discover_and_sign(backends.into_iter(), &user_pin, b"message")
            .expect_err("signing against an absent card should fail");

        assert!(matches!(err, YubiError::CardNotFound(_)));
    }

    #[test]
    fn wrong_pin_during_signing_is_mapped_to_pin_incorrect() {
        let card = provisioned_card_from(FakeCard::new().with_changed_user_pin(b"000000"));
        let wrong_pin = SecretString::from("999999");

        let err = YubiKeySigner::sign_with_open_card(card, &wrong_pin, b"message")
            .expect_err("signing with the wrong PIN should fail");

        assert!(matches!(err, YubiError::PinIncorrect));
    }

    #[test]
    fn touch_timeout_during_signing_is_mapped_to_touch_timeout() {
        let card = provisioned_card_from(FakeCard::new().with_touch_timeout());
        let user_pin = SecretString::from(pin::FACTORY_DEFAULT_USER_PIN);

        let err = YubiKeySigner::sign_with_open_card(card, &user_pin, b"message")
            .expect_err("a simulated touch timeout should fail signing");

        assert!(matches!(err, YubiError::TouchTimeout));
    }

    #[test]
    fn blocked_user_pin_during_signing_is_labeled_as_the_user_pin_not_the_generic_fallback() {
        // Unit-tests `map_signing_pin_error` directly (rather than
        // exhausting 3 real retries through the full `sign` path, which
        // `sign_with_open_card`'s by-value `Card<Open>` makes awkward to
        // do across repeated calls -- each call gets a fresh fake card in
        // this test setup, matching the real "fresh discovery per call"
        // design) -- see this module's doc comment on `map_signing_pin_error`.
        let err = map_signing_pin_error(OpenpgpError::CardStatus(
            StatusBytes::AuthenticationMethodBlocked,
        ));

        match err {
            YubiError::PinBlocked {
                pin_kind,
                recovery_hint,
            } => {
                assert_eq!(pin_kind, "User");
                assert!(recovery_hint.contains("Admin PIN"));
                assert!(!recovery_hint.contains("cannot be recovered"));
            }
            other => {
                panic!("expected YubiError::PinBlocked{{pin_kind: \"User\", ..}}, got {other:?}")
            }
        }
    }

    #[test]
    fn smartcard_transport_error_during_signing_is_mapped_to_touch_timeout() {
        // Grounded in the real `pcsc`/`card-backend-pcsc` string shape a
        // genuine reader timeout produces -- see this module's doc
        // comment's "Grounding: detecting a touch timeout" section.
        let err = map_sign_error(OpenpgpError::Smartcard(SmartcardError::Error(
            "Transmit failed: Timeout".to_string(),
        )));

        assert!(matches!(err, YubiError::TouchTimeout));
    }
}
