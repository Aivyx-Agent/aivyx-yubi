//! On-card Ed25519 key generation and touch-policy configuration for the
//! Signature slot.
//!
//! # Grounding
//!
//! Both public functions here operate on an already Admin-PIN-verified
//! `Card<Admin>` — constructing that (`Card<Transaction>::as_admin_card`)
//! is `pin.rs`'s/the caller's job, not this module's; this module stays
//! scoped to what happens once admin access is established, per this
//! crate's design spec.
//!
//! `Card<Admin<'app,'open>>`'s `generate_key`/`set_touch_policy` are real,
//! live, public methods in `openpgp-card` 0.7.0
//! (`openpgp-card-0.7.0/src/lib.rs` ~1011-1132, confirmed directly against
//! the vendored source, matching `testing.rs`'s own grounding notes,
//! section 3) — this is *not* the tricky part of the API (that was
//! signing, a later task's problem).
//!
//! ## `generate_key`'s real signature
//! ```text
//! pub fn generate_key(
//!     &mut self,
//!     fp_from_pub: fn(&PublicKeyMaterial, KeyGenerationTime, KeyType) -> Result<Fingerprint, Error>,
//!     key_type: KeyType,
//! ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error>
//! ```
//! `PublicKeyMaterial` is an algorithm-tagged enum (`ocard/crypto.rs`):
//! `E(EccPub)` for elliptic-curve keys (`EccPub::data() -> &[u8]`, the raw
//! EC point, and `EccPub::algo() -> &AlgorithmAttributes`, the algorithm
//! actually used) or `R(RSAPub)` for RSA. [`generate_signature_key`] below
//! only ever expects `E(..)` whose algorithm attribute is actually
//! Ed25519/EdDSA (`EccAttributes::ecc_type()`/`curve()`, checked directly
//! — not inferred from "32 bytes", since a Cv25519/X25519 point is also
//! 32 bytes and would otherwise pass silently) and whose point is exactly
//! 32 bytes back — an `R(..)` result, a non-Ed25519 `E(..)`, or an `E(..)`
//! of the wrong length, means the card generated the wrong algorithm (see
//! the next point) and is reported as a [`YubiError::Other`] rather than
//! silently truncated or panicking.
//!
//! ## Real finding: the Signature slot does NOT default to Ed25519
//!
//! `generate_key` generates a key using whatever algorithm is *currently
//! configured* for the slot (`AlgorithmAttributes`, GET DATA tag `C1` for
//! Signing) — it does not itself choose Ed25519 just because that's what
//! this crate wants. A factory-fresh YubiKey's Signature slot defaults to
//! RSA2048, not Ed25519/EdDSA. [`testing.rs`'s fake][crate::testing]
//! mirrors this: it starts at RSA2048 for tag `C1` (same as real
//! hardware) and only reports Ed25519 once a real `PUT DATA` write to tag
//! `C1` — the same write `set_algorithm` below actually performs — has
//! landed (see its own doc comment, section 4). This means the fake's
//! tests below *do* catch a missing algorithm-configuration step: deleting
//! the `set_algorithm` call below makes the fake's `GENERATE ASYMMETRIC
//! KEY PAIR` handler answer with an RSA key instead, which the
//! `PublicKeyMaterial::R(_)` arm below rejects as a hard test failure.
//!
//! [`generate_signature_key`] therefore calls
//! `Card<Admin>::set_algorithm(KeyType::Signing, AlgoSimple::Curve25519)`
//! *before* `generate_key`, to make this crate correct against real
//! hardware and not just against its own fixture. `AlgoSimple::Curve25519`
//! (not a dedicated `Ed25519` variant — there isn't one) is confirmed
//! correct for the Signing slot specifically by reading
//! `ocard/algorithm.rs` directly: `AlgoSimple::ecc_type_25519`/
//! `curve_for_25519` both map `KeyType::Signing` (along with
//! `Authentication`/`Attestation`) to `EccType::EdDSA`/`Curve::Ed25519`,
//! while only `KeyType::Decryption` maps to the X25519/ECDH curve instead
//! — so this call cannot accidentally configure X25519 for the Signature
//! slot. `set_algorithm_attributes` (which `set_algorithm` wraps) silently
//! no-ops (`Ok(())`, no error) if the card's Extended Capabilities report
//! `algo_attrs_changeable() == false` (`ocard/mod.rs`, confirmed by
//! reading it directly) rather than failing loudly — the follow-up
//! algorithm check on `generate_key`'s actual result (previous paragraph)
//! is what catches that case too, since a card that can't change its
//! algorithm and wasn't already Ed25519-configured would still generate
//! (and get rejected for generating) an RSA key.
//!
//! ## `fp_from_pub`: not a real OpenPGP v4 fingerprint, and that's fine
//!
//! `generate_key`'s `fp_from_pub` callback computes the [`Fingerprint`]
//! the card stores on-card (GET DATA tag `C5`) alongside the new key —
//! see `key_slot_fingerprint`'s own doc comment (a private function — see
//! this file's own source, not doc-linkable) for why this crate uses
//! a simple, explicitly-non-spec-compliant placeholder rather than a real
//! RFC 4880 §12.2 fingerprint.
//!
//! ## `set_touch_policy`'s real signature
//! ```text
//! pub fn set_touch_policy(&mut self, key: KeyType, policy: TouchPolicy) -> Result<(), Error>
//! ```
//! `TouchPolicy` (`ocard/data.rs`) has variants `Off`/`On`/`Fixed`/
//! `Cached`/`CachedFixed`/`Unknown(u8)`. This crate's design spec's Global
//! Constraints call for **fixed/always-on** specifically —
//! [`set_signature_touch_policy_fixed`] passes `TouchPolicy::Fixed`, not
//! `On` (a real, meaningful difference: `On` still permits a later
//! `set_touch_policy` call to relax it back to `Off`/`On`; `Fixed`
//! doesn't — matching the design spec's "one-time card setting" framing).
//!
//! ## Admin-auth gating, and a `testing.rs` gap this task closes
//!
//! Both `generate_key` and `set_touch_policy` require the Admin PIN (PW3)
//! verified first on a real card (`GENERATE ASYMMETRIC KEY PAIR` directly;
//! `set_touch_policy`'s actual card-write is a `PUT DATA`, and *all* admin
//! `PUT DATA` writes are PW3-gated on a real card, not just this one).
//! [`testing.rs`'s fake][crate::testing] already gated `GENERATE
//! ASYMMETRIC KEY PAIR` on `verified_pw3_admin` (Task 3's review), but
//! left every `PUT DATA` unconditionally acknowledged — a known gap
//! Task 3's review flagged and left for whichever later task needed it.
//! This task needed it, to write a meaningful
//! "touch-policy-without-admin-auth" test below, so it's fixed as part of
//! this task: see `testing.rs`'s `ins::PUT_DATA` arm.
//!
//! Both failure-path tests below construct an unauthenticated
//! `Card<Admin>` via `Card<Transaction>::as_admin_card(None::<SecretString>)`
//! — confirmed against the real source (`lib.rs`'s `as_admin_card`/
//! `OptionalPin`) that passing `None` skips `verify_admin_pin` entirely
//! and still returns `Ok(Card<Admin>)`, i.e. the typestate alone does
//! *not* guarantee PW3 was actually verified; only the card's own
//! `6982`-on-write response does. Both real-card `6982` responses are
//! mapped by `map_admin_op_error` (a private function — see this file's
//! own source, not doc-linkable) to [`YubiError::AdminAuthRequired`]
//! rather than the generic [`YubiError::Other`] fallback.

use openpgp_card::{
    Card, Error as OpenpgpError,
    ocard::{
        KeyType, StatusBytes,
        algorithm::{AlgoSimple, AlgorithmAttributes, Curve},
        crypto::{EccType, PublicKeyMaterial},
        data::{Fingerprint, KeyGenerationTime, TouchPolicy},
    },
    state::Admin,
};

use crate::YubiError;

/// The raw 32-byte Ed25519 public key point a successful
/// [`generate_signature_key`] returns. A thin newtype (rather than a bare
/// `[u8; 32]`) so a caller can't confuse this with some other 32-byte
/// value (a PIN, a fingerprint prefix, ...) at a glance. The inner byte
/// array is private (construct via [`PublicKeyBytes::new`]) — a `pub`
/// field would let anyone build one from arbitrary bytes via a plain
/// tuple-struct literal, undercutting that same rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    /// Construct a `PublicKeyBytes` from a raw 32-byte Ed25519 public key
    /// point.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<PublicKeyBytes> for [u8; 32] {
    fn from(key: PublicKeyBytes) -> Self {
        key.0
    }
}

/// Generate a fresh Ed25519 keypair on-card in the Signature slot,
/// returning its raw 32-byte public key point.
///
/// `admin` must already be Admin-PIN-verified (PW3) — see this module's
/// doc comment. On success, the card holds a new private key it never
/// exposes; only the public key is returned.
///
/// Configures the Signature slot's algorithm to Ed25519/EdDSA
/// (`AlgoSimple::Curve25519`) before generating, since a factory-default
/// card's Signature slot is RSA2048, not Ed25519 — see this module's doc
/// comment for the real-API finding behind this.
///
/// # This is destructive if the slot already holds a key
///
/// `set_algorithm`'s underlying `PUT DATA` write resets the Signature
/// slot on real hardware, and `generate_key` overwrites whatever private
/// key currently occupies it — there is no card-side "don't clobber an
/// existing key" guard. Per this crate's design spec, provisioning is a
/// one-time operation performed against a freshly-reset or never-before-
/// provisioned card, so this is accepted rather than defended against in
/// code. Callers (including the CLI provisioning flow) must not call this
/// idempotently or accidentally against a card that already has a
/// Signature-slot key they care about — doing so silently destroys it.
pub fn generate_signature_key(
    admin: &mut Card<Admin<'_, '_>>,
) -> Result<PublicKeyBytes, YubiError> {
    admin
        .set_algorithm(KeyType::Signing, AlgoSimple::Curve25519)
        .map_err(map_admin_op_error)?;

    let (pub_key, _generated_at) = admin
        .generate_key(key_slot_fingerprint, KeyType::Signing)
        .map_err(map_admin_op_error)?;

    match pub_key {
        PublicKeyMaterial::E(ecc) => {
            // A 32-byte point alone doesn't prove Ed25519 -- Cv25519/X25519
            // points are also 32 bytes (this matters specifically for the
            // "card pre-set to a 25519 curve where `set_algorithm` silently
            // no-ops" scenario this module's doc comment describes: that
            // could leave the Signature slot on X25519, and a bare length
            // check wouldn't notice). Check the actual curve/type the card
            // reports instead.
            let is_ed25519 = matches!(
                ecc.algo(),
                AlgorithmAttributes::Ecc(attrs)
                    if attrs.ecc_type() == EccType::EdDSA && *attrs.curve() == Curve::Ed25519
            );
            if !is_ed25519 {
                return Err(YubiError::Other(format!(
                    "card generated a {:?} key in the Signature slot instead of Ed25519/EdDSA \
                     -- this card's Signature slot algorithm attribute may not be changeable to \
                     Curve25519",
                    ecc.algo()
                )));
            }
            let bytes: [u8; 32] = ecc.data().try_into().map_err(|_| {
                YubiError::Other(format!(
                    "card returned a {}-byte public key point for the Signature slot, expected \
                     exactly 32 (Ed25519)",
                    ecc.data().len()
                ))
            })?;
            Ok(PublicKeyBytes::new(bytes))
        }
        PublicKeyMaterial::R(_) => Err(YubiError::Other(
            "card generated an RSA key in the Signature slot instead of Ed25519/EdDSA -- this \
             card's Signature slot algorithm attribute may not be changeable to Curve25519"
                .to_string(),
        )),
    }
}

/// Set the Signature slot's touch-policy to fixed/always-on: every
/// `PSO: COMPUTE DIGITAL SIGNATURE` from now on requires a physical touch
/// confirmation, with no PIN-only/cached mode. This crate's design spec
/// (Global Constraints) treats this as a one-time provisioning setting,
/// not re-asserted per signature — see this module's doc comment for why
/// `TouchPolicy::Fixed` (not `On`) is what makes it stick.
///
/// `admin` must already be Admin-PIN-verified (PW3) — see this module's
/// doc comment.
pub fn set_signature_touch_policy_fixed(admin: &mut Card<Admin<'_, '_>>) -> Result<(), YubiError> {
    admin
        .set_touch_policy(KeyType::Signing, TouchPolicy::Fixed)
        .map_err(map_admin_op_error)
}

/// The [`Fingerprint`] [`generate_signature_key`] tells the card to store
/// (GET DATA tag `C5`) alongside a newly-generated key.
///
/// **Not** a real OpenPGP v4 fingerprint (RFC 4880 §12.2's SHA-1 over a
/// constructed public-key packet, which needs the key's *exact* creation
/// timestamp baked in bit-for-bit and a `sha1` dependency this crate has
/// no other use for). `aivyx-yubi` never builds or exports actual OpenPGP
/// certificates — it only uses the OpenPGP card applet as a raw
/// hardware Ed25519 signer for `aivyx-federation`'s `Identity` (see the
/// design spec) — and this value is on-card bookkeeping only: nothing in
/// this crate reads it back or relies on it being spec-correct. It's
/// derived deterministically from the public key's own raw bytes (the
/// first 20, zero-padded if shorter) purely so distinct keys get visibly
/// distinct on-card fingerprints, which is the only property that
/// matters here.
fn key_slot_fingerprint(
    pub_key: &PublicKeyMaterial,
    _generated_at: KeyGenerationTime,
    _key_type: KeyType,
) -> Result<Fingerprint, OpenpgpError> {
    let raw: &[u8] = match pub_key {
        PublicKeyMaterial::E(ecc) => ecc.data(),
        PublicKeyMaterial::R(rsa) => rsa.n(),
    };
    let mut bytes = [0u8; 20];
    let n = raw.len().min(20);
    bytes[..n].copy_from_slice(&raw[..n]);
    Ok(Fingerprint::from(bytes))
}

/// Map an admin-gated card operation's error to this crate's
/// [`YubiError`], upgrading the real `6982 SecurityStatusNotSatisfied`
/// status word to the specific, actionable
/// [`YubiError::AdminAuthRequired`] instead of letting it fall through to
/// the generic [`YubiError::Other`] catch-all — see this module's doc
/// comment.
fn map_admin_op_error(err: OpenpgpError) -> YubiError {
    match err {
        OpenpgpError::CardStatus(StatusBytes::SecurityStatusNotSatisfied) => {
            YubiError::AdminAuthRequired
        }
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use openpgp_card::ocard::data::TouchPolicy as RealTouchPolicy;
    use secrecy::SecretString;

    use super::*;
    use crate::{pin, testing::FakeCard};

    /// Build an Admin-PIN-verified `Card<Admin>` against a fresh
    /// [`FakeCard`], for the success-path tests below.
    fn admin_authenticated_card() -> Card<openpgp_card::state::Open> {
        Card::new(FakeCard::new()).expect("Card::new should SELECT + read ART")
    }

    #[test]
    fn generates_an_ed25519_key_on_the_signature_slot() {
        let mut card = admin_authenticated_card();
        let mut tx = card.transaction().unwrap();
        let admin_pin = SecretString::from(pin::FACTORY_DEFAULT_ADMIN_PIN);
        let mut admin = tx.as_admin_card(admin_pin).unwrap();

        let pub_key = generate_signature_key(&mut admin)
            .expect("key generation should succeed against the fake");

        assert_eq!(<[u8; 32]>::from(pub_key), FakeCard::fake_public_key());
        assert_eq!(pub_key, PublicKeyBytes::new(FakeCard::fake_public_key()));
    }

    #[test]
    fn generating_a_key_without_admin_auth_is_rejected() {
        let mut card = admin_authenticated_card();
        let mut tx = card.transaction().unwrap();
        // `None` skips `verify_admin_pin` entirely -- see this module's
        // doc comment: the typestate alone doesn't guarantee PW3 was
        // verified.
        let mut admin = tx.as_admin_card(None::<SecretString>).unwrap();

        let err = generate_signature_key(&mut admin)
            .expect_err("key generation without a verified admin PIN should be rejected");

        assert!(matches!(err, YubiError::AdminAuthRequired));
    }

    #[test]
    fn sets_the_signature_touch_policy_to_fixed() {
        let mut card = admin_authenticated_card();
        let mut tx = card.transaction().unwrap();
        let admin_pin = SecretString::from(pin::FACTORY_DEFAULT_ADMIN_PIN);
        let mut admin = tx.as_admin_card(admin_pin).unwrap();

        set_signature_touch_policy_fixed(&mut admin)
            .expect("touch policy should be settable against the fake");

        // `admin` borrows `tx` mutably; it's not used again, so NLL ends
        // that borrow here and `tx` is free to reuse below (same pattern
        // as `testing.rs`'s own smoke test).
        let flag = tx
            .user_interaction_flag(KeyType::Signing)
            .expect("re-reading the UIF after invalidating the ART cache should succeed")
            .expect("the fake always reports a UIF for the Signing slot");
        assert_eq!(flag.touch_policy(), RealTouchPolicy::Fixed);
    }

    #[test]
    fn setting_touch_policy_without_admin_auth_is_rejected() {
        let mut card = admin_authenticated_card();
        let mut tx = card.transaction().unwrap();
        let mut admin = tx.as_admin_card(None::<SecretString>).unwrap();

        let err = set_signature_touch_policy_fixed(&mut admin)
            .expect_err("setting touch policy without a verified admin PIN should be rejected");

        assert!(matches!(err, YubiError::AdminAuthRequired));
    }
}
