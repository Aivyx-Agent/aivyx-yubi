//! A fake `CardBackend`/`CardTransaction` test double standing in for real
//! YubiKey hardware (none exists in this environment). Every test in this
//! crate drives an OpenPGP-card-shaped interaction through this fake rather
//! than through `pcscd` + real hardware.
//!
//! # Grounding notes (Task 2)
//!
//! This module's shape is grounded directly in the *vendored source* of
//! `openpgp-card` 0.7.0 and its dependency `card-backend` 0.2.0, read from
//! `~/.cargo/registry/src/index.crates.io-*/openpgp-card-0.7.0/` and
//! `.../card-backend-0.2.0/` (docs.rs does not expose full method
//! signatures for this crate, per the plan's Task 1/2 split). Key findings:
//!
//! ## 1. `CardBackend`/`CardTransaction` are NOT `openpgp_card::card_backend::*`
//!
//! The design spec/brief assumed a module path like
//! `openpgp_card::card_backend::CardBackend`. That module doesn't exist.
//! `CardBackend` and `CardTransaction` are defined in a **separate crate**,
//! `card-backend` 0.2.0 (`card-backend-0.2.0/src/lib.rs`), which
//! `openpgp-card` depends on (`use card_backend::{CardBackend,
//! SmartcardError};` in `openpgp-card-0.7.0/src/lib.rs`) but does **not**
//! re-export. `card-backend-pcsc` (the real hardware backend this crate
//! also depends on) implements these same traits, imported the same way
//! (`card-backend-pcsc-0.5.2/src/lib.rs`: `use card_backend::{CardBackend,
//! CardCaps, CardTransaction, PinType, SmartcardError};`). Consequence:
//! this crate needed its own direct `card-backend = "0.2"` dependency
//! (added to `Cargo.toml`) to implement these traits at all — the brief's
//! assumed re-export path would not have compiled.
//!
//! Real trait shapes (`card-backend-0.2.0/src/lib.rs`):
//! ```text
//! pub trait CardBackend {
//!     fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps;
//!     fn transaction(&mut self, reselect_application: Option<&[u8]>)
//!         -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError>;
//! }
//! pub trait CardTransaction {
//!     fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError>;
//!     fn select(&mut self, application: &[u8]) -> Result<Vec<u8>, SmartcardError> { .. } // has a default impl
//!     fn max_cmd_len(&self) -> Option<usize> { None }                                    // has a default impl
//!     fn feature_pinpad_verify(&self) -> bool;
//!     fn feature_pinpad_modify(&self) -> bool;
//!     fn pinpad_verify(&mut self, pin: PinType, card_caps: &Option<CardCaps>) -> Result<Vec<u8>, SmartcardError>;
//!     fn pinpad_modify(&mut self, pin: PinType, card_caps: &Option<CardCaps>) -> Result<Vec<u8>, SmartcardError>;
//!     fn was_reset(&self) -> bool;
//! }
//! ```
//! `openpgp_card::Card::new<B>(backend: B) where B: Into<Box<dyn CardBackend
//! + Send + Sync>>` — there is no blanket `From<T> for Box<dyn Trait>` in
//! std, so (matching `card-backend-pcsc`'s own `impl From<PcscBackend> for
//! Box<dyn CardBackend + Sync + Send>`) [`FakeCard`] below needs the same
//! explicit `From` impl.
//!
//! ## 2. The real typestate chain (`openpgp-card-0.7.0/src/state.rs` + `src/lib.rs`)
//!
//! `Card<S: State>` transitions: `Open` → (`.transaction()`) → `Transaction<'a>`
//! → (`.as_user_card(pin)` / `.as_signing_card(pin)` / `.as_admin_card(pin)`,
//! each optionally PIN-verifying) → `User<'app,'open>` / `Sign<'app,'open>` /
//! `Admin<'app,'open>`. All five state markers (`Open`, `Transaction`,
//! `User`, `Sign`, `Admin`) are real, confirmed 1:1 against `state.rs`. PIN
//! verification itself (`verify_user_pin`, `verify_user_signing_pin`,
//! `verify_admin_pin`, and their `*_pinpad` siblings) lives on
//! `Card<Transaction>` directly (`lib.rs` lines ~213-288), not on the
//! post-transition states — `as_*_card` is a thin convenience wrapper that
//! calls the matching `verify_*` method before constructing the typed view.
//!
//! ## 3. Surprise: `Card<Sign>` has no public signing method in 0.7.0
//!
//! This is the one place the real API meaningfully diverges from what a
//! reasonable reading of the typestate pattern would suggest, and it
//! matters for Task 4/5's real signing code. `impl Card<Sign<'app,'open>>`
//! (`lib.rs` ~820-872) has exactly one live public method,
//! `generate_attestation` (a Yubico extra) — its `signer()` /
//! `signer_from_public()` methods, which would have returned something
//! capable of actually computing a PGP signature, are commented out in the
//! vendored source itself with `// FIXME`, and its `card()` helper that
//! would let a caller reach the low-level transaction is private
//! (`fn card(&mut self)`, no `pub`). So constructing a `Card<Sign>` only
//! gets you PIN-verification-for-signing gating and attestation — **not**
//! a way to sign.
//!
//! The real, live seam for signing is one layer down, on
//! `Card<Transaction>` itself, which *is* public:
//! - `Card<Transaction>::verify_user_signing_pin(pin)` — verifies PW1 in
//!   signing mode (this is the same call `as_signing_card(pin)` makes
//!   internally; you don't need the `Sign` state at all).
//! - `Card<Transaction>::card()` (`lib.rs` line 190, `pub fn card(&mut
//!   self) -> &mut crate::ocard::Transaction<'a>`, explicitly flagged `//
//!   FIXME: remove later?` in the source but present and public in 0.7.0)
//!   — the escape hatch to the low-level `ocard::Transaction`, which has
//!   the real `pso_compute_digital_signature(data: Vec<u8>)` and
//!   `signature_for_hash(algo: SigningAlgo, digest: &[u8])` methods
//!   (`ocard/mod.rs` ~1042-1066).
//!
//! `generate_key`/`set_touch_policy`, by contrast, genuinely are live and
//! public on `Card<Admin>` (`lib.rs` ~1011-1132) exactly as the brief
//! assumed — only the signing path needed correcting.
//!
//! The smoke test below (`tests::smoke_full_lifecycle`) exercises both the
//! `Admin` path (key generation + touch policy) and this `Transaction`-level
//! signing path end to end against [`FakeCard`], so later tasks have a
//! working, compiling reference for the real call shape.
//!
//! ## 4. Real APDU/TLV grounding used to build [`FakeCard`]'s responses
//!
//! `FakeCard` answers at the raw APDU `transmit()` level (`CLA INS P1 P2
//! [Lc data] [Le]`, matched on `INS`/`P1`/`P2` — see `ocard/commands.rs`
//! and `ocard/apdu/command.rs` for the real command bytes and wire format,
//! and `ocard/mod.rs`'s `StatusBytes` `From<(u8,u8)>` impl for the real
//! status-word mapping used for failure responses below).
//!
//! Every command this fake receives today happens to be short-form
//! (`Lc`/`Le` are single bytes) — but *not* because this fake never
//! advertises extended-length support. It does: the Historical Bytes
//! fixture below (tag `5F52`) sets `CardCapabilities` byte 3 bit 6
//! (`extended_lc_le`), and `openpgp-card` reads that straight into
//! `CardCaps.ext_support = true` (`OpenPGP::new`, `ocard/mod.rs`:
//! `ext_support = cc.extended_lc_le()`). What actually keeps commands
//! short-form is that `openpgp-card` only switches to extended `Lc`/`Le`
//! when *both* `ext_support` is true *and* `max_cmd_bytes > 0xFF`
//! (`ocard/apdu.rs`: `let ext_len = ext_support && (max_cmd_bytes >
//! 0xFF);`) — and this fake's effective `max_cmd_bytes` falls back to the
//! default `255`, because it omits the Extended Length Information DO
//! (tag `7F66`) and `ExtendedCapabilities`'s `max_cmd_len`/`max_resp_len`
//! fields are only populated for card version 2.x
//! (`ocard/data/extended_cap.rs`), while this fixture claims version 3.4.
//!
//! **This is fragile**: if a later change adds tag `7F66` to
//! [`build_application_related_data`] "for realism", `max_cmd_bytes` will
//! exceed 255, `ext_len` flips true, `Lc` becomes the 3-byte extended
//! form, and this fake's current short-form-only command parsing (the
//! `lc`/`cmd.get` line in [`CardTransaction::transmit`]'s `VERIFY` arm)
//! will silently misparse every subsequent command (e.g. treating every
//! PIN as empty) instead of failing loudly. Anyone adding that DO must
//! also add extended-length command parsing here.
//!
//! The fake's "Application Related Data" (GET DATA tag `6E`, returned on
//! `SELECT` + subsequent reads) is a hand-built, spec-correct TLV rather
//! than a hardcoded blob, but its *shape* (which DOs a real YubiKey 5
//! actually returns, and their byte layout) is grounded in a genuine
//! YubiKey 5 NFC fixture baked into `openpgp-card`'s own test suite
//! (`ocard/tlv.rs`, `test_tlv_yubi5`) and in `ocard/data/extended_cap.rs`'s
//! `test_yk5`. AID manufacturer id `0x0006` ("Yubico AB") and version
//! `0x0304` (card spec v3.4) are taken from that real fixture; the
//! Algorithm Attributes for the Signature slot are deliberately set to
//! EdDSA/Ed25519 (`ocard/algorithm.rs`'s `ecc_algo_attrs`: algo id `0x16` +
//! `ocard/oid.rs`'s `ED25519` OID bytes) rather than the fixture's original
//! RSA, since Ed25519-only signing is this crate's actual design target.
//!
//! ## 5. Design choices that are *not* real protocol, and are fake-only
//!
//! - **"PIN is still factory default" vs "changed"**: the OpenPGP card
//!   protocol does not expose this as a queryable fact — `PWStatusBytes`
//!   carries retry *counts*, not a default/changed flag. Real client
//!   software (and [`FakeCard`]'s own [`FakeCard::is_default_pins`] helper,
//!   which is fake-only, not a real card API) infers it by attempting
//!   `VERIFY` with the well-known factory defaults, which `openpgp-card`
//!   itself documents in `ocard/data.rs`: `PW1_INITIAL = "123456"`,
//!   `PW3_INITIAL = "12345678"`. [`FakeCard::new`] defaults to exactly
//!   these two strings as its current PW1/PW3 values;
//!   [`FakeCard::with_changed_user_pin`]/[`FakeCard::with_changed_admin_pin`]
//!   simulate a PIN change by overwriting them.
//! - **Retry counters in the cached ART are static**, not synced with the
//!   fake's own live VERIFY retry tracking. A test that verifies with a
//!   wrong PIN twice and then reads `pw_status_bytes()` will still see the
//!   fixture's fixed `err_count_pw1 = 3`. Tests that care about retries
//!   remaining should assert on the real status word `openpgp-card` surfaces
//!   from the failed `VERIFY` itself (`StatusBytes::PasswordNotChecked(n)`,
//!   real enum, real mapping — see point 4), not on `pw_status_bytes()`.
//! - **Touch timeout** is modeled as a *transport*-level failure (`Err(
//!   SmartcardError::Error(..))` from `transmit()`), not a card status
//!   word. This matches reality: a PC/SC reader that times out waiting for
//!   a physical touch fails the transmit itself; the OpenPGP card never
//!   gets to send a status word at all.
//! - **Card absent/unreachable** is modeled at `CardBackend::transaction()`
//!   (`Err(SmartcardError::CardNotFound(..))`), matching where
//!   `card-backend-pcsc` itself would surface that failure (see
//!   `card-backend-pcsc-0.5.2/src/lib.rs`'s `from_pcsc_reader`).
//! - **PIN-verification session state IS enforced**, unlike the above
//!   fake-only conveniences: [`FakeCard`] tracks `verified_pw1_sign`/
//!   `verified_pw3_admin` and rejects `PSO: COMPUTE DIGITAL SIGNATURE` /
//!   `GENERATE ASYMMETRIC KEY PAIR` with the real `6982
//!   SecurityStatusNotSatisfied` status word (`ocard/mod.rs`'s
//!   `StatusBytes::SecurityStatusNotSatisfied`, mapped from `(0x69,
//!   0x82)`) if the matching `VERIFY` hasn't succeeded first — so a real
//!   bug in a later task that forgets to verify the PIN before signing
//!   or generating a key fails its test against this fake instead of
//!   silently passing. Both flags reset to `false` on every fresh
//!   `CardBackend::transaction()` call, an approximation of a real card's
//!   behavior (which actually keeps PIN-verified state until a card
//!   reset/power-cycle, not per logical PC/SC transaction) chosen because
//!   `transaction()` is the only session boundary the `CardBackend` trait
//!   itself exposes.
//! - **[`FakeCard::is_default_pins`]/[`FakeCard::signing_key_generated`]
//!   are unreachable once the fake is boxed**: `Card::new(fake_card)`
//!   moves the fake into an opaque `Box<dyn CardBackend + Send + Sync>`
//!   with no handle retained, so nothing can call these `&self` inspection
//!   methods again afterwards. A caller that needs to inspect fake state
//!   post-construction currently has no way to; wrapping the mutable
//!   state in `Arc<Mutex<..>>` internally (so a cheap clone of the shared
//!   handle could be retained before the move) would fix this, but is
//!   left as a known limitation for a later task to pick up if it turns
//!   out to be needed, rather than speculatively adding now.

use card_backend::{
    CardBackend, CardCaps, CardTransaction, PinType as BackendPinType, SmartcardError,
};

// ---------------------------------------------------------------------
// Real APDU constants, grounded in `openpgp-card-0.7.0/src/ocard/commands.rs`
// and `.../src/ocard/tags.rs`.
// ---------------------------------------------------------------------

mod ins {
    pub(super) const SELECT: u8 = 0xA4;
    pub(super) const GET_DATA: u8 = 0xCA;
    pub(super) const VERIFY: u8 = 0x20;
    pub(super) const PUT_DATA: u8 = 0xDA;
    pub(super) const PSO: u8 = 0x2A;
    pub(super) const GENERATE_ASYMMETRIC_KEY_PAIR: u8 = 0x47;
}

/// GET DATA tag for "Application Related Data" (`ocard/tags.rs`: `[0x6e]`).
const TAG_APPLICATION_RELATED_DATA: (u8, u8) = (0x00, 0x6e);

/// PSO P1/P2 for "COMPUTE DIGITAL SIGNATURE" (`ocard/commands.rs::signature`).
const PSO_COMPUTE_DIGITAL_SIGNATURE: (u8, u8) = (0x9e, 0x9a);

/// VERIFY P2 values (`card_backend::PinType::id()`, mirrored in
/// `ocard/commands.rs::verify_pw1_81/verify_pw1_82/verify_pw3`).
const VERIFY_P2_SIGN: u8 = 0x81;
const VERIFY_P2_USER: u8 = 0x82;
const VERIFY_P2_ADMIN: u8 = 0x83;

/// Well-known OpenPGP card factory-default PINs, taken verbatim from
/// `openpgp-card-0.7.0/src/ocard/data.rs`'s `KdfDo::iter_salted`
/// (`PW1_INITIAL`/`PW3_INITIAL` constants).
pub const FACTORY_DEFAULT_USER_PIN: &[u8] = b"123456";
pub const FACTORY_DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

/// A fabricated 32-byte Ed25519 public key point, returned by a successful
/// `GENERATE ASYMMETRIC KEY PAIR`. Not a real curve point — just a fixed,
/// recognizable byte pattern later tasks' tests can assert equality
/// against.
const FAKE_ED25519_PUBLIC_KEY: [u8; 32] = [0xAB; 32];

/// A fabricated Ed25519 signature (64 bytes, the real signature length),
/// returned by a successful `PSO: COMPUTE DIGITAL SIGNATURE`.
const FAKE_ED25519_SIGNATURE: [u8; 64] = [0xCD; 64];

/// Encode a BER-TLV length field, per `ocard/tlv/length.rs::tlv_encode_length`.
fn tlv_len(len: usize) -> Vec<u8> {
    let len = len as u16;
    if len > 255 {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else if len > 127 {
        vec![0x81, len as u8]
    } else {
        vec![len as u8]
    }
}

/// Build one self-describing TLV: `tag ++ length ++ value`.
fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 3 + value.len());
    out.extend_from_slice(tag);
    out.extend(tlv_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// Append a success status word (`90 00`, `StatusBytes::Ok`).
fn ok(mut data: Vec<u8>) -> Vec<u8> {
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

/// Build a fabricated "Application Related Data" GET DATA(6E) response
/// value (i.e. the concatenated child DOs, *without* an outer `6E` TLV
/// wrapper — real cards don't include one either: `GET DATA` for tag `6E`
/// returns the tag's *value*, confirmed against
/// `ocard/mod.rs::Transaction::application_related_data`, which parses the
/// raw response bytes directly as `Value::parse(data, constructed = true)`,
/// i.e. a flat list of child TLVs).
///
/// `Tlv::find` (the real crate's lookup) recurses into nested constructed
/// values regardless of depth, so this fake doesn't bother nesting DOs
/// inside the real card's `73` "Discretionary Data Objects" wrapper — a
/// flat list of the same tags is indistinguishable to any caller that only
/// ever looks things up by tag.
fn build_application_related_data(manufacturer: u16, serial: u32, uif_sig: [u8; 2]) -> Vec<u8> {
    // Application Identifier (tag 4F). Layout grounded in
    // `ocard/data/application_id.rs::parse`: `d2 76 00 01 24` fixed prefix,
    // 1-byte application id, be_u16 version, be_u16 manufacturer, be_u32
    // serial, trailing `00 00`.
    let mut aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    aid.extend_from_slice(&0x0304u16.to_be_bytes()); // card spec v3.4
    aid.extend_from_slice(&manufacturer.to_be_bytes());
    aid.extend_from_slice(&serial.to_be_bytes());
    aid.extend_from_slice(&[0x00, 0x00]);

    // Extended Capabilities (tag C0). Exact bytes from a real YubiKey 5's
    // output, `ocard/data/extended_cap.rs::test_yk5`.
    let ext_caps = [0x7d, 0x00, 0x0b, 0xfe, 0x08, 0x00, 0x00, 0xff, 0x00, 0x00];

    // Algorithm Attributes, Signature slot (tag C1): EdDSA (algo id 0x16,
    // `ocard/algorithm.rs::ecc_algo_attrs`) + the real Ed25519 OID bytes
    // from `ocard/oid.rs::ED25519`.
    let mut algo_sig = vec![0x16];
    algo_sig.extend_from_slice(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]);

    // Algorithm Attributes, Decryption/Authentication slots (C2/C3): left
    // as RSA 2048 (real fixture bytes) — this crate doesn't touch these
    // slots, but a well-formed card has *some* algorithm set for them.
    let algo_other = [0x01, 0x08, 0x00, 0x00, 0x11, 0x00];

    // PW Status Bytes (tag C4, must be exactly 7 bytes per
    // `ocard/data/pw_status.rs`). Real YubiKey 5 fixture values: PW1 not
    // "valid once", max lengths 127/127/127, 3 retries each.
    let pw_status = [0xff, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03];

    // Fingerprints (tag C5) and generation times (tag CD): all-zero, i.e.
    // "no key in this slot yet" (`ocard/data/fingerprint.rs`,
    // `ocard/data/key_generation_times.rs`: an all-zero fingerprint/time
    // parses as `None`).
    let fingerprints = [0u8; 60];
    let gen_times = [0u8; 12];

    // Key Information (tag DE): sig/dec/auth key refs 1/2/3, all
    // `KeyStatus::NotPresent` (`ocard/data.rs::KeyInformation`).
    let key_info = [0x01, 0x00, 0x02, 0x00, 0x03, 0x00];

    // Historical Bytes (tag 5F52). Real YubiKey 5 fixture bytes from
    // `ocard/data/historical.rs::test_yk5`. Required, not optional — but
    // note there are actually *two* distinct `historical_bytes` methods
    // in the real crate, easy to conflate:
    //   1. `ocard::data::ApplicationRelatedData::historical_bytes()
    //      -> Result<HistoricalBytes, Error>` (`ocard/data.rs`), which
    //      errors with `Error::NotFound` if the DO is absent, and which
    //      `OpenPGP::new` calls with a bare `?`
    //      (`hb: Some(ard.historical_bytes()?)`, `ocard/mod.rs`) — so a
    //      card missing this DO fails construction entirely. Confirmed
    //      the hard way: this fake originally omitted it and every test
    //      failed with `NotFound("Failed to get historical bytes.")`.
    //   2. `ocard::Transaction::historical_bytes()
    //      -> Result<Option<HistoricalBytes>, Error>` (`ocard/mod.rs`),
    //      a separate, later, Option-typed accessor over the
    //      *already-cached* value. By the time anything can call this
    //      one, construction (and thus method 1's `?`) has already
    //      succeeded, so in practice it can never observe `None`.
    let historical_bytes = [0x00, 0x73, 0x00, 0x00, 0xe0, 0x05, 0x90, 0x00];

    let mut out = Vec::new();
    out.extend(tlv(&[0x4f], &aid));
    out.extend(tlv(&[0x5f, 0x52], &historical_bytes));
    out.extend(tlv(&[0xc0], &ext_caps));
    out.extend(tlv(&[0xc1], &algo_sig));
    out.extend(tlv(&[0xc2], &algo_other));
    out.extend(tlv(&[0xc3], &algo_other));
    out.extend(tlv(&[0xc4], &pw_status));
    out.extend(tlv(&[0xc5], &fingerprints));
    out.extend(tlv(&[0xcd], &gen_times));
    out.extend(tlv(&[0xde], &key_info));
    out.extend(tlv(&[0xd6], &uif_sig)); // UifSig ("touch policy" for signing)
    out.extend(tlv(&[0xd7], &[0x00, 0x20])); // UifDec
    out.extend(tlv(&[0xd8], &[0x00, 0x20])); // UifAuth
    out.extend(tlv(&[0xd9], &[0x00, 0x20])); // UifAttestation
    out
}

/// Build the response to `GENERATE ASYMMETRIC KEY PAIR` /
/// `GET PUBLIC KEY` (INS 0x47): a single TLV, tag `7F49` ("Public Key",
/// `ocard/tags.rs`), wrapping a nested `86` ("Public key - EC point",
/// `ocard/tags.rs::PublicKeyDataEccPoint`) with the fabricated raw point
/// bytes. Grounded in `ocard/keys.rs::tlv_to_pubkey`, which looks up tag
/// `86` specifically (RSA would instead need tags `81`/`82` present, `86`
/// absent).
fn build_generate_key_response() -> Vec<u8> {
    let point = tlv(&[0x86], &FAKE_ED25519_PUBLIC_KEY);
    tlv(&[0x7f, 0x49], &point)
}

/// One PIN's live state in a [`FakeCard`].
#[derive(Debug, Clone)]
struct PinSlot {
    current: Vec<u8>,
    retries_left: u8,
}

impl PinSlot {
    fn new(initial: &[u8]) -> Self {
        Self {
            current: initial.to_vec(),
            retries_left: 3,
        }
    }

    /// Returns the status word for a VERIFY attempt with `presented`.
    fn verify(&mut self, presented: &[u8]) -> [u8; 2] {
        if presented == self.current.as_slice() {
            self.retries_left = 3;
            [0x90, 0x00] // StatusBytes::Ok
        } else if self.retries_left < 1 {
            // Already at 0 retries (blocked): reject outright without
            // decrementing further. Using `< 1` (not `<= 1`) matters — a
            // real card lets all 3 wrong attempts decrement the counter
            // and report `PasswordNotChecked(2)`, `(1)`, `(0)` in turn;
            // it's only the *next* attempt, made with the counter already
            // at 0, that gets `AuthenticationMethodBlocked`. `<= 1` would
            // instead intercept the 3rd wrong attempt itself and block it
            // pre-emptively, one attempt early.
            self.retries_left = 0;
            [0x69, 0x83] // StatusBytes::AuthenticationMethodBlocked
        } else {
            self.retries_left -= 1;
            [0x63, 0xC0 | self.retries_left] // StatusBytes::PasswordNotChecked(n)
        }
    }
}

/// A fake OpenPGP card, standing in for real YubiKey hardware. Implements
/// [`card_backend::CardBackend`]; see this module's own doc comment for how
/// that trait was grounded and what its responses do and don't simulate.
///
/// Build one with [`FakeCard::new`] (a fresh, present card with
/// factory-default PINs and no generated keys), then hand it to
/// `openpgp_card::Card::new(fake_card)`.
pub struct FakeCard {
    present: bool,
    broken: bool,
    manufacturer: u16,
    serial: u32,
    pw1: PinSlot,
    pw3: PinSlot,
    uif_sig: [u8; 2],
    signing_key_generated: bool,
    touch_timeout: bool,
    /// PW1 (signing mode, VERIFY P2 `0x81`) has been successfully
    /// verified in the current session. Gates `PSO: COMPUTE DIGITAL
    /// SIGNATURE`. See this module's doc comment, section 5.
    verified_pw1_sign: bool,
    /// PW3 (admin, VERIFY P2 `0x83`) has been successfully verified in
    /// the current session. Gates `GENERATE ASYMMETRIC KEY PAIR`. See
    /// this module's doc comment, section 5.
    verified_pw3_admin: bool,
}

impl FakeCard {
    /// A present, freshly-initialized fake card: factory-default PINs
    /// (`123456`/`12345678`), no key generated yet, touch policy Off for
    /// signing, and a real Yubico manufacturer id with a fixed serial.
    pub fn new() -> Self {
        Self {
            present: true,
            broken: false,
            manufacturer: 0x0006, // "Yubico AB", per `ApplicationIdentifier::manufacturer_name`
            serial: 0x0011_2233,
            pw1: PinSlot::new(FACTORY_DEFAULT_USER_PIN),
            pw3: PinSlot::new(FACTORY_DEFAULT_ADMIN_PIN),
            uif_sig: [0x00, 0x20], // TouchPolicy::Off, Features::Button
            signing_key_generated: false,
            touch_timeout: false,
            verified_pw1_sign: false,
            verified_pw3_admin: false,
        }
    }

    /// Simulate a card that is absent/unreachable: `CardBackend::transaction`
    /// fails immediately, before any APDU is ever sent, matching where
    /// `card-backend-pcsc` itself surfaces "no card" (`SmartcardError::
    /// CardNotFound`, see this module's doc comment point 5).
    pub fn absent() -> Self {
        let mut card = Self::new();
        card.present = false;
        card
    }

    /// Simulate a card that's physically reachable (`CardBackend::
    /// transaction` succeeds, `SELECT` succeeds) but isn't a usable
    /// OpenPGP card — e.g. a wrong/non-OpenPGP applet, or a corrupted
    /// Application Related Data structure. `GET DATA` for tag `6E`
    /// (Application Related Data) fails with the real `6A88`
    /// `ReferencedDataNotFound` status word, so `openpgp_card::Card::new`
    /// fails *after* connecting — distinct from [`Self::absent`], which
    /// fails at `CardBackend::transaction` itself before any APDU is
    /// sent. Added to exercise `discovery::discover_card_from`'s
    /// "found-but-broken vs. truly absent" distinction.
    pub fn broken() -> Self {
        let mut card = Self::new();
        card.broken = true;
        card
    }

    /// Overwrite this card's current User PIN (PW1), simulating that the
    /// factory default has been changed. Fake-only setup helper — see this
    /// module's doc comment point 5 for why there's no real-protocol way to
    /// query "is this still the default".
    pub fn with_changed_user_pin(mut self, new_pin: &[u8]) -> Self {
        self.pw1 = PinSlot::new(new_pin);
        self
    }

    /// Overwrite this card's current Admin PIN (PW3). See
    /// [`Self::with_changed_user_pin`].
    pub fn with_changed_admin_pin(mut self, new_pin: &[u8]) -> Self {
        self.pw3 = PinSlot::new(new_pin);
        self
    }

    /// Simulate a reader that times out waiting for the touch confirmation
    /// a `PSO: COMPUTE DIGITAL SIGNATURE` needs: `transmit()` itself fails
    /// (see this module's doc comment point 5), rather than the card
    /// returning any status word.
    pub fn with_touch_timeout(mut self) -> Self {
        self.touch_timeout = true;
        self
    }

    /// Fake-only convenience: true if both PINs are still at their factory
    /// defaults. Not a real card API — see this module's doc comment point
    /// 5. Provided so tests can assert on fixture *intent* without also
    /// hardcoding the default PIN bytes at every call site.
    pub fn is_default_pins(&self) -> bool {
        self.pw1.current == FACTORY_DEFAULT_USER_PIN
            && self.pw3.current == FACTORY_DEFAULT_ADMIN_PIN
    }

    /// Fake-only accessor: has a signing key been generated on this fake
    /// card yet (i.e. did a `GENERATE ASYMMETRIC KEY PAIR` succeed)?
    pub fn signing_key_generated(&self) -> bool {
        self.signing_key_generated
    }

    /// The fabricated Ed25519 public key point a successful key generation
    /// returns. Exposed so tests can assert the value they got back from
    /// `openpgp-card` round-trips correctly, without hardcoding the pattern
    /// twice.
    pub fn fake_public_key() -> [u8; 32] {
        FAKE_ED25519_PUBLIC_KEY
    }

    /// The fabricated signature bytes a successful `PSO: COMPUTE DIGITAL
    /// SIGNATURE` returns. See [`Self::fake_public_key`].
    pub fn fake_signature() -> [u8; 64] {
        FAKE_ED25519_SIGNATURE
    }
}

impl Default for FakeCard {
    fn default() -> Self {
        Self::new()
    }
}

/// Boxing helper, mirroring `card-backend-pcsc`'s own `impl From<PcscBackend>
/// for Box<dyn CardBackend + Sync + Send>` (`card-backend-pcsc-0.5.2/src/
/// lib.rs`) — `openpgp_card::Card::new` requires `B: Into<Box<dyn
/// CardBackend + Send + Sync>>`, and there is no blanket impl for that in
/// std.
impl From<FakeCard> for Box<dyn CardBackend + Send + Sync> {
    fn from(card: FakeCard) -> Self {
        Box::new(card)
    }
}

impl CardBackend for FakeCard {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        card_caps
    }

    fn transaction(
        &mut self,
        _reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        if !self.present {
            return Err(SmartcardError::CardNotFound(
                "fake card is absent".to_string(),
            ));
        }
        // A fresh transaction is this fake's session boundary: PIN
        // verification doesn't carry over (see this module's doc
        // comment, section 5).
        self.verified_pw1_sign = false;
        self.verified_pw3_admin = false;
        Ok(Box::new(FakeCardTransaction { card: self }))
    }
}

/// The transaction handle [`FakeCard::transaction`] hands out. All actual
/// response fabrication happens in [`CardTransaction::transmit`] below.
struct FakeCardTransaction<'a> {
    card: &'a mut FakeCard,
}

impl CardTransaction for FakeCardTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        if cmd.len() < 4 {
            return Err(SmartcardError::Error(format!(
                "malformed APDU, too short: {cmd:02x?}"
            )));
        }
        let (ins, p1, p2) = (cmd[1], cmd[2], cmd[3]);

        match ins {
            ins::SELECT => Ok(ok(vec![])),

            ins::GET_DATA => {
                if (p1, p2) == TAG_APPLICATION_RELATED_DATA {
                    if self.card.broken {
                        // Simulate a card that connects but can't provide
                        // Application Related Data (wrong applet,
                        // corrupted state) — see `FakeCard::broken`.
                        return Ok(vec![0x6A, 0x88]); // StatusBytes::ReferencedDataNotFound
                    }
                    Ok(ok(build_application_related_data(
                        self.card.manufacturer,
                        self.card.serial,
                        self.card.uif_sig,
                    )))
                } else {
                    // StatusBytes::ReferencedDataNotFound — a real card's
                    // answer for a DO it doesn't have.
                    Ok(vec![0x6A, 0x88])
                }
            }

            ins::VERIFY => {
                if !matches!(p2, VERIFY_P2_SIGN | VERIFY_P2_USER | VERIFY_P2_ADMIN) {
                    return Ok(vec![0x6A, 0x86]); // StatusBytes: incorrect P1-P2 (unmapped in this fake)
                }

                if cmd.len() == 4 {
                    // Empty-data "check" form (`check_pw1_user` etc.): this
                    // fake doesn't track a persistent "already verified"
                    // session flag for *this* query form, so it always
                    // reports "not verified yet" here regardless of
                    // `verified_pw1_sign`/`verified_pw3_admin` below (which
                    // gate `PSO`/`GENERATE ASYMMETRIC KEY PAIR` instead).
                    let n = match p2 {
                        VERIFY_P2_SIGN | VERIFY_P2_USER => self.card.pw1.retries_left,
                        _ => self.card.pw3.retries_left,
                    };
                    return Ok(vec![0x63, 0xC0 | n]);
                }

                // Short-form Lc only (single byte). Safe *today* only
                // because this fake's effective `max_cmd_bytes` falls
                // back to 255 (no Extended Length Information DO, tag
                // `7F66`) — see this module's doc comment, section 4, for
                // why `CardCaps.ext_support` being true does NOT already
                // mean extended-length parsing is needed here, and why
                // adding that DO later would silently break this line
                // (e.g. treating every PIN as empty) instead of failing
                // loudly.
                let lc = cmd[4] as usize;
                let pin = cmd.get(5..5 + lc).unwrap_or(&[]);

                let status = match p2 {
                    VERIFY_P2_SIGN | VERIFY_P2_USER => self.card.pw1.verify(pin),
                    _ => self.card.pw3.verify(pin),
                };
                let verified = status == [0x90, 0x00];

                // Track session verification state for the security-gate
                // checks on `PSO`/`GENERATE ASYMMETRIC KEY PAIR` below. A
                // failed VERIFY explicitly un-verifies (matches real card
                // behavior: a wrong PIN invalidates any prior successful
                // verification for that key reference).
                match p2 {
                    VERIFY_P2_SIGN => self.card.verified_pw1_sign = verified,
                    VERIFY_P2_ADMIN => self.card.verified_pw3_admin = verified,
                    _ => {}
                }

                Ok(status.to_vec())
            }

            ins::GENERATE_ASYMMETRIC_KEY_PAIR => {
                // P1 0x80 = generate, 0x81 = read back the public key of a
                // previously generated key (`ocard/commands.rs::gen_key` /
                // `get_pub_key`). This fake always answers the Signing slot
                // — later tasks only ever generate that one slot.
                match p1 {
                    0x80 => {
                        if !self.card.verified_pw3_admin {
                            // StatusBytes::SecurityStatusNotSatisfied — a
                            // real card requires PW3 (admin) VERIFYed
                            // before key generation (I-1 finding).
                            return Ok(vec![0x69, 0x82]);
                        }
                        self.card.signing_key_generated = true;
                        Ok(ok(build_generate_key_response()))
                    }
                    0x81 if self.card.signing_key_generated => {
                        Ok(ok(build_generate_key_response()))
                    }
                    _ => Ok(vec![0x6A, 0x88]), // no key generated yet
                }
            }

            ins::PUT_DATA => {
                // Every PUT DATA this fake receives (touch policy, creation
                // time, fingerprint, ...) is unconditionally acknowledged.
                // Later tasks needing a PUT-DATA failure scenario should add
                // a dedicated `FakeCard` builder toggle rather than
                // overloading this generic path.
                if (p1, p2) == (0x00, 0xd6) {
                    // UifSig — remember it so a later `user_interaction_flag`
                    // read reflects the change.
                    if let Some(bytes) = cmd.get(5..)
                        && bytes.len() >= 2
                    {
                        self.card.uif_sig = [bytes[0], bytes[1]];
                    }
                }
                Ok(ok(vec![]))
            }

            ins::PSO if (p1, p2) == PSO_COMPUTE_DIGITAL_SIGNATURE => {
                if !self.card.verified_pw1_sign {
                    // StatusBytes::SecurityStatusNotSatisfied — a real
                    // card requires PW1 (signing mode) VERIFYed before
                    // PSO: COMPUTE DIGITAL SIGNATURE (I-1 finding).
                    return Ok(vec![0x69, 0x82]);
                }
                if self.card.touch_timeout {
                    return Err(SmartcardError::Error(
                        "reader timed out waiting for touch confirmation".to_string(),
                    ));
                }
                Ok(ok(FAKE_ED25519_SIGNATURE.to_vec()))
            }

            _ => Ok(vec![0x6D, 0x00]), // StatusBytes::INSNotSupported
        }
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: BackendPinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error("fake card has no pinpad".to_string()))
    }

    fn pinpad_modify(
        &mut self,
        _pin: BackendPinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error("fake card has no pinpad".to_string()))
    }

    fn was_reset(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use openpgp_card::{
        Card,
        ocard::{
            KeyType,
            crypto::{PublicKeyMaterial, SigningAlgo},
            data::{Fingerprint, KeyGenerationTime},
        },
    };

    use super::*;

    /// Drives a [`FakeCard`] through the real state-transition sequence
    /// grounded in this module's doc comment: `Open` → `Transaction` →
    /// `Admin` (key generation, touch policy) → back to `Transaction` for
    /// the actual signing call (since `Card<Sign>` itself, per grounding
    /// point 3, exposes no public way to sign in openpgp-card 0.7.0).
    #[test]
    fn smoke_full_lifecycle() {
        let fake = FakeCard::new();
        assert!(fake.is_default_pins());

        let mut card = Card::new(fake).expect("Card::new should SELECT + read ART");
        let mut tx = card.transaction().expect("transaction should start");

        // Discovery: the real AID round-trips through the fake.
        let aid = tx
            .application_identifier()
            .expect("application_identifier should read from the cached ART");
        assert_eq!(aid.manufacturer(), 0x0006);
        assert_eq!(aid.serial(), 0x0011_2233);

        // Admin: generate a key on the Signing slot, then set touch policy.
        let admin_pin = SecretString::from(std::str::from_utf8(FACTORY_DEFAULT_ADMIN_PIN).unwrap());
        let mut admin = tx
            .as_admin_card(admin_pin)
            .expect("admin PIN should verify against the fake's factory-default PW3");

        fn fake_fingerprint(
            _pub_key: &PublicKeyMaterial,
            _ts: KeyGenerationTime,
            _key_type: KeyType,
        ) -> Result<Fingerprint, openpgp_card::Error> {
            Fingerprint::try_from(&[0xEE_u8; 20][..])
        }

        let (pub_key, _ts) = admin
            .generate_key(fake_fingerprint, KeyType::Signing)
            .expect("key generation should succeed against the fake");

        match pub_key {
            PublicKeyMaterial::E(ecc) => {
                assert_eq!(ecc.data(), FakeCard::fake_public_key());
            }
            PublicKeyMaterial::R(_) => panic!("expected an ECC (Ed25519) public key"),
        }

        admin
            .set_touch_policy(KeyType::Signing, openpgp_card::ocard::data::TouchPolicy::On)
            .expect("touch policy should be settable against the fake");

        // `admin` borrows `tx` mutably; it's not used again, so NLL ends
        // that borrow here and `tx` is free to reuse below.

        // Signing: verify PW1 for signing directly on `Card<Transaction>`,
        // then reach the low-level `ocard::Transaction` via the public
        // `card()` escape hatch (grounding point 3) to actually sign,
        // since `Card<Sign>` itself has nothing public that can.
        let user_pin = SecretString::from(std::str::from_utf8(FACTORY_DEFAULT_USER_PIN).unwrap());
        tx.verify_user_signing_pin(user_pin)
            .expect("user PIN should verify against the fake's factory-default PW1");

        let signature = tx
            .card()
            .signature_for_hash(SigningAlgo::ECC, b"some message digest")
            .expect("signing should succeed against the fake");

        assert_eq!(signature, FakeCard::fake_signature());
    }

    #[test]
    fn absent_card_fails_at_transaction() {
        let mut fake = FakeCard::absent();
        let err = card_backend::CardBackend::transaction(&mut fake, None)
            .err()
            .expect("transaction on an absent card should fail");
        assert!(matches!(err, SmartcardError::CardNotFound(_)));
    }

    #[test]
    fn wrong_pin_is_rejected_and_reported_as_password_not_checked() {
        let fake = FakeCard::new().with_changed_user_pin(b"000000");
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        let wrong_pin = SecretString::from("999999");
        let err = tx
            .verify_user_signing_pin(wrong_pin)
            .expect_err("wrong PIN should be rejected");

        match err {
            openpgp_card::Error::CardStatus(status) => {
                assert!(matches!(
                    status,
                    openpgp_card::ocard::StatusBytes::PasswordNotChecked(_)
                ));
            }
            other => panic!("expected a CardStatus error, got {other:?}"),
        }
    }

    #[test]
    fn signing_without_verified_pin_is_rejected_as_security_status_not_satisfied() {
        let fake = FakeCard::new();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        // No `verify_user_signing_pin` call at all: a real implementation
        // bug in a later task that forgets to verify PW1 before signing
        // must fail against this fake, not silently pass (I-1 finding).
        let err = tx
            .card()
            .signature_for_hash(SigningAlgo::ECC, b"some message digest")
            .expect_err("signing without a verified PIN should be rejected");

        match err {
            openpgp_card::Error::CardStatus(status) => {
                assert!(matches!(
                    status,
                    openpgp_card::ocard::StatusBytes::SecurityStatusNotSatisfied
                ));
            }
            other => panic!("expected a CardStatus error, got {other:?}"),
        }
    }

    #[test]
    fn generating_a_key_without_verified_admin_pin_is_rejected_as_security_status_not_satisfied() {
        let fake = FakeCard::new();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        fn fake_fingerprint(
            _pub_key: &PublicKeyMaterial,
            _ts: KeyGenerationTime,
            _key_type: KeyType,
        ) -> Result<Fingerprint, openpgp_card::Error> {
            Fingerprint::try_from(&[0xEE_u8; 20][..])
        }

        // No `as_admin_card`/`verify_admin_pin` call at all: reach the
        // low-level `generate_key` directly via the same `card()` escape
        // hatch grounding point 3 uses for signing, so this exercises the
        // fake's own gating rather than the typed `Card<Admin>` wrapper
        // (which would force verification first and could hide a bug in
        // this fake instead of catching it).
        let err = tx
            .card()
            .generate_key(fake_fingerprint, KeyType::Signing)
            .expect_err("key generation without a verified admin PIN should be rejected");

        match err {
            openpgp_card::Error::CardStatus(status) => {
                assert!(matches!(
                    status,
                    openpgp_card::ocard::StatusBytes::SecurityStatusNotSatisfied
                ));
            }
            other => panic!("expected a CardStatus error, got {other:?}"),
        }
    }

    #[test]
    fn touch_timeout_surfaces_as_a_smartcard_error() {
        let fake = FakeCard::new().with_touch_timeout();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        let user_pin = SecretString::from(std::str::from_utf8(FACTORY_DEFAULT_USER_PIN).unwrap());
        tx.verify_user_signing_pin(user_pin).unwrap();

        let err = tx
            .card()
            .signature_for_hash(SigningAlgo::ECC, b"digest")
            .expect_err("touch timeout should surface as an error");

        assert!(matches!(err, openpgp_card::Error::Smartcard(_)));
    }
}
