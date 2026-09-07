//! Card discovery: enumerating connected YubiKey/OpenPGP-card devices via
//! `card-backend-pcsc`'s real PC/SC transport, and reading a discovered
//! card's serial/AID.
//!
//! # Grounding
//!
//! `card-backend-pcsc` (`card-backend-pcsc-0.5.2/src/lib.rs`) enumerates
//! readers and hands back cards two ways:
//! - `PcscBackend::cards(mode) -> Result<impl Iterator<Item =
//!   Result<PcscBackend, SmartcardError>>, SmartcardError>`
//! - `PcscBackend::card_backends(mode) -> Result<impl Iterator<Item =
//!   Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
//!   SmartcardError>` — the pre-boxed form, ready to hand straight to
//!   `openpgp_card::Card::new`/`Card::open_by_ident`. This module uses
//!   the latter.
//!
//! The *outer* `Result` (returned by the function call itself) only fails
//! for enumeration-level problems: establishing the PC/SC context
//! (`SmartcardError::ContextError`, the "pcscd not running/unreachable"
//! case) or listing readers (`SmartcardError::ReaderError`/
//! `NoReaderFoundError`, confirmed by reading `card-backend-0.2.0/src/
//! lib.rs`'s `SmartcardError` enum directly). Per-reader connection
//! failures (e.g. a reader with no card inserted) are instead filtered
//! out *inside* `card-backend-pcsc`'s own `raw_pcsc_cards` — a reader
//! reporting `pcsc::Error::NoSmartcard` is silently skipped there, never
//! surfaced as an `Err` in the returned iterator (confirmed by reading
//! `card-backend-pcsc-0.5.2/src/lib.rs`'s `raw_pcsc_cards` directly). So
//! "zero readers have a card" and "pcscd isn't running" are genuinely
//! different failure shapes: the former surfaces as an *empty* iterator
//! (this module's job to turn into a clear [`YubiError::CardNotFound`]),
//! the latter as the outer `Result::Err` (mapped by
//! [`map_enumeration_error`]).
//!
//! [`discover_card_from`] mirrors the real crate's own
//! `Card::<Open>::open_by_ident` (`openpgp-card-0.7.0/src/lib.rs`
//! ~lines 118-141), which takes the exact same `impl Iterator<Item =
//! Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>` shape and
//! `.filter_map(|c| c.ok())`s it — factored out here (rather than inlined
//! into [`discover_real_card`]) so the actual selection logic is
//! independently testable against [`crate::testing::FakeCard`], which has
//! no real PC/SC reader to enumerate through.
//!
//! `openpgp_card::Card::<Open>::new` itself immediately `SELECT`s the
//! OpenPGP application and reads Application Related Data
//! (`ocard/mod.rs::OpenPGP::new`, confirmed by reading it directly) — so
//! a backend that connects but isn't a live OpenPGP-capable card (wrong
//! applet, card removed mid-enumeration) fails at *that* point too, not
//! only at `card_backends()`'s per-reader connect step.
//! [`discover_card_from`] treats that failure the same way as a
//! per-reader connection failure: skip it, keep looking at the next
//! candidate.
//!
//! `discover_real_card` itself has no automated test in this crate: it's
//! the one real seam that talks to actual `pcscd`/PC/SC, which this
//! environment (and this crate's CI) has none of — see the design spec's
//! "Real hardware verification" note and this crate's own `CLAUDE.md`.
//! [`discover_card_from`] carries the real, tested selection logic; this
//! function is a thin, hand-verified wrapper around it plus the one
//! enumeration-error mapping ([`map_enumeration_error`]) that only the
//! real `card_backends()` call can exercise.

use card_backend::{CardBackend, SmartcardError};
use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    Card,
    state::{Open, Transaction},
};

use crate::YubiError;

/// Enumerate connected PC/SC readers via the real `card-backend-pcsc`
/// transport and return the first one presenting a usable OpenPGP card.
///
/// Maps "pcscd unreachable"/"no reader found" to a
/// [`YubiError::CardNotFound`] naming the likely cause, rather than a raw
/// PC/SC error string — see this module's doc comment for why those are
/// two distinct failure shapes in the real API.
pub fn discover_real_card() -> Result<Card<Open>, YubiError> {
    let cards = PcscBackend::card_backends(None).map_err(map_enumeration_error)?;
    discover_card_from(cards)
}

/// The backend-agnostic core of [`discover_real_card`]: given an iterator
/// of candidate backends (real PC/SC ones, or — in this crate's own
/// tests — [`crate::testing::FakeCard`]s), returns the first one that's a
/// live, SELECT-able OpenPGP card. Errors from individual candidates
/// (card absent, wrong applet, ...) are swallowed and treated as "try the
/// next one", matching `openpgp_card::Card::open_by_ident`'s own
/// behavior (see this module's doc comment).
pub fn discover_card_from(
    cards: impl Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
) -> Result<Card<Open>, YubiError> {
    for backend in cards.filter_map(Result::ok) {
        if let Ok(card) = Card::<Open>::new(backend) {
            return Ok(card);
        }
    }
    Err(YubiError::CardNotFound(
        "no OpenPGP-capable card found on any connected PC/SC reader — insert a YubiKey \
         and retry"
            .to_string(),
    ))
}

/// Read a discovered card's serial/AID as a stable, human-readable
/// string — needed by `aivyx-federation`'s binding record (Task 7) to
/// detect "wrong card inserted" (see this crate's design spec).
///
/// Uses `ApplicationIdentifier::ident()`
/// (`ocard/data/application_id.rs::ApplicationIdentifier::ident`) rather
/// than the bare numeric serial: it's the real crate's own canonical
/// human-readable form (`"MMMM:SSSSSSSS"`, manufacturer id + serial, both
/// zero-padded uppercase hex — confirmed by reading `ident`'s
/// implementation directly), already unique per card, and its own doc
/// comment says it's meant for exactly this kind of "which card is this"
/// identification ("a more easily human-readable, shorter form of the
/// full 16-byte AID").
pub fn read_serial(tx: &mut Card<Transaction<'_>>) -> Result<String, YubiError> {
    let aid = tx.application_identifier()?;
    Ok(aid.ident())
}

/// Map an enumeration-level (outer) `card_backends()` failure to a clear
/// [`YubiError::CardNotFound`] naming the likely cause. See this module's
/// doc comment for why these are the variants expected here; the
/// remaining `SmartcardError` variants (per-connection failures) fall
/// back to [`YubiError::Other`] since `card_backends()`'s outer `Result`
/// isn't documented or observed to produce them.
fn map_enumeration_error(err: SmartcardError) -> YubiError {
    match err {
        SmartcardError::ContextError(msg) => YubiError::CardNotFound(format!(
            "could not establish a PC/SC context ({msg}) — is pcscd running?"
        )),
        SmartcardError::ReaderError(msg) => YubiError::CardNotFound(format!(
            "could not list PC/SC readers ({msg}) — is pcscd running?"
        )),
        SmartcardError::NoReaderFoundError => {
            YubiError::CardNotFound("no PC/SC reader found — is a YubiKey plugged in?".to_string())
        }
        other => YubiError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeCard;

    #[test]
    fn discovers_the_first_present_fake_card() {
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> =
            vec![Ok(FakeCard::new().into())];

        assert!(discover_card_from(backends.into_iter()).is_ok());
    }

    #[test]
    fn empty_reader_list_reports_card_not_found() {
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> = vec![];

        let err = discover_card_from(backends.into_iter())
            .err()
            .expect("empty reader list should fail");
        assert!(matches!(err, YubiError::CardNotFound(_)));
    }

    #[test]
    fn absent_card_is_skipped_and_reports_card_not_found() {
        // `FakeCard::absent()` fails at `CardBackend::transaction()`
        // itself (see `testing.rs`'s doc comment), which is exactly
        // where `openpgp_card::Card::<Open>::new` fails too (it SELECTs
        // immediately) — so this exercises the same "skip and keep
        // looking" path a real reader with no card inserted would hit.
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> =
            vec![Ok(FakeCard::absent().into())];

        let err = discover_card_from(backends.into_iter())
            .err()
            .expect("absent card should not be selected");
        assert!(matches!(err, YubiError::CardNotFound(_)));
    }

    #[test]
    fn falls_through_an_absent_card_to_a_present_one() {
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> =
            vec![Ok(FakeCard::absent().into()), Ok(FakeCard::new().into())];

        assert!(discover_card_from(backends.into_iter()).is_ok());
    }

    #[test]
    fn reads_the_fake_cards_serial_as_a_manufacturer_colon_serial_string() {
        let fake = FakeCard::new();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();

        let serial = read_serial(&mut tx).unwrap();
        // `FakeCard::new()`'s fixed manufacturer (0x0006, "Yubico AB")
        // and serial (0x00112233) — see `testing.rs`.
        assert_eq!(serial, "0006:00112233");
    }
}
