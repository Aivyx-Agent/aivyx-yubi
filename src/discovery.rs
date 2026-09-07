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
//! [`discover_card_from`]'s enumeration-level filtering matches the real
//! crate's own `Card::<Open>::open_by_ident` (`openpgp-card-0.7.0/src/
//! lib.rs` ~lines 118-141), which takes the exact same `impl
//! Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>,
//! SmartcardError>>` shape and `.filter_map(|c| c.ok())`s it — factored
//! out here (rather than inlined into [`discover_real_card`]) so the
//! actual selection logic is independently testable against
//! [`crate::testing::FakeCard`], which has no real PC/SC reader to
//! enumerate through.
//!
//! **Where this deliberately diverges from `open_by_ident`**: after that
//! `filter_map`, the real `open_by_ident` calls `Card::<Open>::new(b)?`
//! with a bare `?` (confirmed by reading it directly) — a `Card::new`
//! failure on any one candidate **aborts the whole search** with an
//! error, it does not move on to the next candidate. `openpgp_card::
//! Card::<Open>::new` itself immediately `SELECT`s the OpenPGP
//! application and reads Application Related Data (`ocard/mod.rs::
//! OpenPGP::new`, confirmed by reading it directly) — so a backend that
//! connects but isn't a live OpenPGP-capable card (wrong applet, card
//! removed mid-enumeration) fails at *that* point, distinct from
//! `card_backends()`'s per-reader connect step. [`discover_card_from`]
//! instead *skips* a `Card::new` failure and keeps trying the next
//! candidate — a deliberate improvement for multi-reader environments
//! (one broken or non-OpenPGP card plugged into one reader shouldn't
//! prevent finding a working card plugged into a different reader), not
//! an attempt to replicate `open_by_ident`'s own (more strict) behavior.
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
    Card, Error as OpenpgpError,
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
/// live, SELECT-able OpenPGP card. Per-candidate enumeration errors
/// (`Err` items in the iterator itself) are filtered out the same way
/// `openpgp_card::Card::open_by_ident` does; a `Card::new` failure on a
/// present candidate (card absent, wrong applet, ...) is then skipped and
/// the next candidate tried — a deliberate departure from
/// `open_by_ident`, which aborts its whole search on that failure via a
/// bare `?`. See this module's doc comment for the full grounding and
/// rationale.
pub fn discover_card_from(
    cards: impl Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
) -> Result<Card<Open>, YubiError> {
    // Distinguishes "no card was ever reachable" from "a card was
    // reachable but failed to open as OpenPGP" (wrong applet, corrupted
    // ART, card pulled mid-detection, ...), so the final error doesn't
    // misleadingly claim "no reader/card at all" when a card genuinely
    // is inserted but broken.
    let mut saw_broken_candidate = false;
    for backend in cards.filter_map(Result::ok) {
        match Card::<Open>::new(backend) {
            Ok(card) => return Ok(card),
            // `Error::Smartcard(SmartcardError::CardNotFound(_))` is what
            // `Card::new` propagates (via `?` on `op.transaction()`,
            // `ocard/mod.rs::OpenPGP::new`) when *this* candidate simply
            // had no card present — not evidence of a broken card, so it
            // doesn't set the flag below.
            Err(OpenpgpError::Smartcard(SmartcardError::CardNotFound(_))) => {}
            Err(_) => saw_broken_candidate = true,
        }
    }
    let message = if saw_broken_candidate {
        "a card was found but could not be opened as an OpenPGP card (wrong applet, \
         corrupted card state, or the card was removed mid-detection) — this is not the \
         \"no reader/card at all\" case; check that a genuine OpenPGP-capable card is \
         inserted"
    } else {
        "no OpenPGP-capable card found on any connected PC/SC reader — insert a YubiKey \
         and retry"
    };
    Err(YubiError::CardNotFound(message.to_string()))
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
    fn skips_a_per_item_enumeration_error_and_finds_the_working_candidate() {
        // The real `card_backends()` iterator can yield a per-item `Err`
        // (e.g. a reader that failed mid-enumeration), not just
        // `Ok`-wrapped present/absent cards — `.filter_map(Result::ok)`
        // must skip that item and keep looking, same as
        // `open_by_ident`'s own enumeration-level filtering.
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> = vec![
            Err(SmartcardError::Error("reader glitch".to_string())),
            Ok(FakeCard::new().into()),
        ];

        assert!(discover_card_from(backends.into_iter()).is_ok());
    }

    #[test]
    fn broken_but_present_card_is_reported_distinctly_from_no_card_at_all() {
        // `FakeCard::broken()` connects and SELECTs fine but fails to
        // provide Application Related Data (wrong applet/corrupted
        // state) — `Card::new` fails with a `CardStatus` error, not
        // `Smartcard(CardNotFound)`, so the resulting message must say a
        // card WAS found rather than reusing the "no reader/card at all"
        // wording (Finding 5).
        let backends: Vec<Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>> =
            vec![Ok(FakeCard::broken().into())];

        let err = discover_card_from(backends.into_iter())
            .err()
            .expect("a broken candidate should not be selected");
        match err {
            YubiError::CardNotFound(msg) => {
                assert!(
                    msg.contains("was found but could not be opened"),
                    "message should distinguish a broken card from no card at all: {msg}"
                );
            }
            other => panic!("expected YubiError::CardNotFound, got {other:?}"),
        }
    }

    #[test]
    fn context_error_names_pcscd_as_the_likely_cause() {
        // `SmartcardError::ContextError` (`card-backend-0.2.0/src/lib.rs`)
        // is what `PcscBackend::card_backends` surfaces when it can't
        // establish a PC/SC context at all — the "pcscd isn't running"
        // case (see this module's doc comment).
        let err = map_enumeration_error(SmartcardError::ContextError("boom".to_string()));
        match err {
            YubiError::CardNotFound(msg) => {
                assert!(msg.contains("pcscd"), "message should name pcscd: {msg}");
                assert!(
                    msg.contains("boom"),
                    "message should include the underlying cause: {msg}"
                );
            }
            other => panic!("expected YubiError::CardNotFound, got {other:?}"),
        }
    }

    #[test]
    fn reader_error_names_pcscd_as_the_likely_cause() {
        // `SmartcardError::ReaderError` is what `card_backends` surfaces
        // when listing readers itself fails.
        let err = map_enumeration_error(SmartcardError::ReaderError("boom".to_string()));
        match err {
            YubiError::CardNotFound(msg) => {
                assert!(msg.contains("pcscd"), "message should name pcscd: {msg}");
                assert!(
                    msg.contains("boom"),
                    "message should include the underlying cause: {msg}"
                );
            }
            other => panic!("expected YubiError::CardNotFound, got {other:?}"),
        }
    }

    #[test]
    fn no_reader_found_error_reports_card_not_found_naming_a_reader() {
        let err = map_enumeration_error(SmartcardError::NoReaderFoundError);
        match err {
            YubiError::CardNotFound(msg) => {
                assert!(
                    msg.to_lowercase().contains("reader"),
                    "message should mention a reader: {msg}"
                );
            }
            other => panic!("expected YubiError::CardNotFound, got {other:?}"),
        }
    }

    #[test]
    fn other_smartcard_error_variants_fall_back_to_other() {
        // Per-connection failure variants aren't documented/observed to
        // occur on `card_backends()`'s *outer* `Result` (see this
        // module's doc comment) — confirm the fallback arm behaves as
        // documented rather than silently mis-mapping them too.
        let err = map_enumeration_error(SmartcardError::CardNotFound("boom".to_string()));
        assert!(matches!(err, YubiError::Other(_)));
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
