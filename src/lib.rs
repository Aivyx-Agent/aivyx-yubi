//! `aivyx-yubi` — hardware-backed Ed25519 signing via a YubiKey's
//! OpenPGP card applet. See `docs/superpowers/specs/
//! 2026-09-07-aivyx-yubi-design.md` for the full design rationale.

pub use openpgp_card::Card;

/// Fake `CardBackend`/`CardTransaction` test double standing in for real
/// YubiKey hardware. See the module's own doc comment for how it was
/// grounded in `openpgp-card`'s real vendored source.
///
/// Available under plain `cargo test` (via `cfg(test)`, for this crate's
/// own unit tests) and, for later tasks' integration tests under `tests/`,
/// under the `test-util` Cargo feature (`cargo test --features test-util`).
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
