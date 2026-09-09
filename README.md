# aivyx-yubi

Hardware-backed Ed25519 signing via a YubiKey's OpenPGP card applet —
built so `aivyx-federation`'s cross-boundary identity key can live in a
hardware device instead of (even encrypted) on disk, with every
signature requiring a physical touch.

## Why the OpenPGP applet, not PIV

Confirmed directly against the real crate ecosystem before choosing:
the `yubikey` Rust crate (PIV) hasn't been updated since August 2023 and
its own docs list no Ed25519 support, even though firmware 5.7+ (2024)
added it to PIV — the crate hasn't caught up. `openpgp-card` (this
crate's real dependency) is actively maintained and has supported
Ed25519 since firmware 5.2.3 (2019), covering far more YubiKeys already
in the wild. See `docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md`
for the full account.

## Requirements

- A YubiKey (or other OpenPGP-card-compatible device) with firmware
  5.2.3 or later.
- **`pcscd` running** — this crate talks to the card over PC/SC via
  `card-backend-pcsc`, which needs the PC/SC daemon reachable. Install
  and enable it per your distro (`pcscd` on most Linux distros; macOS
  and Windows have PC/SC built into the OS).

## What this crate does (and doesn't)

- Discovers connected OpenPGP-card-compatible devices.
- Generates an Ed25519 keypair **on the card itself** for the Signature
  key slot — the private key never leaves the device.
- Sets the Signature slot's touch-policy to fixed/always-on: every
  signature requires a physical tap.
- Refuses to provision a key while the card's PIN is still the
  well-known factory default (`123456`).
- Signs arbitrary byte messages, returning a raw 64-byte Ed25519
  signature.
- Caches the User PIN in process memory for a `YubiKeySigner`'s entire
  lifetime (re-presented to the card on every signature, but the operator
  is only re-touched, not re-prompted for the PIN, after construction) —
  see `CLAUDE.md`'s "Known, deliberately-undefended limitations" for why
  this is a deliberate deviation from the design spec worth a consumer's
  explicit attention.
- Has **no knowledge of Aivyx PA's federation protocol** or any other
  product concept — `aivyx-federation`'s `Identity` is the consumer that
  gives this primitive meaning.

## Testing

No real YubiKey/PC/SC hardware is available in this crate's own CI —
every test runs against a fake `CardBackend`/`CardTransaction`
implementation (`src/testing.rs`). Manual verification against a real
device is a documented follow-up, not something this crate's own test
suite can prove.
