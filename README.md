# aivyx-yubi

[![CI](https://github.com/Aivyx-Agent/aivyx-yubi/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Aivyx-Agent/aivyx-yubi/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)

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
  well-known factory default (`123456`), and refuses to even probe for
  that if either PIN's retry counter is already reduced (check the card
  with `gpg --card-status` first in that case).
- Refuses to generate a new Signature-slot key if the slot already holds
  one, unless the caller explicitly opts into overwriting it
  (`provision::generate_signature_key_overwriting`) — many YubiKey owners
  keep a real GPG signing key in this slot, and losing it is irreversible.
- **Writes a non-standard key fingerprint to the slot.** The on-card
  fingerprint this crate stores alongside a newly-generated key (GET DATA
  tag `C5`) is *not* a real OpenPGP v4 fingerprint (RFC 4880 §12.2) — this
  crate never builds or exports actual OpenPGP certificates, so it uses a
  simple placeholder instead (see `provision.rs`'s `key_slot_fingerprint`
  doc comment). Running `gpg --card-status` against a card provisioned by
  this crate will show a fingerprint that matches no real certificate —
  expected, not a bug, but worth knowing if you also use the card with
  GnuPG for anything else.
- Signs arbitrary byte messages, returning a raw 64-byte Ed25519
  signature. Finds the right card by serial among several attached
  devices, and stops presenting the User PIN again (failing immediately
  instead) once the card has rejected it once.
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
