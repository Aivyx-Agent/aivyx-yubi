# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`aivyx-yubi` wraps a YubiKey's OpenPGP card applet for hardware-backed
Ed25519 signing — card discovery, on-card key generation for the
Signature slot, touch-policy configuration, PIN handling, and raw-byte
signing. It has no knowledge of Aivyx's federation protocol or any
other product-specific concept; `aivyx-federation`'s `Identity` is its
first (and so far only) consumer.

See `docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md` for the
full design rationale, including why the OpenPGP applet was chosen over
PIV (the `yubikey` PIV crate is unmaintained and lacks Ed25519 support;
`openpgp-card` is actively maintained and has supported Ed25519 since
firmware 5.2.3).

## Build, run, test, lint

```sh
cargo build
cargo test
cargo clippy --all-targets
```

**Requires `pcscd` running** to talk to a real card — a new system
dependency this crate introduces (not required by any other Aivyx
repo). Every test in this crate's own suite runs against a fake
`CardBackend`/`CardTransaction` implementation, not real hardware — this
environment has none. Manual verification against a real YubiKey is a
documented follow-up, not something this crate's own CI/tests can prove.

## Where to look next

- `README.md` — setup and usage.
- `docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md` — full design.
