# Security Policy

aivyx-yubi signs with an Ed25519 key held on a YubiKey's OpenPGP card
applet, so the key never leaves the card. A way to make it sign without
the card's touch or PIN, to extract the key, or to get a signature over
data the caller didn't ask for is in scope.

This is not a bug bounty program.

## Reporting a vulnerability

Report it privately on GitHub: [Report a vulnerability](https://github.com/Aivyx-Agent/aivyx-yubi/security/advisories/new)
(this repo's **Security** tab). Only the maintainer sees the report
until a fix is published. Please don't open a public issue for a
vulnerability.

We aim to resolve or provide a remediation plan for a confirmed
vulnerability within 90 days of the report, or coordinate a later
disclosure date with the reporter if a fix genuinely needs longer.
Credit is offered in release notes at the reporter's preference.
