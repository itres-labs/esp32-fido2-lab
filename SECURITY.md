# Security policy

## Status

This repository is experimental security research software. It is **not** FIDO-certified and has not undergone an independent security audit. Do not use it as the sole authenticator for valuable accounts or production infrastructure.

## Threat model of v0.3.0-lab

The design attempts to keep the 32-byte credential root out of plaintext NVS. A successful `clientPIN` flow derives an AES key from the CTAP2 PIN hash, authenticates/decrypts the root record with AES-256-GCM, and keeps the root in RAM for the active power session.

The design does **not** claim protection against:

- offline guessing when an attacker has copied NVS;
- firmware replacement or malicious reflashing;
- rollback of older NVS state;
- invasive hardware attacks, fault injection or RAM extraction;
- host compromise while the authenticator is unlocked;
- denial of service through intentional PIN retry exhaustion.

The firmware does not enable Secure Boot or flash encryption and does not use eFuse-backed secrets.

## Sensitive material

Do not publish:

- full device flash dumps;
- NVS dumps containing `root_enc_v1` from any device used with real credentials;
- configured PIN/passphrase values;
- private test material from external accounts.

Credential IDs and public keys are designed to be public protocol values, but test artefacts should still be reviewed before publication.

## Reporting

For a public deployment of this repository, report security issues privately to the repository maintainers before opening a detailed public issue when practical. Until a dedicated disclosure address is configured, use GitHub's private vulnerability reporting feature if it is enabled for the repository.
