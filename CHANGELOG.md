# Changelog

## 0.3.0-lab — known-good research snapshot

- Added CTAP2 PIN/UV Auth Protocol 1 (`clientPIN`).
- Replaced plaintext root storage with a PIN-derived AES-256-GCM NVS record (`root_enc_v1`).
- Added persistent PIN retry handling and per-boot temporary blocking.
- Added `credProtect` advertisement and policies 1/2/3.
- Bound `credProtect` policy cryptographically into version-2 non-resident credential IDs.
- Required per-request PIN/UV authorization for policy 3.
- Fixed deterministic CBOR ordering in `authenticatorGetInfo` (key 1 precedes extension key 2).
- Preserved OpenSSH CTAP2 `getAssertion(up:false)` preflight with a real UP=0 signature and no persistent counter increment.
- Validated Chromium/WebAuthn and OpenSSH `ecdsa-sk -O verify-required` enrollment/sign/verify on M5Stack AtomS3U.

The repository cleanup after this snapshot changes documentation and native-test mocks only; `main/` is kept byte-identical to the known-good source tree.
