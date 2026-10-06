# Architecture

## Scope

`v0.3.0-lab` is intentionally small: one USB HID FIDO interface, a bounded CTAPHID transport, a minimal CBOR codec, a CTAP2 command engine, a PIN/UV Auth Protocol 1 implementation, and a crypto/NVS backend.

```text
USB HID (64-byte reports)
        |
      CTAPHID
        |
      CTAP2
   +----+----------------------+------------------+
   |                           |                  |
getInfo                 make/get assertion     clientPIN
   |                           |                  |
   +---------------------------+------------------+
                               |
                   credential / root backend
                               |
           ES256 + HMAC + PBKDF2 + AES-256-GCM
                               |
                              NVS
```

## Root secret and credential derivation

A fresh setup creates a random 32-byte root. The root is wrapped into `root_enc_v1` using AES-256-GCM. The wrapping key is produced by PBKDF2-HMAC-SHA256 from the 16-byte CTAP2 `PINHash` and a per-record random 16-byte salt.

The root is not stored in plaintext by the v0.3 format. It is loaded into RAM after successful PIN verification and cleared by `fc_lock()` or power loss.

Non-resident credential IDs are 33 bytes. Version-2 IDs include the `credProtect` policy in authenticated ID material. The root HMAC authenticates the RP ID, ID nonce/policy material and credential version; the per-credential P-256 private scalar is then deterministically derived from the same root, RP ID and credential ID.

## User presence and user verification

User presence (UP) and user verification (UV) are independent:

- Normal assertions default to UP=true and require a fresh button edge.
- OpenSSH discovery uses `up:false`; this firmware returns a genuine ES256 assertion with UP=0 and does not increment the persistent counter.
- A valid CTAP2 `pinUvAuthParam` sets UV in `authenticatorData`.
- Credentials carrying `credProtect=3` are rejected unless the assertion request has valid per-request PIN/UV authorization, even when the root is already unlocked in RAM.

## NVS records

Namespace: `fido_lab`

- `root_enc_v1`: encrypted root record.
- `counter`: global signature counter used for UP=true assertions.
- `pin_retries`: persistent remaining PIN attempts.

The firmware refuses to continue if it sees the historical plaintext key `root_v1`. Migration requires an explicit destructive flash erase rather than silently rewriting old secrets.

## Deliberate omissions

The design does not implement resident credentials, CTAP1/U2F, attestation, secure reset, encrypted NVS, Secure Boot, flash encryption, eFuse-backed application secrets, or a secure element.
