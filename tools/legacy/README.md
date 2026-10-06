# Legacy integration scripts

These scripts came from earlier CTAP2 bring-up stages. They are kept for historical/debugging value but are **not** the canonical v0.3 PIN/`credProtect` validation path.

In particular, they do not drive the full `clientPIN` exchange required to unlock a freshly powered v0.3 authenticator. Prefer Chromium/WebAuthn, `fido2-token`, and OpenSSH for end-to-end validation of this snapshot.
