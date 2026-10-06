# Release checklist

For a public `v0.3.0-lab` release:

- [ ] Build on a clean ESP-IDF environment and record the exact `idf.py --version` / Git revision.
- [ ] Run `bash tests/run_native.sh`.
- [ ] Flash a disposable AtomS3U and provision a new laboratory PIN/passphrase.
- [ ] Confirm `fido2-token -I` advertises `FIDO_2_0`, `clientPin`, PIN/UV protocol 1 and `credProtect`.
- [ ] Repeat Chromium/WebAuthn registration and authentication.
- [ ] Repeat OpenSSH `ecdsa-sk -O verify-required` enrollment.
- [ ] Repeat `ssh-keygen -Y sign` and `ssh-keygen -Y verify`.
- [ ] Record the release application SHA-256.
- [ ] Confirm that no flash/NVS dumps, PINs, private keys or local build paths are committed.
- [ ] Keep the release prominently labelled **LAB ONLY / not FIDO-certified / not audited**.
- [ ] Enable GitHub private vulnerability reporting if available.

Do not silently change the flash-size configuration, NVS format, credential-ID format, PIN semantics or CTAPHID preflight behaviour in the same release that claims the known-good v0.3 validation. Such changes require a new retested release.
