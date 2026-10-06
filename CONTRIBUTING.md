# Contributing

This is a small research firmware project. Changes should preserve the distinction between **demonstrated behaviour** and **security claims**.

Before submitting a change:

1. Run `bash tests/run_native.sh`.
2. Build for `esp32s3` with the pinned component dependency.
3. For protocol changes, repeat the relevant Chromium/WebAuthn and OpenSSH interoperability tests on real hardware.
4. Document any change to the NVS format, credential-ID format, PIN/UV semantics, user-presence handling, or signature counter.
5. Do not describe the project as FIDO-certified, production-ready, tamper-resistant, or audited unless that status actually changes.

Security-sensitive changes should include a short threat-model note explaining what attack is addressed and what remains out of scope.
