# Validation record

This document records what was actually demonstrated for the known-good `v0.3.0-lab` firmware. It is not a FIDO conformance report.

## Hardware/software context

- Board: M5Stack AtomS3U (ESP32-S3)
- USB VID:PID observed by the host: `303a:4004`
- ESP-IDF source tree reported by the successful build: `v5.5-dev-1637-g5950be0d6e-dirty`
- Compiler toolchain: `xtensa-esp-elf 14.2.0`
- `esp_tinyusb`: 2.3.0
- Python FIDO tooling used during development: python-fido2 2.2.1
- OpenSSH: 10.x test flow

## Demonstrated flows

### Chromium / WebAuthn

A new credential was registered and subsequently authenticated through Chromium/WebAuthn after provisioning `clientPIN`. The browser displayed its native PIN prompt and the device required the physical button for normal user-presence operations.

### OpenSSH enrollment with user verification

The following form of command succeeded:

```bash
ssh-keygen -vvv -t ecdsa-sk -O verify-required -f /tmp/id_esp32_credprot -N ''
```

The OpenSSH/libfido2 path initially received `FIDO_ERR_PIN_REQUIRED`, requested the authenticator PIN, and completed enrollment with the `with-pin` flag. This exercised `credProtect=3`.

### OpenSSH signing and verification

A subsequent `ssh-keygen -Y sign` operation requested PIN and user presence and produced an SSH signature. Verification with `ssh-keygen -Y verify` returned a valid `Good "file" signature` result.

## Native tests

`tests/run_native.sh` compiles the protocol/parser tests on the host with:

- `-Wall -Wextra -Werror`
- AddressSanitizer
- UndefinedBehaviorSanitizer

The tests use crypto/storage mocks and therefore do not validate the ESP32 mbedTLS/NVS implementation.

## What has not been demonstrated

- FIDO Alliance certification or complete CTAP conformance.
- Resistance to malicious firmware or physical extraction.
- Secure handling under power loss at every NVS write boundary.
- Production-grade PIN KDF hardness.
- Resident/discoverable credentials.
- The LILYGO and Waveshare board selections.
