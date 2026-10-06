# ESP32-FIDO2 Lab

Experimental **CTAP2/FIDO2 USB authenticator firmware for ESP32-S3**, validated on an **M5Stack AtomS3U** with Chromium/WebAuthn and OpenSSH security-key (`ecdsa-sk`) workflows.

> **Research software — LAB ONLY.** This project is not FIDO-certified, has not received an independent security audit, and must not be used as the sole authenticator for valuable accounts or production systems.

## What this version implements

`v0.3.0-lab` is the frozen, known-good branch produced during the AtomS3U interoperability work. It implements:

- USB HID transport using the FIDO usage page and 64-byte CTAPHID reports.
- CTAP2 `authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`, and `authenticatorClientPIN`.
- **CTAP2 only**; there is deliberately no CTAP1/U2F implementation.
- ES256 (ECDSA P-256 / SHA-256).
- Non-resident credentials (`rk:false`) with deterministic private-key derivation from an encrypted root secret.
- Physical user presence through the AtomS3U button (GPIO41).
- PIN/UV Auth Protocol 1: `getRetries`, `getKeyAgreement`, `setPIN`, `changePIN`, and `getPINToken`.
- `credProtect` policies 1, 2 and 3 encoded and authenticated inside version-2 credential IDs.
- OpenSSH-compatible `getAssertion(up:false)` preflight: a genuine UP=0 assertion is returned without incrementing the persistent signature counter.
- AES-256-GCM protection of the 32-byte root secret in NVS. The AES key is derived from the CTAP2 PIN hash using PBKDF2-HMAC-SHA256 (40,000 iterations in this research version).

Not implemented: discoverable/resident credentials, CTAP1/U2F, attestation, `authenticatorReset`, Secure Boot, flash encryption, anti-rollback storage, or hardware-backed key isolation.

## Validated interoperability

The following flows were exercised on real M5Stack AtomS3U hardware:

| Client / flow | Result |
| --- | --- |
| Chromium + WebAuthn registration | Passed with native PIN prompt + button |
| Chromium + WebAuthn authentication | Passed with native PIN prompt + button |
| OpenSSH 10 `ssh-keygen -t ecdsa-sk -O verify-required` | Passed; `credProtect=3` triggered PIN/UV correctly |
| OpenSSH `ssh-keygen -Y sign` | Passed with PIN + user presence |
| OpenSSH `ssh-keygen -Y verify` | Passed (`Good "file" signature`) |

This is an interoperability result, **not** a claim of CTAP conformance or security certification.

## Known-good firmware provenance

The firmware that passed the hardware tests was built from the `main/` sources preserved in this repository before the documentation/test cleanup.

- Target: `esp32s3`
- Hardware: M5Stack AtomS3U
- ESP-IDF working tree: `v5.5-dev-1637-g5950be0d6e-dirty`
- Toolchain: `xtensa-esp-elf 14.2.0`
- `esp_tinyusb`: `2.3.0`
- Application partition offset: `0x10000`
- Known-good application image SHA-256: `597945d24b585b5cd853db6d23a0b241b6a8149ba430c662c9b282c91d75a377`

The archived application image was compared byte-for-byte with the application region of the captured device flash and matched exactly. The original ESP-IDF checkout was marked `dirty`, so a bit-for-bit rebuild from a clean public ESP-IDF checkout is **not** claimed. The historical CMake project name `esp32_fido2_starter` is retained intentionally for provenance. See [`docs/KNOWN_GOOD_BUILD.md`](docs/KNOWN_GOOD_BUILD.md).

## Build

Requirements:

- ESP-IDF 5.5-era toolchain with ESP32-S3 support.
- Python environment supported by that ESP-IDF checkout.
- The component manager enabled so `espressif/esp_tinyusb==2.3.0` can be resolved.

```bash
. "$IDF_PATH/export.sh"
idf.py set-target esp32s3
idf.py build
```

`dependencies.lock` is kept intentionally. Generated `build/`, `managed_components/`, and local `sdkconfig` files are not tracked.

### Flashing a fresh laboratory device

**This destroys the current flash contents. Do not run it on a security key that protects real accounts.**

```bash
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash
```

After reconnecting, locate the HID device and inspect it:

```bash
fido2-token -L
fido2-token -I /dev/hidrawX
```

Provision the passphrase/PIN once:

```bash
fido2-token -S /dev/hidrawX
```

This firmware intentionally requires **12–63 UTF-8 bytes** for the configured PIN/passphrase. The passphrase is security-critical: the current design permits offline guessing against a copied NVS image.

## OpenSSH test

Create a new test credential that requires user verification:

```bash
ssh-keygen -vvv -t ecdsa-sk \
  -O verify-required \
  -f /tmp/id_esp32_credprot \
  -N ''
```

Sign a test file:

```bash
echo 'ESP32 FIDO2 test' > /tmp/esp32-fido2-test.txt
ssh-keygen -vvv -Y sign \
  -f /tmp/id_esp32_credprot \
  -n file \
  /tmp/esp32-fido2-test.txt
```

Verify the signature:

```bash
printf 'esp32 %s\n' "$(cat /tmp/id_esp32_credprot.pub)" > /tmp/allowed-signers
ssh-keygen -Y verify \
  -f /tmp/allowed-signers \
  -I esp32 \
  -n file \
  -s /tmp/esp32-fido2-test.txt.sig \
  < /tmp/esp32-fido2-test.txt
```

Expected result: `Good "file" signature ...`.

## Native regression tests

The native tests exercise the bounded CBOR parser, CTAPHID state handling, touch gating, the OpenSSH silent-preflight behaviour, and `credProtect` policy routing with a mocked crypto backend.

```bash
bash tests/run_native.sh
```

They run with AddressSanitizer and UndefinedBehaviorSanitizer. They **do not** validate ESP32 NVS, mbedTLS AES-GCM/PBKDF2, hardware RNG, USB timing, or real `clientPIN` ECDH.

## Security model and limitations

The encrypted root record stored in NVS contains a version, random salt, random 96-bit GCM IV, 128-bit GCM tag, and 32-byte ciphertext. The root is decrypted into RAM only after a successful `clientPIN.getPINToken` path.

Important limitations:

- A full flash copy permits **offline passphrase guessing**. PBKDF2-40,000 is not intended to make weak human PINs safe.
- The device has no Secure Boot or flash encryption in this version. An attacker with physical access can replace firmware.
- The decrypted root and PIN token live in RAM while the session remains unlocked.
- NVS state is not protected against rollback.
- `credProtect=3` requires a valid per-request PIN/UV authorization; policies 1/2 do not make every assertion require PIN merely because the root is unlocked.
- Silent `up:false` assertions are intentionally supported for OpenSSH key discovery and carry UP=0.
- There is no certified secure element and no resistance claim against invasive hardware attacks, fault injection, or RAM extraction.

Read [`SECURITY.md`](SECURITY.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before modifying or deploying the firmware.

## Repository layout

```text
main/                   firmware: USB, CTAPHID, CBOR, CTAP2, crypto and clientPIN
tests/                  native regression tests with mocked crypto backend
tools/probar_host.py    non-destructive getInfo helper
tools/legacy/           historical lab scripts; not part of the validated v0.3 PIN flow
docs/                   architecture, validation and build provenance
```

## Supported boards

The Kconfig currently contains selections for AtomS3U, LILYGO T-Dongle-S3 and Waveshare ESP32-S3-GEEK. **Only the M5Stack AtomS3U has been validated in this work.** The other entries should be treated as unverified ports. The known-good AtomS3U build also used a 2 MiB flash-size setting on hardware that physically reports 8 MiB; this is documented rather than silently changed in the frozen snapshot.

## License

MIT. See [`LICENSE`](LICENSE).
