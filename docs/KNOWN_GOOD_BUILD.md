# Known-good build provenance

The uploaded project archive contained both source and the build output used during the successful hardware test session.

## Application identity

Known-good application image:

```text
SHA-256  597945d24b585b5cd853db6d23a0b241b6a8149ba430c662c9b282c91d75a377
size     327216 bytes
offset   0x10000
```

The application bytes at offset `0x10000` in the archived 8 MiB device flash dump were compared with `build/esp32_fido2_starter.bin`; they matched byte-for-byte.

The source timestamps in the archived tree also place the final `fido_engine.c` edit before the final application build:

```text
fido_engine.c               2026-10-03 15:40:10 UTC
libmain.a                    2026-10-03 15:40:12 UTC
esp32_fido2_starter.bin      2026-10-03 15:40:16 UTC
```

The final source contains the corrected `getInfo` ordering (`1, 2, 3, ...`) and the `credProtect` policy-3 assertion check.

## Build environment captured in the archive

```text
ESP-IDF git revision: v5.5-dev-1637-g5950be0d6e-dirty
IDF_PATH:             local ESP-IDF checkout (path omitted)
Python:               3.14.7
xtensa-esp-elf:        14.2.0
esp_tinyusb:           2.3.0
target:                esp32s3
```

Because the ESP-IDF source tree was reported as `dirty`, the repository does not claim that a clean ESP-IDF 5.5 checkout will reproduce the application image bit-for-bit. Functional rebuilds should use a 5.5-era ESP-IDF and the pinned component lockfile, then rerun the interoperability tests.

## Repository-cleanup guarantee

The public-repository preparation preserves the executable firmware logic. The only `main/` edit is a stale banner comment in `fido_usb_main.c`; documentation and native-test mocks/tests are also cleaned up.

The historical CMake project name `esp32_fido2_starter` is retained in this snapshot deliberately; changing it would alter build metadata without improving the validated firmware.

The tested AtomS3U contains an 8 MiB flash chip, while the known-good application image header/configuration selected 2 MiB. The firmware uses only the small partition table shown in the project, so this did not prevent the validated flows, but it is a configuration mismatch to resolve only in a separately retested revision.
