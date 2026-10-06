#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
FLAGS="-std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Imain"
cc $FLAGS tests/test_engine.c main/fido_engine.c main/cbor_min.c -o /tmp/fido-test-engine
/tmp/fido-test-engine
cc $FLAGS tests/test_ctaphid.c main/ctaphid.c -o /tmp/fido-test-hid
/tmp/fido-test-hid

cc $FLAGS tests/test_channels.c main/ctaphid.c -o /tmp/fido-test-channels
/tmp/fido-test-channels
cc $FLAGS tests/test_ssh_probe.c main/ctaphid.c main/fido_engine.c main/cbor_min.c -o /tmp/fido-test-ssh-probe
/tmp/fido-test-ssh-probe

cc $FLAGS tests/test_credprotect.c main/fido_engine.c main/cbor_min.c -o /tmp/fido-test-credprotect
/tmp/fido-test-credprotect
