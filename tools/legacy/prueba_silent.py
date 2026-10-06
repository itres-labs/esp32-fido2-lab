#!/usr/bin/env python3
"""Prueba LAB ONLY de CTAP2 getAssertion(up=false) + verificación ES256 real.

Usa la credencial pública de tools/prueba_registro.py; no borra NVS ni crea
credenciales. Una petición silent lleva UP=0 aunque contiene firma real.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice


def read_counter(auth_data: bytes) -> int:
    assert len(auth_data) >= 37, "authenticatorData truncado"
    return int.from_bytes(auth_data[33:37], "big")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", default="credencial-lab.json")
    parser.add_argument("--with-touch", action="store_true", help="Prueba además UP=1 con botón")
    args = parser.parse_args()
    payload = json.loads(Path(args.file).read_text())
    rp = payload["rp_id"]
    cred = bytes.fromhex(payload["credential_id"])
    pub = ec.EllipticCurvePublicNumbers(
        int(payload["x"], 16), int(payload["y"], 16), ec.SECP256R1()
    ).public_key()
    devices = [
        d for d in CtapHidDevice.list_devices()
        if d.descriptor.vid == 0x303A and d.descriptor.pid == 0x4004
    ]
    if len(devices) != 1:
        raise SystemExit(f"Se esperaba una llave LAB 303a:4004, encontradas: {len(devices)}")
    ctap = Ctap2(devices[0])
    counter = None

    for i in range(2):
        challenge = hashlib.sha256(os.urandom(32)).digest()
        assertion = ctap.get_assertion(
            rp, challenge,
            allow_list=[{"type": "public-key", "id": cred}],
            options={"up": False},
        )
        auth_data = bytes(assertion.auth_data)
        assert auth_data[:32] == hashlib.sha256(rp.encode()).digest(), "RP ID incorrecto"
        assert (auth_data[32] & 0x01) == 0, "BUG: UP=1 sin pulsación"
        pub.verify(assertion.signature, auth_data + challenge, ec.ECDSA(hashes.SHA256()))
        now = read_counter(auth_data)
        if counter is not None:
            assert now == counter, "BUG: el preflight ha modificado el contador"
        counter = now
        print(f"Preflight {i+1}: ES256 OK, UP=0, contador={now}")

    try:
        ctap.get_assertion(
            rp, os.urandom(32),
            allow_list=[{"type": "public-key", "id": bytes([cred[0] ^ 1]) + cred[1:]}],
            options={"up": False},
        )
        raise AssertionError("BUG: se aceptó una credencial desconocida")
    except CtapError as e:
        assert int(e.code) == 0x2E, f"Error inesperado: {e}"
        print("Credencial desconocida: NO_CREDENTIALS OK")

    try:
        ctap.get_assertion(
            "rp-equivocado.local", os.urandom(32),
            allow_list=[{"type": "public-key", "id": cred}],
            options={"up": False},
        )
        raise AssertionError("BUG: se aceptó un RP ID equivocado")
    except CtapError as e:
        assert int(e.code) == 0x2E, f"Error inesperado para RP ID: {e}"
        print("RP ID equivocado: NO_CREDENTIALS OK")

    if args.with_touch:
        challenge = hashlib.sha256(os.urandom(32)).digest()
        print("Ahora, PULSA el botón para la firma UP=1.", flush=True)
        assertion = ctap.get_assertion(
            rp, challenge,
            allow_list=[{"type": "public-key", "id": cred}],
            options={"up": True},
        )
        auth_data = bytes(assertion.auth_data)
        assert (auth_data[32] & 0x01) == 1, "Falta UP=1"
        pub.verify(assertion.signature, auth_data + challenge, ec.ECDSA(hashes.SHA256()))
        now = read_counter(auth_data)
        assert now > counter, "El contador no creció tras la pulsación"
        # Mantener actualizado el contador del fichero de pruebas ya existente.
        payload["sign_count"] = now
        Path(args.file).write_text(json.dumps(payload, indent=2) + "\n")
        print(f"Firma normal ES256 OK, UP=1, contador={now}")
    print("PASS: preflight CTAP2 silencioso compatible, sin elevar presencia física")


if __name__ == "__main__":
    main()
