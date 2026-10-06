#!/usr/bin/env python3
"""LAB ONLY: two-phase CTAP2 test, including replug between phases.
Requires python-fido2 and cryptography. Never use a real account.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

parser = argparse.ArgumentParser(description="Test ES256 registration/assertion without browser")
parser.add_argument("mode", choices=["registrar", "autenticar"])
parser.add_argument("--file", default="credencial-lab.json")
args = parser.parse_args()
file = Path(args.file)
devices = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x303A and d.descriptor.pid == 0x4004]
if len(devices) != 1:
    raise SystemExit(f"Se esperaba una llave de laboratorio 303a:4004; encontradas {len(devices)}")
ctap = Ctap2(devices[0])
rp = "localhost"

if args.mode == "registrar":
    challenge_hash = hashlib.sha256(os.urandom(32)).digest()
    print("REGISTRO: pulsa el botón de la llave DESPUÉS de solicitarlo.", flush=True)
    response = ctap.make_credential(
        challenge_hash,
        {"id": rp, "name": "FIDO laboratorio"},
        {"id": b"lab-user", "name": "Usuario de prueba"},
        [{"type": "public-key", "alg": -7}],
        options={"rk": False},
        on_keepalive=lambda status: None,
    )
    data = response.auth_data.credential_data
    if data is None:
        raise RuntimeError("Registro sin clave pública")
    public = data.public_key
    x, y = bytes(public[-2]), bytes(public[-3])
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    assert key.key_size == 256
    payload = {"rp_id": rp, "credential_id": data.credential_id.hex(), "x": x.hex(), "y": y.hex(), "sign_count": int(response.auth_data.counter)}
    # File contains only public information; no private key is exported.
    file.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"REGISTRO OK: {file} (solo datos públicos). Desconecta, reconecta y ejecuta 'autenticar'.")
else:
    payload = json.loads(file.read_text())
    assert payload["rp_id"] == rp
    cred_id = bytes.fromhex(payload["credential_id"])
    x = int(payload["x"], 16)
    y = int(payload["y"], 16)
    public = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    challenge_hash = hashlib.sha256(os.urandom(32)).digest()
    print("AUTENTICACIÓN: pulsa el botón de la llave DESPUÉS de solicitarlo.", flush=True)
    assertion = ctap.get_assertion(
        rp, challenge_hash,
        allow_list=[{"type": "public-key", "id": cred_id}],
        on_keepalive=lambda status: None,
    )
    auth_data = bytes(assertion.auth_data)
    assert auth_data[:32] == hashlib.sha256(rp.encode()).digest(), "RP ID incorrecto"
    assert (auth_data[32] & 1) == 1, "Falta user presence"
    public.verify(assertion.signature, auth_data + challenge_hash, ec.ECDSA(hashes.SHA256()))
    counter = assertion.auth_data.counter
    assert counter > payload["sign_count"], "El contador no avanzó"
    payload["sign_count"] = counter
    file.write_text(json.dumps(payload, indent=2) + "\n")
    print("AUTENTICACIÓN ES256 OK: firma y RP ID verificados; contador", counter)
