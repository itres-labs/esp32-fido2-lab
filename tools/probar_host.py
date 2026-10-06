#!/usr/bin/env python3
"""Consulta dispositivos FIDO HID y getInfo (necesita python-fido2).
NO genera ni registra credenciales.
"""
try:
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
except ImportError:
    raise SystemExit('Instala la dependencia: python3 -m pip install fido2')

devices=list(CtapHidDevice.list_devices())
print(f'Dispositivos FIDO HID: {len(devices)}')
for dev in devices:
    try:
        info=Ctap2(dev).get_info()
        print('Versions:',info.versions)
        print('Options:',info.options)
        print('AAGUID:',info.aaguid.hex())
    except Exception as exc:
        print('Fallo getInfo:',repr(exc))
    finally:
        dev.close()
