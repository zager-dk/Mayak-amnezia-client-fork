"""Release gate for the COMPILED APK, not the source AndroidManifest.xml.

Requires Android SDK apkanalyzer on Windows (JAVA_HOME set). Run before signing
publication feeds. A package with a Qt template Activity has a functioning UI
but cannot call the Mayak JNI Activity or create its VPN service.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile

A = '{http://schemas.android.com/apk/res/android}'


def verify(apk, manifest, version, code):
    root = ET.fromstring(manifest)
    assert root.get('package') == 'ru.mayaklight.vpn', 'Wrong install identity'
    assert root.get(A+'versionName') == version and root.get(A+'versionCode') == str(code), 'Wrong version'
    app = root.find('application')
    assert app is not None and app.get(A+'name') == 'org.amnezia.vpn.AmneziaApplication', 'Product Application missing (Qt template APK)'
    components = {e.get(A+'name'): e for e in app}
    activity = components.get('org.amnezia.vpn.AmneziaActivity')
    assert activity is not None, 'JNI Activity missing'
    assert activity.get(A+'exported') == 'true'
    assert any(e.get(A+'name') == 'android.intent.action.MAIN' for e in activity.findall('intent-filter/action'))
    assert not any(e.get(A+'name') == 'org.qtproject.qt.android.bindings.QtActivity' for e in app.findall('activity'))
    service = components.get('org.amnezia.vpn.AwgService')
    assert service is not None, 'AWG service missing'
    assert service.get(A+'permission') == 'android.permission.BIND_VPN_SERVICE'
    assert service.get(A+'process') == ':amneziaAwgService' and service.get(A+'exported') == 'false'
    # apkanalyzer resolves this compiled enum to its numeric flag (1 << 10).
    kind = service.get(A+'foregroundServiceType')
    assert kind == 'systemExempted' or int(kind or '0', 0) == 0x400
    assert any(e.get(A+'name') == 'android.net.VpnService' for e in service.findall('intent-filter/action'))
    permissions = {e.get(A+'name') for e in root.findall('uses-permission')}
    required = {'INTERNET', 'FOREGROUND_SERVICE', 'FOREGROUND_SERVICE_SYSTEM_EXEMPTED', 'REQUEST_INSTALL_PACKAGES'}
    assert {'android.permission.'+p for p in required} <= permissions, 'Required VPN/update permissions missing'
    provider = next((e for e in app.findall('provider') if e.get(A+'authorities') == 'ru.mayaklight.vpn.qtprovider'), None)
    assert provider is not None and provider.get(A+'grantUriPermissions') == 'true'
    assert 'org.amnezia.vpn.VpnRequestActivity' in components, 'VPN consent Activity missing'
    with zipfile.ZipFile(apk) as z:
        dex = b''.join(z.read(n) for n in z.namelist() if n.endswith('.dex'))
        for c in ['AmneziaActivity', 'AmneziaApplication', 'AwgService', 'AmneziaVpnService']:
            assert ('Lorg/amnezia/vpn/'+c+';').encode() in dex, 'Manifest class absent in DEX: '+c
        for method in [b'managedInspect', b'installUpdateApk', b'onManagedLifecycle']:
            assert method in dex, 'JNI bridge method absent from DEX'
        libraries = [n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
        count = 0
        for name in libraries:
            b = z.read(name)
            assert b[:5] == b'\x7fELF\x02' and name.startswith('lib/arm64-v8a/'), name
            offset = struct.unpack_from('<Q', b, 32)[0]
            size, num = struct.unpack_from('<HH', b, 54)
            for i in range(num):
                at = offset + i*size
                if struct.unpack_from('<I', b, at)[0] == 1:
                    assert struct.unpack_from('<Q', b, at+48)[0] >= 16384, name
                    count += 1
        lib = z.read('lib/arm64-v8a/libAmneziaVPN_arm64-v8a.so')
        assert version.encode() in lib and b'MayakAutoConnectRuntime' in lib
    return {'result': 'PASS', 'version': version, 'code': code,
            'compiledManifestAndDex': True, 'vpnAndUpdaterPermissions': True,
            'libraries': len(libraries), 'loadSegments16K': count,
            'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
            'physicalConnection': 'NOT VERIFIED'}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--apkanalyzer', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--version-code', type=int, required=True)
    p.add_argument('--report', type=Path, required=True)
    args = p.parse_args()
    xml = subprocess.check_output([str(args.apkanalyzer), 'manifest', 'print', str(args.apk)])
    result = verify(args.apk, xml, args.version, args.version_code)
    args.report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
