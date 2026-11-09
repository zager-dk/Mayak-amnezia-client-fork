"""Restore the product manifest AFTER auxiliary androiddeployqt.

Auxiliary deployment overwrites the template and skips copyAndroidSources.
Use its generated dependency files but render our manifest from source. Never inherit the
generic QtActivity template: it cannot bind our VPN service or invoke our JNI.
"""
import argparse
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET


def stage(source: Path, destination: Path, deployment: Path):
    manifest = source / 'AndroidManifest.xml'
    android = '{http://schemas.android.com/apk/res/android}'
    text = manifest.read_text(encoding='utf-8')
    settings = json.loads(deployment.read_text(encoding='utf-8'))
    values = {'INSERT_VERSION_NAME': settings['android-version-name'],
              'INSERT_VERSION_CODE': settings['android-version-code'],
              'INSERT_APP_NAME': 'Маяк VPN',
              'INSERT_APP_LIB_NAME': settings['application-binary']}
    for key, value in values.items():
        text = text.replace('-- %%'+key+'%% --', str(value))
    root = ET.fromstring(text)
    root.set('package', 'org.amnezia.vpn')
    sdk = ET.SubElement(root, 'uses-sdk')
    sdk.set(android+'minSdkVersion', str(settings['android-min-sdk-version']))
    sdk.set(android+'targetSdkVersion', str(settings['android-target-sdk-version']))
    app = root.find('application')
    assert app is not None and app.get(android + 'name') == '.AmneziaApplication'
    activity = next((x for x in app.findall('activity')
                     if x.get(android + 'name') == '.AmneziaActivity'), None)
    assert activity is not None
    assert any(x.get(android + 'name') == 'android.app.background_running' and
               x.get(android + 'value') == 'true'
               for x in activity.findall('meta-data')), \
        'AmneziaActivity must opt into Qt Android background event loops'
    assert any(x.get(android + 'name') == '.AwgService' for x in app.findall('service'))
    destination.mkdir(parents=True, exist_ok=True)
    ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
    ET.register_namespace('tools', 'http://schemas.android.com/tools')
    ET.ElementTree(root).write(destination / 'AndroidManifest.xml', encoding='utf-8', xml_declaration=True)
    # androiddeployqt reads the namespace from this stub; Gradle uses .kts.
    shutil.copyfile(source / 'build.gradle', destination / 'build.gradle')
    print('Product Android manifest restored after Qt auxiliary deployment')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--destination', type=Path, required=True)
    p.add_argument('--deployment', type=Path, required=True)
    a = p.parse_args()
    stage(a.source, a.destination, a.deployment)
