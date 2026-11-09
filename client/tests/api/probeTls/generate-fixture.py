"""Generate ephemeral LOCAL TEST ONLY TLS material; no CA private key is stored."""
from pathlib import Path
from datetime import datetime, timezone
from ipaddress import ip_address
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
folder=Path(sys.argv[1]);folder.mkdir(parents=True,exist_ok=True)
start=datetime(2026,1,1,tzinfo=timezone.utc);end=datetime(2036,1,1,tzinfo=timezone.utc)
ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Mayak LOCAL TEST ONLY CA')])
ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256()))
(folder/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
for kind in ['server','wrong-host']:
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 san=x509.SubjectAlternativeName([x509.IPAddress(ip_address('127.0.0.1')),x509.DNSName('localhost')] if kind=='server' else [x509.DNSName('wrong.invalid')])
 cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Mayak LOCAL TEST ONLY '+kind)])).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(san,critical=False).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256()))
 (folder/(kind+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (folder/(kind+'-key.pem')).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
