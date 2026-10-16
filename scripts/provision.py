#!/usr/bin/env python3
"""Run with sudo in an interactive SSH terminal. Never prints or logs passwords."""
import argparse, getpass, hashlib, http.client, json, os, re, socket, ssl, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def main():
    if os.geteuid() != 0:
        raise SystemExit('Run this helper with sudo on the VPN host.')
    parser = argparse.ArgumentParser(description='Provision local console secrets using a verified public certificate.')
    parser.add_argument('--host', required=True, help='Private SoftEther address reachable from this host')
    parser.add_argument('--tls-name', required=True, help='Server certificate name')
    parser.add_argument('--ca-file', required=True, type=Path, help='Verified public server certificate in PEM format')
    parser.add_argument('--port', type=int, default=443)
    args = parser.parse_args()
    supplied = args.ca_file.read_text()
    if 'PRIVATE KEY' in supplied or supplied.count('-----BEGIN CERTIFICATE-----') != 1:
        raise SystemExit('Supply exactly one public server certificate, without private keys.')
    pem = ssl.DER_cert_to_PEM_cert(ssl.PEM_cert_to_DER_cert(supplied))
    ctx = ssl.create_default_context(cadata=pem)
    password = getpass.getpass('Current SoftEther server administrator password: ')
    if not password or '\r' in password or '\n' in password:
        raise SystemExit('Invalid password input; no changes made.')
    connection = http.client.HTTPSConnection(args.tls_name, port=args.port, context=ctx, timeout=5)
    connection.sock = ctx.wrap_socket(socket.create_connection((args.host, args.port), timeout=5), server_hostname=args.tls_name)
    connection.request('POST','/api/',json.dumps({'jsonrpc':'2.0','id':'provision','method':'GetServerInfo','params':{}}),{'Content-Type':'application/json','X-VPNADMIN-PASSWORD':password,'X-VPNADMIN-HUBNAME':''})
    response = connection.getresponse()
    if response.status != 200:
        raise SystemExit('SoftEther authentication failed; no files changed.')
    result = json.loads(response.read(1000000))
    connection.close()
    if not isinstance(result.get('result'),dict) or not result['result'].get('ServerVersionString_str'):
        raise SystemExit('Unexpected API response; no files changed.')
    login = getpass.getpass('New console password (10 or more characters): ')
    if len(login) < 10 or login != getpass.getpass('Repeat new console password: '):
        raise SystemExit('Console passwords did not match or were too short; no files changed.')
    salt = os.urandom(16)
    hashed = hashlib.scrypt(login.encode(), salt=salt, n=16384, r=8, p=1, dklen=64).hex()
    directory = ROOT/'secrets'
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    for name, content in [('softether_password',password),('admin_hash.json',json.dumps({'salt':salt.hex(),'hash':hashed})),('softether-ca.pem',pem)]:
        fd, temporary = tempfile.mkstemp(dir=directory)
        with os.fdopen(fd,'w') as stream: stream.write(content)
        # Protected parent directory on the host; readable by the non-root container UID.
        os.chmod(temporary,0o444)
        os.replace(temporary,directory/name)
    print('Verified private API and TLS. Secret files provisioned. Console username: admin')
    print('No VPN settings changed. The new console is not started automatically.')

if __name__ == '__main__':
    try: main()
    except (ssl.SSLError, OSError, ValueError, KeyError):
        raise SystemExit('Provisioning failed. Check connectivity and TLS configuration; no secret details are displayed.')
