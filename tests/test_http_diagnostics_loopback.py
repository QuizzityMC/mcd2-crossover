"""Independent macOS HTTPS integration test; no game, account, or remote service.

Run: python3 tests/test_http_diagnostics_loopback.py
Export exact production rows: add --records-output /path/to/http.log
Or --emit-fixture to print only those rows to stdout (test report stays on stderr).
All keys, certificates, binaries and received bodies live in a private temporary
folder. No system trust settings are modified. Requires clang and openssl.
"""
import argparse
import contextlib
import http.server
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
UUID = '12345678-1234-1234-1234-123456789abc'
BODY = (b'{"error":"InvalidSignature","token":"TOKEN_SENTINEL",'
        b'"account":"ACCOUNT_SENTINEL","credential":"CREDENTIAL_SENTINEL",'
        b'"unicode":"\xe2\x98\x83"}\n')
RECORDS_OUTPUT = None
EMIT_FIXTURE = False


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=45, **kwargs)


def build_probe(directory):
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('clang is required')
    # Separate translation unit avoids curl.h conflicting with production exports.
    constants = {'CURLOPT_CONNECT_TO': 10243, 'CURLOPT_PROXY': 10004,
                 'CURLOPT_NOPROXY': 10177, 'CURLOPT_FOLLOWLOCATION': 52,
                 'CURLOPT_NOSIGNAL': 99, 'CURLOPT_CONNECTTIMEOUT_MS': 156,
                 'CURLOPT_TIMEOUT_MS': 155, 'CURLOPT_HTTPHEADER': 10023,
                 'CURLOPT_WRITEFUNCTION': 20011, 'CURLOPT_WRITEDATA': 10001,
                 'CURLOPT_URL': 10002, 'CURLE_PEER_FAILED_VERIFICATION': 60}
    source = '#include <curl/curl.h>\n' + '\n'.join(
        f'_Static_assert({key} == {value}, "{key}");' for key, value in constants.items())
    command([compiler, '-std=c11', '-x', 'c', '-fsyntax-only', '-'],
            input=source.encode())
    binary = directory / 'loopback-probe'
    command([compiler, '-std=c11', '-fdeclspec', '-Wno-ignored-attributes',
             '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
             str(ROOT / 'tests/http_diag_loopback.c'), '-o', str(binary)])
    return binary


def certificates(directory):
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('openssl is required')

    def run(*args):
        command([openssl, *args], cwd=directory)

    (directory / 'ca.cnf').write_text('''[req]
prompt = no
distinguished_name = dn
x509_extensions = ca
[dn]
CN = Synthetic loopback test CA
[ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
''')
    for name in ('trusted', 'untrusted'):
        run('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-config', 'ca.cnf', '-keyout', f'{name}.key', '-out', f'{name}.pem')
    for name, host in (('valid', 'profile.xboxlive.com'), ('wrong', 'wrong.invalid')):
        (directory / f'{name}.cnf').write_text(f'''[req]
prompt = no
distinguished_name = dn
req_extensions = server
[dn]
CN = {host}
[server]
subjectAltName = DNS:{host}
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
''')
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', f'{name}.cnf',
            '-keyout', f'{name}.key', '-out', f'{name}.csr')
        run('x509', '-req', '-in', f'{name}.csr', '-CA', 'trusted.pem',
            '-CAkey', 'trusted.key', '-set_serial', '1' if name == 'valid' else '2',
            '-days', '1', '-extfile', f'{name}.cnf', '-extensions', 'server',
            '-out', f'{name}.pem')


@contextlib.contextmanager
def server(directory, certificate, status):
    requests = []
    sni = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(BODY)))
            self.send_header('X-Request-Id', UUID)
            self.send_header('Set-Cookie', 'private=RESPONSE_COOKIE_SENTINEL')
            self.end_headers()
            # Distinct writes exercise real transport; assertions do not assume
            # any particular TLS record or libcurl callback chunk boundaries.
            self.wfile.write(BODY[:31])
            self.wfile.flush()
            self.wfile.write(BODY[31:])

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / f'{certificate}.pem', directory / f'{certificate}.key')
    context.set_servername_callback(lambda sock, name, ctx: sni.append(name))
    httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_port, requests, sni
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('loopback server failed to stop')


@unittest.skipUnless(sys.platform == 'darwin', 'requires real macOS libcurl')
class HTTPDiagnosticsLoopback(unittest.TestCase):
    def test_real_https_and_verification(self):
        exported = []
        with tempfile.TemporaryDirectory(prefix='http-diag-loopback-') as temporary:
            directory = pathlib.Path(temporary)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            binary = build_probe(directory)
            certificates(directory)
            cases = [('401', 'valid', 'trusted', 401, 0),
                     ('200', 'valid', 'trusted', 200, 0),
                     ('wrong-host', 'wrong', 'trusted', 401, 60),
                     ('untrusted', 'valid', 'untrusted', 401, 60)]
            for label, certificate, ca, status, code in cases:
                with self.subTest(case=label):
                    sink = directory / f'{label}.body'
                    # Poison proxy settings to prove explicit options win.
                    env = dict(os.environ, HTTPS_PROXY='http://127.0.0.1:1',
                               ALL_PROXY='http://127.0.0.1:1',
                               https_proxy='http://127.0.0.1:1',
                               all_proxy='http://127.0.0.1:1', NO_PROXY='', no_proxy='')
                    with server(directory, certificate, status) as (port, requests, sni):
                        run = subprocess.run([str(binary), str(directory / f'{ca}.pem'),
                                              str(port), str(code), str(sink)],
                                             capture_output=True, env=env, timeout=20)
                    self.assertEqual(run.returncode, 0, run.stderr.decode(errors='replace'))
                    self.assertEqual(run.stderr, b'', 'unexpected sanitizer/runtime diagnostics')
                    self.assertEqual(sni, ['profile.xboxlive.com'])
                    self.assertEqual(sink.read_bytes(), BODY if code == 0 else b'')
                    self.assertEqual(len(requests), 0 if code else 1)
                    if not code:
                        path, headers = requests[0]
                        self.assertEqual(path, '/test?token=SYNTHETIC_SECRET')
                        self.assertEqual(headers['Host'], 'profile.xboxlive.com')
                        self.assertEqual(headers['Authorization'], 'Bearer AUTH_SENTINEL')
                        self.assertEqual(headers['Cookie'], 'session=COOKIE_SENTINEL')
                    logs = run.stdout.decode('ascii')
                    for forbidden in ('SENTINEL', 'SYNTHETIC_SECRET', 'token=', '/test',
                                      'Authorization:', 'Bearer ', 'Set-Cookie:', temporary):
                        self.assertNotIn(forbidden, logs)
                    lines = [line for line in logs.splitlines(keepends=True)
                             if line.startswith('diag ')]
                    self.assertEqual(len(lines), 2)
                    rows = [dict(field.split('=', 1) for field in line.split()[1:])
                            for line in lines]
                    start, complete = rows
                    self.assertEqual(start['event'], 'start')
                    self.assertEqual(complete['event'], 'complete')
                    for key in ('source', 'layer', 'id', 'pid'):
                        self.assertEqual(start[key], complete[key])
                    self.assertGreater(int(start['id']), 0)
                    for row in rows:
                        for key, value in {'v': '1', 'source': 'curl', 'layer': 'http',
                                           'host': 'profile.xboxlive.com', 'operation': 'profile',
                                           'method': 'GET', 'retry': '0', 'correlation': 'exact'}.items():
                            self.assertEqual(row[key], value)
                        self.assertGreater(int(row['pid']), 0)
                        self.assertGreaterEqual(int(row['elapsed_ms']), 0)
                    self.assertEqual(complete['http'], '0' if code else str(status))
                    self.assertEqual(complete['curl'], str(code))
                    self.assertEqual(complete['error'], 'InvalidSignature' if status == 401 and not code else 'none')
                    # TLS rejection happens before any HTTP response can be observed.
                    self.assertEqual(complete['response'], 'unobserved' if code else 'json')
                    self.assertEqual(complete['request_id'], 'absent' if code else UUID)
                    exported.extend(lines)
        # Publish only after all four cases passed; preserve original CRLF bytes.
        if len(exported) == 8:
            raw = ''.join(exported).encode('ascii')
            if RECORDS_OUTPUT:
                fd = os.open(RECORDS_OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(raw)
            if EMIT_FIXTURE:
                sys.stdout.buffer.write(raw)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records-output', type=pathlib.Path,
                        help='write exact rows to a new private file (never overwrite)')
    parser.add_argument('--emit-fixture', action='store_true')
    options, remaining = parser.parse_known_args()
    RECORDS_OUTPUT, EMIT_FIXTURE = options.records_output, options.emit_fixture
    unittest.main(argv=[sys.argv[0], *remaining])
