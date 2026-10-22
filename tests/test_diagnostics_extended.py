"""Exporter privacy and evidence semantics, using synthetic recordings only."""
import ast
import json
import os
from pathlib import Path
import re
import sys
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helper'))
import diagnostics
import diagnostic_schema as schema


def envelope(row, pid=42, timestamp=2000000000000):
    return f'[t={timestamp} p={pid} th=7] {row}'


def diag(layer='http', event='result', fields=''):
    return f'diag v=1 layer={layer} event={event} {fields}'.rstrip()


class ExtendedDiagnosticsTests(unittest.TestCase):
    def sanitize(self, row, name='runtime.log'):
        data, _ = diagnostics.sanitize((row + '\n').encode(), name)
        return data.decode().strip()

    def test_fixed_c_vocabulary_is_preserved(self):
        source = (ROOT / 'src/diagnostic.inc').read_text()
        hosts = set(re.findall(r'\{"([a-z0-9.]+)","[a-z-]+"\}', source))
        self.assertEqual(hosts, schema.HOSTS)
        errors = set(re.findall(r'"([A-Za-z_]+)"', source.split('static const char*known[]=')[-1].split('};')[0]))
        self.assertEqual(errors, schema.ERRORS)
        for host in hosts:
            self.assertIn('host=' + host, self.sanitize(diag(fields='host=' + host)))
            self.assertIn(host, self.sanitize(host + ' 0x80004005'))
            self.assertIn('host=' + host, self.sanitize('connection curl=0 http=403 host=' + host, 'http.log'))
        for operation in schema.OPERATIONS:
            self.assertIn('operation=' + operation, self.sanitize(diag(fields='operation=' + operation)))
        for error in schema.ERRORS:
            self.assertIn('error=' + error, self.sanitize(diag(fields='error=' + error)))

    def test_optional_fields_and_envelope(self):
        row = envelope(diag('token', 'complete', 'id=12 host=profile.xboxlive.com operation=profile '
            'method=GET refresh=1 signature=absent hr=80004005 http=403 curl=-42 '
            'elapsed_ms=101 error=Forbidden error_code=-1 response=json '
            'request_id=12345678-1234-5678-9012-123456789abc retry=2 correlation=exact'))
        self.assertEqual(self.sanitize(row), row)
        self.assertEqual(self.sanitize(diag('native', 'failure', 'id=7 hr=80190193 correlation=unavailable')),
                         diag('native', 'failure', 'id=7 hr=80190193 correlation=unavailable'))

    def test_unknown_values_are_visible_without_originals(self):
        text = self.sanitize(diag(fields='host=credential.profile.xboxlive.com '
            'operation=https://private.example/path?token=SECRET error=SECRET '
            'Authorization=SECRET'))
        # Invalid field names make a row ambiguous; never export arbitrary text.
        self.assertEqual(text, '')
        text = self.sanitize(diag(fields='host=credential.profile.xboxlive.com '
            'operation=private-operation error=SECRET authorization=SECRET body=SECRET'))
        for key in ('host', 'operation', 'error'):
            self.assertIn(key + '=other', text)
            self.assertIn(key + '_unknown=1', text)
        for value in ('credential', 'private-operation', 'SECRET', 'authorization=', 'body='):
            self.assertNotIn(value, text)
        self.assertEqual(self.sanitize(text), text)
        for host in ('api.xboxlive.com', 'profile.xboxlive.com.evil', 'private.playfabapi.com',
                     'login.microsoft.com', 'https://profile.xboxlive.com/path'):
            self.assertIn('host=other', self.sanitize(diag(fields='host=' + host)))

    def test_strict_field_validation_does_not_erase_valid_failure(self):
        invalid = {'id': '-1', 'http': '600', 'curl': '2147483648', 'elapsed_ms': '-1',
                   'error_code': '1.2', 'retry': '-1', 'refresh': '2', 'signature': 'SECRET',
                   'hr': '0x80004005', 'request_id': 'SECRET', 'method': 'get',
                   'correlation': 'timestamp', 'source': 'SECRET', 'coverage': 'SECRET'}
        for key, value in invalid.items():
            with self.subTest(key=key):
                safe = self.sanitize(diag(event='failure', fields=f'{key}={value} error=Forbidden'))
                self.assertIn('event=failure', safe)
                self.assertIn('error=Forbidden', safe)
                self.assertNotIn(' ' + key + '=', safe)
        for invalid_hr in ('8000400a', 'FFFFFFFFF', 'SECRET00'):
            self.assertNotIn('hr=', self.sanitize(diag(fields='hr=' + invalid_hr)))
        for invalid_http in ('６００', '1e2', '100x', '-1'):
            self.assertNotIn('http=', self.sanitize(diag(fields='http=' + invalid_http)))
        for row in ('diag v=2 layer=http event=result', 'diag v=1 layer=SECRET event=result',
                    'diag v=1 layer=http event=SECRET', 'diag v=1 layer=http',
                    diag(fields='id=1 id=2'), diag(fields='body={"secret": "SECRET"}')):
            self.assertEqual(self.sanitize(row), '')
        self.assertEqual(self.sanitize(envelope(diag(), pid=2**32)), '')

    def test_valid_boundaries_and_native_field_order(self):
        for key, values in {
            'http': ('0', '599'), 'curl': ('-2147483648', '2147483647'),
            'hr': ('00000000', 'FFFFFFFF'), 'id': ('0', '18446744073709551615'),
            'request_id': ('absent', '12345678-ABCD-1234-ABCD-123456789ABC'),
        }.items():
            for value in values:
                self.assertIn(key + '=' + value, self.sanitize(diag(fields=key + '=' + value)))
        row = envelope('diag v=1 source=curl layer=http event=complete id=8 '
                       'host=profile.xboxlive.com operation=profile http=403 error=Forbidden')
        safe = self.sanitize(row, 'http.log')
        self.assertIn('source=curl', safe)
        self.assertIn('http=403', safe)
        self.assertTrue(safe.startswith('[t=2000000000000 p=42 th=7]'))

    def test_source_and_observer_coverage_enums(self):
        for state in schema.ENUMS['coverage']:
            row = diag(event='coverage', fields=f'hr=00000000 source=native-http coverage={state}')
            self.assertEqual(self.sanitize(row), row)
        for source in ('curl', 'native-http'):
            self.assertIn('source=' + source, self.sanitize(diag(fields='source=' + source)))

    def test_zip_end_to_end_interleaved_operations_and_synthetic_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder) / 'home'
            now = 2000000000
            self.assertFalse(diagnostics.enabled(home, now))
            self.assertFalse(diagnostics.record(home, 'launch', now=now))
            self.assertFalse(home.exists())
            diagnostics.start(home, now)
            runtime = [
                diag('token', 'start', 'id=1 host=profile.xboxlive.com operation=profile refresh=1 signature=absent'),
                diag('token', 'start', 'id=2 host=social.xboxlive.com operation=social'),
                diag('token', 'complete', 'id=2 hr=00000000 correlation=exact'),
                diag('native', 'failure', 'id=1 operation=async-status hr=80190193 correlation=unavailable'),
                diag('native', 'failure', 'id=1 operation=async-status hr=80190193 correlation=unavailable'),
                diag('http', 'coverage', 'hr=00000000 source=native-http coverage=registered'),
                diag('http', 'result', 'id=3 host=privacy.xboxlive.com operation=privacy http=200 source=native-http'),
            ]
            http = [
                diag(event='start', fields='id=1 host=profile.xboxlive.com operation=profile source=curl'),
                diag(event='start', fields='id=2 host=social.xboxlive.com operation=social source=curl'),
                diag(event='complete', fields='id=2 http=200 source=curl'),
                diag(event='complete', fields='id=1 host=profile.xboxlive.com operation=profile '
                     'method=GET hr=80190193 http=403 curl=0 error=Forbidden response=json '
                     'authorization=Bearer-SYNTHETIC-CREDENTIAL body=SYNTHETIC-BODY source=curl'),
                diag(event='start', fields='id=3 source=curl'),
                'POST https://profile.xboxlive.com/private?token=SYNTHETIC-CREDENTIAL',
                '{"access_token":"SYNTHETIC-CREDENTIAL","body":"SYNTHETIC-BODY"}',
            ]
            (home / 'runtime.log').write_text('\n'.join(envelope(row) for row in runtime))
            (home / 'http.log').write_text('\n'.join(envelope(row) for row in http))
            (home / 'session.bin').write_text('SYNTHETIC-SESSION')
            target = Path(folder) / 'export.zip'
            diagnostics.export(home, target, now + 10)
            self.assertFalse(diagnostics.enabled(home, now + 10))
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(set(archive.namelist()), {'READ ME.txt', 'manifest.json',
                    'logs/app.log', 'logs/http.log', 'logs/runtime.log'})
                blob = b'\n'.join(archive.read(name) for name in archive.namelist())
                for secret in (b'SYNTHETIC', b'private?token=', b'authorization=', b'body='):
                    self.assertNotIn(secret, blob)
                failed = archive.read('logs/http.log').decode().splitlines()[3]
                for field in ('[t=2000000000000 p=42 th=7]', 'id=1', 'host=profile.xboxlive.com',
                              'operation=profile', 'http=403', 'hr=80190193', 'error=Forbidden'):
                    self.assertIn(field, failed)
                coverage = json.loads(archive.read('manifest.json'))['diagnostic_coverage']
                self.assertEqual(coverage['uncorrelated_native_failure_observations'], 2)
                self.assertEqual(coverage['layers']['token']['missing_terminal_identities'], 1)
                self.assertEqual(coverage['layers']['http']['missing_terminal_identities'], 1)
                self.assertEqual(coverage['http_sources']['curl']['observation_rows'], 5)
                self.assertEqual(coverage['http_sources']['native-http']['observation_rows'], 1)
                self.assertEqual(coverage['http_sources']['native-http']['coverage_states'], {'registered': 1})

    def test_coverage_reports_gaps_without_timestamp_or_process_joins(self):
        rows = [envelope(diag('token', 'start', 'id=1'), pid=1),
                envelope(diag('token', 'complete', 'id=1'), pid=2),
                envelope(diag(event='coverage', fields='source=native-http coverage=module-missing')),
                envelope('Native async failure after user login 0x80004005')]
        safe, report = diagnostics.sanitize('\n'.join(rows).encode(), 'runtime.log')
        coverage = schema.coverage({'logs/runtime.log': safe}, {'runtime.log': {**report, 'input_capped': True}})
        self.assertIn('HTTP requests', coverage['missing_or_unobserved'])
        self.assertEqual(coverage['layers']['token']['missing_terminal_identities'], 1)
        self.assertEqual(coverage['uncorrelated_native_failure_observations'], 1)
        self.assertTrue(coverage['input_capped'])
        empty = schema.coverage({}, {})
        self.assertEqual(empty['missing_or_unobserved'], ['HTTP requests', 'token requests'])
        self.assertIn('timestamps never establish causation', empty['correlation'])

    def test_copy_lists_and_producer_vocabulary_contract(self):
        for path in ('scripts/install.py', 'scripts/package_release.py', 'helper/bridge.py'):
            tree = ast.parse((ROOT / path).read_text())
            literals = {node.value for node in ast.walk(tree)
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)}
            self.assertIn('diagnostic_schema.py', literals, path)
        shared = (ROOT / 'src/diagnostic.inc').read_text()
        operations = set(re.findall(r'\{"[^"\n]+","([a-z-]+)"\}', shared))
        self.assertTrue(operations)
        self.assertLessEqual(operations, schema.OPERATIONS)
        framing = (ROOT / 'src/framing.inc').read_text().split('htmlErrorHint', 1)[1].split('};', 1)[0]
        self.assertLessEqual(set(re.findall(r'\{"[^"\n]+","([A-Za-z]+)"\}', framing)), schema.ERRORS)
        observer = (ROOT / 'src/native-http-diagnostics.inc').read_text()
        names = observer.split('static const char*names[]=', 1)[1].split('};', 1)[0]
        emitted_states = set(re.findall(r'"([a-z-]+)"', names))
        self.assertLessEqual(emitted_states, schema.ENUMS['coverage'])
        # The exporter also accepts pending while older .1/.2 producers lack it.
        self.assertLessEqual(schema.ENUMS['coverage'] - emitted_states, {'pending'})

    @unittest.skipUnless(shutil.which('clang'), 'Clang required for producer/export integration')
    def test_native_http_production_rows_survive_zip_as_attempt_observations(self):
        # All fixtures and compiler outputs are private to this test. No shared
        # source/build file is patched, replaced, or restored while agents run.
        harness = r'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned long long U64;
typedef uint32_t DWORD;
typedef void *H;
#define IMP
static char output[16384];
static unsigned len(const char*s){return s?strlen(s):0;}
static void append(char*b,unsigned cap,const char*s){unsigned n=strlen(b);snprintf(b+n,cap-n,"%s",s?s:"");}
static unsigned dcDecimal(char*b,unsigned n,U64 v){return n+sprintf(b+n,"%llu",v);}
static unsigned dcLogPrefix(char*b){return sprintf(b,"[t=2000000000000 p=42 th=7] ");}
static int dcLogging(void){return 1;}
static int dcPath(char*b,unsigned cap,const char*leaf){return 1;}
static H CreateFileA(const char*a,DWORD b,DWORD c,void*d,DWORD e,DWORD f,H g){return (H)1;}
static int WriteFile(H h,const void*b,DWORD n,DWORD*w,void*x){strncat(output,b,n);*w=n;return 1;}
static int CloseHandle(H h){return 1;}
/* This fixture invokes only result serialization; scheduling is covered by
 * the observer harness. Never execute a worker inline to fake deferral. */
static H CreateThread(void*a,U64 n,DWORD(*f)(void*),void*c,DWORD flags,DWORD*id){return 0;}
static U64 GetTickCount64(void){return 0;}
static void AcquireSRWLockExclusive(void*p){}
static void ReleaseSRWLockExclusive(void*p){}
H GetModuleHandleA(const char*p){return 0;}
void* GetProcAddress(H h,const char*p){return 0;}
#include "runtime-diagnostics.inc"
#include "native-http-diagnostics.inc"
static U64 getId(void*c){return 99;}
static int getUrl(void*c,const char**method,const char**url){*method="GET";*url="https://profile.xboxlive.com/users/PRIVATE?token=SYNTHETIC";return 0;}
static int getStatus(void*c,unsigned*s){*s=403;return 0;}
static int getNetwork(void*c,int*h,unsigned*p){*h=0;*p=0x80000000U;return 0;}
static const char body[]="{\"error\":\"Forbidden\",\"token\":\"SYNTHETIC\"}";
static int getSize(void*c,U64*n){*n=strlen(body);return 0;}
static int getBytes(void*c,U64 n,unsigned char*b,U64*used){*used=strlen(body);memcpy(b,body,*used);return 0;}
static int getHeader(void*c,const char*n,const char**v){*v="12345678-1234-5678-9012-123456789abc";return 0;}
int main(void){
 nativeHttpApi.id=getId;nativeHttpApi.url=getUrl;nativeHttpApi.status=getStatus;
 nativeHttpApi.network=getNetwork;nativeHttpApi.bodySize=getSize;
 nativeHttpApi.bodyBytes=getBytes;nativeHttpApi.header=getHeader;
 nativeHttpCoverageRow(1,0);
 nativeHttpResult((void*)1,0);nativeHttpResult((void*)1,0);
 nativeFailure((int)0x80190193U);nativeFailure((int)0x80190193U);
 fputs(output,stdout);return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'probe.c'
            source.write_text(harness)
            binary = root / 'probe'
            subprocess.run(['clang', '-std=c11', '-fsanitize=address,undefined',
                            '-I', str(ROOT / 'src'), str(source), '-o', str(binary)],
                           check=True, capture_output=True)
            emitted = subprocess.run([str(binary)], check=True, capture_output=True).stdout
            home = root / 'home'
            home.mkdir()
            (home / 'runtime.log').write_bytes(emitted)
            target = root / 'export.zip'
            diagnostics.export(home, target, 2000000010)
            with zipfile.ZipFile(target) as archive:
                safe = archive.read('logs/runtime.log').decode()
                self.assertNotIn('PRIVATE', safe)
                self.assertNotIn('SYNTHETIC', safe)
                rows = [schema.parse(schema.ENVELOPE.sub('', line)) for line in safe.splitlines()]
                http = [row for row in rows if row['event'] == 'result']
                self.assertEqual(len(http), 2)
                self.assertEqual([row['retry'] for row in http], ['0', '1'])
                for row in http:
                    self.assertEqual(row['id'], '99')
                    self.assertEqual(row['source'], 'native-http')
                    self.assertEqual(row['hr'], '00000000')
                    self.assertEqual(row['http'], '403')
                    self.assertEqual(row['error_code'], '-2147483648')
                    self.assertEqual(row['error'], 'Forbidden')
                    self.assertEqual(row['response'], 'json')
                coverage = json.loads(archive.read('manifest.json'))['diagnostic_coverage']
                self.assertEqual(coverage['layers']['http']['terminal_rows'], 2)
                self.assertEqual(coverage['http_sources']['native-http']['events'], {'coverage': 1, 'result': 2})
                self.assertEqual(coverage['uncorrelated_native_failure_observations'], 2)
                self.assertEqual(coverage['layers']['token']['status'], 'unobserved')
                self.assertIn('not final requests', coverage['field_semantics']['terminal_rows'])
                self.assertIn('not an authoritative retry count', coverage['field_semantics']['native_http_retry'])

    def test_pending_and_historical_registered_do_not_imply_http_capture(self):
        for build in ('20261022.1', '20261022.2'):
            for states in (('pending',), ('registered',), ('pending', 'registered', 'registered')):
                with self.subTest(build=build, states=states), tempfile.TemporaryDirectory() as folder:
                    home = Path(folder) / 'home'
                    home.mkdir()
                    rows = [envelope(diag(event='coverage', fields=
                            f'source=native-http coverage={state} hr=00000000 build={build}'))
                            for state in states]
                    (home / 'runtime.log').write_text('\n'.join(rows))
                    target = Path(folder) / 'report.zip'
                    diagnostics.export(home, target, 2000000010)
                    with zipfile.ZipFile(target) as archive:
                        safe = archive.read('logs/runtime.log').decode()
                        self.assertEqual(len(safe.splitlines()), len(states))
                        self.assertIn('build=' + build, safe)
                        if 'pending' in states:
                            self.assertIn('coverage=pending', safe)
                        coverage = json.loads(archive.read('manifest.json'))['diagnostic_coverage']
                        native = coverage['http_sources']['native-http']
                        self.assertEqual(native['coverage_states'], {state: states.count(state) for state in states})
                        self.assertEqual(native['status'], 'unobserved')
                        self.assertEqual(native['observation_rows'], 0)
                        self.assertIn('HTTP requests', coverage['missing_or_unobserved'])
                        self.assertEqual(coverage['capture_completeness'], 'unknown')
                        self.assertIn('miss the first request', coverage['field_semantics']['coverage_pending'])
                        self.assertIn('teardown/reinitialization', coverage['field_semantics']['coverage_states'])

    def test_new_recording_does_not_inherit_suppressed_registration_state(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder) / 'home'
            now = 2000000000
            diagnostics.start(home, now)
            old = envelope(diag(event='coverage', fields=
                'source=native-http coverage=registered hr=00000000 build=20261022.1'))
            (home / 'runtime.log').write_text(old + '\n')
            diagnostics.start(home, now + 10)
            self.assertFalse((home / 'runtime.log').exists())
            self.assertEqual(next((home / 'recordings').glob('*/runtime.log')).read_text(), old + '\n')
            # A still-running producer can suppress an unchanged coverage state.
            # An observed callback is evidence only of that callback.
            (home / 'runtime.log').write_text(envelope(diag(fields=
                'source=native-http id=8 http=403 hr=00000000 retry=1 build=20261022.2'),
                timestamp=(now + 11) * 1000) + '\n')
            target = Path(folder) / 'new.zip'
            diagnostics.export(home, target, now + 12)
            with zipfile.ZipFile(target) as archive:
                self.assertNotIn('coverage=registered', archive.read('logs/runtime.log').decode())
                coverage = json.loads(archive.read('manifest.json'))['diagnostic_coverage']
                native = coverage['http_sources']['native-http']
                self.assertEqual(native['coverage_states'], {})
                self.assertEqual(native['status'], 'observed')
                self.assertEqual(coverage['capture_completeness'], 'unknown')
                self.assertIn('partial even after registered', coverage['limitations'])
                self.assertIn('Producer suppression', coverage['field_semantics']['recording_coverage'])

    def test_internal_error_file_time_does_not_assert_current_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder) / 'home'
            now = 2000000000
            diagnostics.start(home, now)
            path = home / 'internal-error.json'
            path.write_text('{"code":3004,"timestamp":2000000000,"token":"SYNTHETIC"}')
            os.utime(path, (now - 86400, now - 86400))
            target = Path(folder) / 'report.zip'
            diagnostics.export(home, target, now + 10)
            with zipfile.ZipFile(target) as archive:
                report = json.loads(archive.read('internal-error.json'))
                self.assertEqual(report['code'], 3004)
                context = report['time_context']
                self.assertEqual(context['modified_unix_seconds'], now - 86400)
                self.assertEqual(context['recording_relation'], 'predates_recording')
                self.assertEqual(context['freshness'], 'unverified')
                self.assertNotIn('timestamp', report)
            os.utime(path, (now + 100, now + 100))
            context = diagnostics._internal_error_report(home, now)['time_context']
            self.assertEqual(context['recording_relation'], 'after_export_clock')
            self.assertEqual(context['freshness'], 'unverified')


if __name__ == '__main__':
    unittest.main()
