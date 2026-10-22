"""Native production-curl tests; --emit-fixture prints raw production log rows."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def build_probe(directory):
    compiler = shutil.which('clang')
    if compiler is None:
        raise RuntimeError('clang is required')
    if not (ROOT / 'src/diagnostic.inc').exists():
        raise RuntimeError('parent-provided diagnostic.inc must be present')
    binary = pathlib.Path(directory) / 'probe'
    subprocess.run([compiler, '-std=c11', '-fdeclspec', '-Wno-ignored-attributes',
                    '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(ROOT / 'tests/http_diag_probe.c'), '-o', str(binary)], check=True)
    return binary


class HTTPDiagnosticsNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = build_probe(cls.directory.name)

    def test_callbacks_and_lifecycle(self):
        run = subprocess.run([str(self.binary)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('http diagnostics native: ok', run.stdout)

    def test_emitted_fixture(self):
        run = subprocess.run([str(self.binary), '--emit-fixture'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertNotIn('SENTINEL', run.stdout)
        lines = run.stdout.splitlines()
        self.assertEqual(len(lines), 4)
        rows = []
        for line in lines:
            self.assertTrue(line.startswith('diag v=1 source=curl layer=http '))
            rows.append(dict(item.split('=', 1) for item in line.split()[1:]))
        for start, complete in (rows[:2], rows[2:]):
            self.assertEqual(start['event'], 'start')
            self.assertEqual(complete['event'], 'complete')
            for key in ('source', 'pid', 'layer', 'id'):
                self.assertEqual(start[key], complete[key])
            self.assertEqual(complete['http'], '401')
            self.assertEqual(complete['request_id'], '12345678-1234-1234-1234-123456789abc')
        self.assertNotEqual(rows[0]['id'], rows[2]['id'])
        self.assertEqual(rows[1]['error'], 'InvalidToken')
        self.assertEqual(rows[1]['response'], 'json')
        self.assertEqual(rows[3]['error'], 'BadRequest')
        self.assertEqual(rows[3]['response'], 'markup')
        self.assertIn('curl_multi_remove_handle @63', (ROOT / 'src/curl.def').read_text())
        self.assertNotIn('curl_multi_remove_handle=curl-compat', (ROOT / 'src/curl.def').read_text())


if __name__ == '__main__':
    if sys.argv[1:] == ['--emit-fixture']:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([str(build_probe(directory)), '--emit-fixture'], check=True)
    else:
        unittest.main()
