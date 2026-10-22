"""Run the actual observer against stub official DLL APIs, never a game."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def compile_probe(binary, restore_init_hook=False):
    # Compile the actual production initializer too. Extract its complete body
    # verbatim, avoiding a hand-written test replica that could miss init hooks.
    runtime = (ROOT / 'src/runtime.c').read_text()
    initializer = runtime[runtime.index('int InitializeApiImplEx2('):
                          runtime.index('int InitializeApiImpl(')]
    if restore_init_hook:
        # Negative control: reinstate the exact unsafe integration point.
        initializer = initializer.replace('loghr("Native runtime initialization",r);',
            'loghr("Native runtime initialization",r);if(r>=0)nativeHttpObserve();')
    include = pathlib.Path(binary).parent / 'runtime_initializer.inc'
    unload = runtime[runtime.index('int DllCanUnloadNow('):runtime.index('void XErrorReport(')]
    include.write_text(initializer + '\n' + unload)
    subprocess.run([
        shutil.which('clang') or 'clang', '-std=c11', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra',
        '-Wno-unused-function', '-g', '-pthread',
        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
        '-DNATIVE_HTTP_RUNTIME_INIT_INCLUDE="' + str(include) + '"',
        str(ROOT / 'tests/native_http_diag_probe.c'), '-o', str(binary),
    ], check=True)


class NativeHTTPObserver(unittest.TestCase):
    def test_regression_rejects_restored_init_hook(self):
        with tempfile.TemporaryDirectory(prefix='native-http-negative-') as tmp:
            binary = pathlib.Path(tmp) / 'probe'
            compile_probe(binary, restore_init_hook=True)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('!threadCreates&&!addCalls&&!lookupCalls', run.stderr)

    def test_windows_freestanding_abi(self):
        compiler = shutil.which('clang')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='native-http-abi-') as tmp:
            obj = pathlib.Path(tmp) / 'probe.obj'
            subprocess.run([
                compiler, '--target=x86_64-pc-windows-msvc', '-std=c11', '-O1',
                '-fno-stack-protector', '-fno-builtin', '-Wall', '-Wextra',
                '-Werror', '-Wno-unused-function', '-c',
                str(ROOT / 'tests/native_http_windows_probe.c'), '-o', str(obj),
            ], check=True)
            symbols = subprocess.run(['objdump', '-t', str(obj)], capture_output=True,
                                     text=True, check=True).stdout
            self.assertNotIn('memcpy', symbols)
            self.assertNotIn('memmove', symbols)
            self.assertIn('GetModuleHandleA', symbols)
            self.assertIn('CreateThread', symbols)
            self.assertNotIn('Sleep', symbols)
            self.assertNotIn('WaitFor', symbols)
            self.assertNotIn('LoadLibraryA', symbols)
            self.assertNotIn('VirtualProtect', symbols)

    def test_production_include(self):
        compiler = shutil.which('clang')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='native-http-observer-') as tmp:
            binary = pathlib.Path(tmp) / 'probe'
            compile_probe(binary)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('native HTTP routed diagnostics: ok', run.stdout)
            fixture = subprocess.run([str(binary), '--emit-fixture'], capture_output=True,
                                     text=True, check=True, timeout=10)
            rows = fixture.stdout.splitlines()
            self.assertEqual(len(rows), 4)
            self.assertIn('coverage=pending hr=00000000', rows[0])
            self.assertIn('coverage=registered hr=00000000', rows[1])
            self.assertIn('http=401', rows[2])
            self.assertIn('retry=0 correlation=exact', rows[2])
            self.assertIn('retry=1 correlation=exact', rows[3])
            self.assertTrue(all('source=native-http' in row for row in rows))


if __name__ == '__main__':
    if sys.argv[1:] == ['--emit-fixture']:
        with tempfile.TemporaryDirectory(prefix='native-http-fixture-') as tmp:
            binary = pathlib.Path(tmp) / 'probe'
            compile_probe(binary)
            subprocess.run([str(binary), '--emit-fixture'], check=True, timeout=10)
    else:
        unittest.main()
