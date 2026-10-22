import pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class TokenDiagnosticTests(unittest.TestCase):
 def test_production_provider_lifecycle(self):
  with tempfile.TemporaryDirectory() as tmp:
   exe=pathlib.Path(tmp)/'probe'
   p=subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined',str(ROOT/'tests/token_diagnostics_probe.c'),'-o',str(exe)],capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stderr)
   p=subprocess.run([str(exe)],capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stdout+p.stderr)
if __name__=='__main__':unittest.main()
