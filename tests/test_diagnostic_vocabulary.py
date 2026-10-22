import pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class VocabularyTests(unittest.TestCase):
 def test_actual_c_helpers_with_sanitizers(self):
  with tempfile.TemporaryDirectory() as tmp:
   exe=pathlib.Path(tmp)/'probe'
   subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined',str(ROOT/'tests/diagnostic_vocabulary_probe.c'),'-o',str(exe)],check=True,capture_output=True)
   result=subprocess.run([str(exe)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stdout+result.stderr)
if __name__=='__main__': unittest.main()
