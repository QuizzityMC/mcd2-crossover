import pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'helper'))
import diagnostics,diagnostic_schema
class VersionTests(unittest.TestCase):
 def test_supported_release_versions_survive(self):
  for version in ('0.1.8','0.1.8.2','0.2.0-beta.1'):
   self.assertEqual(diagnostics._app_fields({'app_version':version})['app_version'],version)
  for version in ('account-secret','0.1.8.2-token','0.1.8.2.3','0.1.8\nSECRET'):
   self.assertNotIn('app_version',diagnostics._app_fields({'app_version':version}))
 def test_only_known_build_markers_survive(self):
  prefix='diag v=1 layer=token event=start id=1 '
  self.assertEqual(diagnostic_schema.parse(prefix+'build=20261022.1')['build'],'20261022.1')
  self.assertEqual(diagnostic_schema.parse(prefix+'build=20261022.2')['build'],'20261022.2')
  self.assertNotIn('build',diagnostic_schema.parse(prefix+'build=SECRET'))
if __name__=='__main__':unittest.main()
