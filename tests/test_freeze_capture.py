import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'helper'));sys.path.insert(0,str(ROOT/'scripts'))
import diagnostics as d
import freeze_capture as f
from game_process import ProcessReport

SAMPLE='''Process: Dungeons [42]
Path: /Users/PrivatePerson/Game/Dungeons.exe
User ID: 501
Call graph:
    300 Thread_123 DispatchQueue_1 account@example.com
    + 300 start (in dyld) + 0 [0x1234]
    +   300 __psynch_cvwait (in libsystem_kernel.dylib) + 8 [0x4567]
    +     300 SecretAccountName (in PrivatePerson.dll) + 8 [0x7654]
    +       300 foo /Users/PrivatePerson/secret (in Metal) + 8 [0xabcd]
Total number in stack (recursive counted multiple, when >=5):
Binary Images:
secret@example.com /Users/PrivatePerson/keychain
'''

class FreezeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.home=self.root/'home';self.home.mkdir()
  self.game=self.root/'game';self.binary=self.game/'Dungeons/Binaries/Win64';self.binary.mkdir(parents=True)
  (self.binary/'Dungeons-Win64-Shipping.exe').write_bytes(b'fixture')
  (self.home/'settings.json').write_text(json.dumps(dict(game=str(self.game),binary=str(self.binary),bottle='Test')))
  self.calls=[]
 def tearDown(self):self.temp.cleanup()
 def runner(self,args,**kwargs):
  self.calls.append(args)
  if args[0]=='/usr/bin/sample':
   Path(args[-1]).write_text(SAMPLE)
   return subprocess.CompletedProcess(args,0)
  return subprocess.CompletedProcess(args,0,stdout='Fri Oct 18 12:00:00 2026' if args[-1]=='lstart=' else '14.3 102400')
 def inspect(self,*args,**kwargs):return ProcessReport((42,),(),False)
 def test_capture_before_setup_reports_missing_settings(self):
  (self.home/'settings.json').unlink()
  result=f.capture(self.home,inspect=self.inspect,run=self.runner)
  self.assertEqual(result['capture_outcome'],'settings_missing');self.assertFalse(self.calls)
 def test_malformed_saved_report_is_filtered(self):
  for frames in (None, 42, {}, 'bad'):
   self.assertEqual(f.safe_report({'outcome':'captured','frames':frames})['frames'], [])
  for key in ('module','symbol','address'):
   frame=dict(thread=1,depth=1,samples=1,module='Metal',symbol='wait',address='unknown');frame[key]=None
   self.assertEqual(f.safe_report({'outcome':'captured','frames':[frame]})['frames'], [])
 def test_capture_and_export_without_recording(self):
  result=f.capture(self.home,inspect=self.inspect,run=self.runner)
  self.assertTrue(result['ok']);self.assertEqual(result['frames'],4)
  self.assertFalse(list(self.home.glob('.freeze-*')))
  output=self.root/'report.zip';d.export(self.home,output)
  with zipfile.ZipFile(output) as z:
   report=json.loads(z.read('freeze.json'));allbytes=b'\n'.join(z.read(n) for n in z.namelist())
   self.assertEqual(report['rss_kib'],102400);self.assertEqual(report['cpu_tenths'],143)
   self.assertIn(b'__psynch_cvwait',allbytes)
   for secret in (b'PrivatePerson',b'SecretAccountName',b'account@example.com',b'/Users/',b'keychain'): self.assertNotIn(secret,z.read('freeze.json'))
  self.assertEqual([a[0] for a in self.calls],['/bin/ps','/bin/ps','/usr/bin/sample','/bin/ps'])
 def test_absent_ambiguous_and_wrong_game_are_not_sampled(self):
  for report,why in [(ProcessReport(), 'game_not_running'),(ProcessReport((42,43)), 'ambiguous_game'),(ProcessReport((42,),(),True),'ambiguous_game')]:
   self.calls.clear();r=f.capture(self.home,inspect=lambda *_:report,run=self.runner)
   self.assertFalse(r['ok']);self.assertEqual(r['capture_outcome'],why);self.assertFalse(self.calls)
 def test_identity_change_discards_sample(self):
  with patch.object(f,'sample_frames',wraps=f.sample_frames) as parse:
   reports=iter([ProcessReport((42,)),ProcessReport((43,))])
   result=f.capture(self.home,inspect=lambda *_:next(reports),run=self.runner)
   self.assertEqual(result['capture_outcome'],'process_changed');parse.assert_not_called()
 def test_timeout_removes_raw_capture_and_preserves_credentials(self):
  (self.home/'session.bin').write_bytes(b'untouched-secret')
  def run(args,**kw):
   if args[0]=='/usr/bin/sample':
    Path(args[-1]).write_text(SAMPLE);raise subprocess.TimeoutExpired(args,15)
   return self.runner(args,**kw)
  r=f.capture(self.home,inspect=self.inspect,run=run)
  self.assertEqual(r['capture_outcome'],'sample_timeout');self.assertFalse(list(self.home.glob('.freeze-*')))
  self.assertEqual((self.home/'session.bin').read_bytes(),b'untouched-secret')
 def test_denied_and_empty_sample_are_honest_failures(self):
  for code,body,outcome in [(1,SAMPLE,'sample_denied'),(0,'no frames','sample_empty')]:
   def run(args,**kw):
    if args[0]=='/usr/bin/sample':Path(args[-1]).write_text(body);return subprocess.CompletedProcess(args,code)
    return self.runner(args,**kw)
   self.assertEqual(f.capture(self.home,inspect=self.inspect,run=run)['capture_outcome'],outcome)
 def test_reexport_drops_injected_paths_and_metadata(self):
  f.capture(self.home,inspect=self.inspect,run=self.runner)
  report=json.loads((self.home/'freeze.json').read_text());report['path']='/Users/Secret';report['frames'].append({'thread':1,'depth':1,'samples':1,'symbol':'/Users/Secret','module':'Metal','address':'unknown'})
  (self.home/'freeze.json').write_text(json.dumps(report))
  output=self.root/'safe.zip';d.export(self.home,output)
  with zipfile.ZipFile(output) as z:self.assertNotIn(b'Secret',z.read('freeze.json'))
 def test_new_recording_archives_previous_capture(self):
  f.capture(self.home,inspect=self.inspect,run=self.runner);d.start(self.home)
  self.assertFalse((self.home/'freeze.json').exists());self.assertTrue(list((self.home/'recordings').glob('*/freeze.json')))
 def test_path_outside_selected_game_is_rejected(self):
  (self.home/'settings.json').write_text(json.dumps(dict(game=str(self.game),binary='/tmp',bottle='Test')))
  self.assertEqual(f.capture(self.home,inspect=self.inspect,run=self.runner)['capture_outcome'],'settings_missing');self.assertFalse(self.calls)
 def test_timing_survives_export_without_secrets(self):
  now=int(time.time());d.start(self.home,now)
  (self.home/'auth.log').write_text(json.dumps(dict(step='microsoft-refresh',timestamp_ms=now*1000,elapsed_ms=150,attempt=2,phase='completed',http_status=200,token='SECRET'))+'\n')
  (self.home/'runtime.log').write_text(f'[t={now*1000} p=42 th=91] Keychain-backed ForceRefresh result 0x00000000\n')
  (self.home/'http.log').write_text(f'[t={now*1000} p=42 th=91] request id=1 phase=completed elapsed_ms=123 curl=0 http=429\n')
  output=self.root/'timing.zip';d.export(self.home,output,now+1)
  with zipfile.ZipFile(output) as z:
   auth=json.loads(z.read('logs/auth.log'));self.assertEqual(auth['elapsed_ms'],150);self.assertEqual(auth['attempt'],2);self.assertNotIn('token',auth)
   self.assertIn(b'th=91',z.read('logs/runtime.log'));self.assertIn(b'elapsed_ms=123',z.read('logs/http.log'))
 def test_old_issue_logs_still_accepted(self):
  result,_=d.sanitize(b'Native async failure after user login 0x80190191\n','runtime.log');self.assertIn(b'0x80190191',result)
 def test_auth_observer_records_duration_and_start(self):
  import bridge
  class Response:
   status=200
   def __enter__(self):return self
   def __exit__(self,*_):pass
   def read(self,*_):return b'{"access_token":"SECRET"}'
  d.start(self.home)
  with patch.object(bridge,'HOME',self.home),patch.object(bridge.ssl,'create_default_context'),patch.object(bridge.urllib.request,'urlopen',return_value=Response()):
   bridge.post('microsoft-refresh','https://login.live.com/oauth20_token.srf',form={})
  rows=[json.loads(x) for x in (self.home/'auth.log').read_text().splitlines()]
  self.assertEqual([r['phase'] for r in rows],['started','completed']);self.assertIn('elapsed_ms',rows[1]);self.assertNotIn('SECRET',(self.home/'auth.log').read_text())
if __name__=='__main__':unittest.main()
