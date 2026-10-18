import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'helper'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import runtime_capture as r
import diagnostics as d
from bounded_capture import capture

class RuntimeTests(unittest.TestCase):
 def test_partial_stack_is_kept_on_deadline(self):
  raw='{"identity_verified":1,"threads":[{"tid":7,"suspend_count":1,"windows_stack":[{"pc":123}]},{"tid":8'
  source='import sys,time;sys.stdout.write('+repr(raw)+');sys.stdout.flush();time.sleep(30)'
  result=capture([sys.executable,'-u','-c',source],timeout=.3)
  self.assertFalse(result['report_complete'])
  self.assertTrue(result['report']['partial'])
  self.assertEqual(result['report']['threads'],[{'tid':7,'suspend_count':1,'windows_stack':[{'pc':123}]}])
 def test_export_revalidates_runtime_and_includes_game_logs(self):
  with tempfile.TemporaryDirectory() as temp:
   home=Path(temp)/'home';home.mkdir()
   report={'schema':1,'status':'context_incomplete','selection':{'report':{'processes':[{'pid':5,'role':'winedbg.exe','command':'secret'}]}},'baseline':{'report':{'debugger_present':1,'threads':[{'tid':3,'suspend_count':0,'account':'secret'}]}},'context':{'stop_reason':'deadline','last_phase':{'phase':'thread_context','tid':3},'report':{'partial':True,'threads':[{'tid':2,'windows_stack':[{'pc':123,'start_module':'ntdll.dll','start_rva':10,'secret':'secret'}]}]}}}
   (home/'freeze-runtime.json').write_text(json.dumps(report))
   # The recording toggle was never enabled.
   with patch.object(d,'_game_log_entries',return_value=({'game-logs/log-01.log':b'cef diagnostic\n'},{'status':'included'})):
    target=Path(temp)/'support.zip';d.export(home,target)
   with zipfile.ZipFile(target) as z:
    doc=json.loads(z.read('freeze-runtime.json'))
    self.assertEqual(doc['baseline']['report']['debugger_present'],1)
    self.assertEqual(doc['context']['last_phase']['tid'],3)
    self.assertIn('game-logs/log-01.log',z.namelist())
    self.assertNotIn('secret',z.read('freeze-runtime.json').decode())
 def test_malformed_nested_fields_are_rejected(self):
  doc=r.safe_report({'status':'captured','baseline':{'report':{'threads':[{'tid':True,'suspend_count':'1','start_module':'private.dll','windows_stack':'private'}]}}})
  self.assertEqual(doc['baseline']['report']['threads'],[{}])
 def test_saved_report_does_not_follow_symlink(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);(root/'elsewhere').write_text('{"status":"captured"}');(root/'freeze-runtime.json').symlink_to(root/'elsewhere')
   self.assertIsNone(r.saved_report(root))
 def test_failed_context_launch_keeps_baseline(self):
  with tempfile.TemporaryDirectory() as temp:
   home=Path(temp)
   def fail(wine,probes,expected,output,timeout,initial=None):
    Path(output).write_text(json.dumps({'status':'capturing_context','baseline':{'report':{'threads':[{'tid':4,'suspend_count':1}]}}}))
    raise subprocess.TimeoutExpired('observer',10)
   with patch('capture_selected.capture_selected',side_effect=fail),patch('crossover.wine',return_value='wine'):
    result=r.capture(home,home/'game.exe',home/'bottle')
   self.assertEqual(result['status'],'capture_failed')
   self.assertEqual(result['baseline']['report']['threads'][0]['tid'],4)

if __name__=='__main__':unittest.main()
