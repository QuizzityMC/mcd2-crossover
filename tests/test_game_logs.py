import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from test_diagnostics import diagnostics

class GameLogs(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.home=self.root/'support';self.home.mkdir()
        (self.home/'settings.json').write_text(json.dumps({'bottle':'Selected'}))
        self.folder=self.root/'Library/Application Support/CrossOver/Bottles/Selected/drive_c/users/crossover/AppData/Local/Dungeons2/Saved/Logs'
        self.folder.mkdir(parents=True)
        self.patch=patch.object(diagnostics.Path,'home',return_value=self.root);self.patch.start()
    def tearDown(self):
        self.patch.stop();self.tmp.cleanup()
    def test_game_only_zip_and_status_without_recording(self):
        cef='[1018/161610.934:ERROR:gpu_init.cc(426)] Passthrough is not supported, GL is disabled\n'
        (self.folder/'cef3.log').write_text(cef)
        (self.folder/'save.dat').write_text('private save')
        other=Path(str(self.folder).replace('/Selected/','/Other/'));other.mkdir(parents=True)
        (other/'cef3.log').write_text('other bottle secret')
        self.assertTrue(diagnostics.status(self.home)['available'])
        output=self.root/'export.zip';diagnostics.export(self.home,output)
        with zipfile.ZipFile(output) as z:
            self.assertEqual(z.read('game-logs/log-01.log').decode(),cef)
            self.assertEqual(json.loads(z.read('manifest.json'))['game_logs']['files'][0]['kind'],'cef')
            data=b''.join(z.read(n) for n in z.namelist())
            self.assertNotIn(b'private save',data);self.assertNotIn(b'other bottle secret',data)
    def test_redaction(self):
        data=b'LogAuth: token=secret\nLogInit: User: private-person\nLogFile: C:\\Users\\private-person\\x.txt\nEmail a@example.com\nGET https://example.com/?secret=x\nERROR: timeout 50 ms\n'
        safe,omitted=diagnostics._sanitize_game_log(data)
        self.assertEqual(omitted,3)
        for secret in (b'secret',b'private-person',b'a@example.com'):self.assertNotIn(secret,safe)
        self.assertIn(b'ERROR: timeout 50 ms',safe)
    def test_caps_and_symlink_file(self):
        outside=self.root/'outside.log';outside.write_text('private value')
        (self.folder/'linked.log').symlink_to(outside)
        for i in range(5):(self.folder/f'game{i}.log').write_bytes(b'old row\n'*40000+b'ERROR: recent end\n')
        entries,report=diagnostics._game_log_entries({'bottle':'Selected'})
        self.assertEqual(len(entries),4);self.assertEqual(report['skipped_files'],1)
        self.assertTrue(all(x['input_capped'] for x in report['files']))
        self.assertTrue(all(v.endswith(b'ERROR: recent end\n') and len(v)<=diagnostics.MAX_LOG_BYTES for v in entries.values()))
    def test_symlink_directory_and_invalid_bottle(self):
        outside=self.root/'external';outside.mkdir();(outside/'cef3.log').write_text('private value')
        self.folder.rmdir();self.folder.symlink_to(outside,target_is_directory=True)
        entries,report=diagnostics._game_log_entries({'bottle':'Selected'})
        self.assertFalse(entries);self.assertEqual(report['status'],'missing')
        self.assertFalse(diagnostics._game_log_entries({'bottle':'../external'})[0])
