import json
import threading
import tempfile
import sys
import os
import subprocess
from unittest.mock import patch
from contextlib import redirect_stderr
import io
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import run


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.old_engine, self.old_settings = run.ENGINE, run.SETTINGS
        self.settings_dir = tempfile.TemporaryDirectory()
        run.ENGINE = run.SimEngine()
        run.SETTINGS = Path(self.settings_dir.name) / 'controller_settings.json'

    def tearDown(self):
        run.ENGINE, run.SETTINGS = self.old_engine, self.old_settings
        self.settings_dir.cleanup()

    @classmethod
    def setUpClass(cls):
        cls.server=run.LocalHTTPServer(('127.0.0.1',0),run.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.port=cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method,path,payload=None,content_type='application/json'):
        client=HTTPConnection('127.0.0.1',self.port,timeout=5)
        data=json.dumps(payload).encode() if payload is not None else None
        client.request(method,path,body=data,headers={'Content-Type':content_type})
        r=client.getresponse()
        body=r.read(); status=r.status; ctype=r.getheader('Content-Type')
        client.close()
        return status,body,ctype

    def test_static_assets(self):
        for path in ['/','/styles.css','/app.js']:
            status,body,ctype=self.request('GET',path)
            self.assertEqual(status,200)
            self.assertGreater(len(body),100)

    def test_live_state_contract(self):
        status,body,_=self.request('GET','/api/state')
        self.assertEqual(status,200)
        state=json.loads(body)
        for key in ['vehicles','rsus','rules','runtime_policies','history','stats','events','mobility_mode']:
            self.assertIn(key,state)

    def test_scenario_and_report_export(self):
        status,body,_=self.request('POST','/api/scenario',{'scenario':'combined','attacker':'V07','victim':'V02'})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['scenario'],'combined')
        status,body,ctype=self.request('GET','/api/report')
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['metadata']['mode'],'simulation')

    def test_rule_post_and_toggle(self):
        data={'label':'API rule','source':'V07','traffic':'UDP_FLOOD','rsu':'*',
              'priority':950,'action':'DROP','enabled':True}
        status,body,_=self.request('POST','/api/rules',data)
        self.assertEqual(status,200)
        rid=next(r['id'] for r in json.loads(body)['rules'] if r['label']=='API rule')
        status,body,_=self.request('POST',f'/api/rules/{rid}/toggle',{})
        self.assertEqual(status,200)
        r=next(r for r in json.loads(body)['rules'] if r['id']==rid)
        self.assertFalse(r['enabled'])
        self.request('POST','/api/rules-delete',{'id':rid})

    def test_error_paths(self):
        status,body,_=self.request('POST','/api/config',{'base_pps':-123})
        self.assertEqual(status,400)
        status,body,_=self.request('GET','/api/unknown')
        self.assertEqual(status,404)
        status,body,_=self.request('POST','/api/run',{'running':'maybe'})
        self.assertEqual(status,400)

    def test_unsupported_mobility_mode(self):
        status,body,_=self.request('POST','/api/mobility',{'mode':'spaceflight'})
        self.assertEqual(status,400)

    def test_rejected_updates_leave_state_and_profile_unchanged(self):
        initial = run.ENGINE.status()
        status, _, _ = self.request('POST', '/api/config', {'base_pps': 150, 'bogus': 1})
        self.assertEqual(status, 400)
        self.assertEqual(run.ENGINE.config, initial['config'])
        status, _, _ = self.request('POST', '/api/scenario',
                                    {'scenario': 'flood', 'attacker': 'V02'})
        self.assertEqual(status, 400)
        self.assertEqual(run.ENGINE.attacker, initial['attacker'])
        self.assertFalse(run.SETTINGS.exists())

    def test_concurrent_changes_persist_one_complete_snapshot(self):
        with ThreadPoolExecutor(max_workers=5) as pool:
            responses = list(pool.map(lambda i: self.request('POST', '/api/rules', {
                'label': f'Concurrent {i}', 'source': 'V07', 'action': 'DROP',
                'traffic': 'UDP_FLOOD', 'priority': 500, 'enabled': True}), range(10)))
        self.assertTrue(all(status == 200 for status, _, _ in responses))
        profile = json.loads(run.SETTINGS.read_text(encoding='utf-8'))
        self.assertEqual(profile['rules'], run.ENGINE.status()['rules'])
        self.assertEqual(len({r['id'] for r in profile['rules']}), 11)

    def test_worker_stops_without_advancing_after_stop(self):
        stop = threading.Event()
        stop.set()
        worker = threading.Thread(target=run.run_engine, args=(stop,))
        worker.start()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(run.ENGINE.t, 0)

    def test_busy_port_fails_main_before_starting_worker(self):
        with patch.object(sys, 'argv', ['run.py', '--no-browser', '--port', str(self.port)]), \
             patch.object(run.threading, 'Thread') as thread, \
             redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as exit_error:
                run.main()
        self.assertEqual(exit_error.exception.code, 2)
        self.assertIn('Could not start local server', error.getvalue())
        thread.assert_not_called()

    def test_launcher_forwards_options_and_uses_its_directory(self):
        launcher = (run.BASE / 'START_WINDOWS.bat').read_text()
        self.assertIn('cd /d "%~dp0"', launcher)
        self.assertIn('py -3 run.py %*', launcher)
        self.assertIn('python run.py %*', launcher)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows batch launcher')
    def test_launcher_runs_help_with_an_available_python(self):
        command_processor = os.environ.get('ComSpec', r'C:\Windows\System32\cmd.exe')
        result = subprocess.run([command_processor, '/c', str(run.BASE / 'START_WINDOWS.bat'), '--help'],
                                cwd=run.BASE.parent, input='\n', text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('MarsVanet unified visual simulator', result.stdout)
        self.assertIn('--port', result.stdout)


if __name__=='__main__': unittest.main()
