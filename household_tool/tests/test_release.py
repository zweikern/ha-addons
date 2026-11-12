"""Release regressions; all state is temporary, no real notifications."""
import json
import sqlite3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db
import reminders

APP = str(Path(__file__).resolve().parents[1] / 'app')


class DeliveryReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in [('DATA_DIR', Path(self.tmp.name)), ('DB_PATH', Path(self.tmp.name) / 'app.db')]:
            patcher = patch.object(db, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        db.create_user('owner', 'test-hash', 'admin', reminder_opt_in=True,
                       reminder_target='notify.mobile_app_owner')
        self.project = db.create_project('Test', '', 1)
        self.task = db.create_task(self.project, 'Due', '', 'open', 1, deadline='2026-11-12')

    def test_independent_processes_send_once(self):
        code = r'''
import os,time
from pathlib import Path
from datetime import datetime
import reminders
class Notifier:
 def send(self,title,message,target=None):
  root=Path(os.environ['HOUSEHOLD_DATA_DIR'])
  (root/('sent-'+str(os.getpid()))).write_text('simulated')
  time.sleep(.3)
  return True,'simulated'
reminders.run_reminder_once(datetime(2026,11,12,12),
 {'ha_reminders_enabled':True,'ha_base_url':'http://example.invalid','ha_token':'test'},Notifier())
'''
        env = dict(os.environ, HOUSEHOLD_DATA_DIR=self.tmp.name, PYTHONPATH=APP)
        workers = [subprocess.Popen([sys.executable, '-c', code], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for worker in workers:
            out, err = worker.communicate(timeout=15)
            self.assertEqual(worker.returncode, 0, out + err)
        self.assertEqual(len(list(Path(self.tmp.name).glob('sent-*'))), 1)

    def test_lease_recovery_owner_and_retry_limit(self):
        args = (self.task, 1, '2026-11-12')
        first = db.claim_reminder_delivery(*args, now=100)
        self.assertIsNotNone(first)
        self.assertIsNone(db.claim_reminder_delivery(*args, now=110))
        second = db.claim_reminder_delivery(*args, now=221)
        self.assertIsNotNone(second)
        self.assertFalse(db.set_reminder_delivery_status(*args, 'sent', claim_token=first))
        self.assertTrue(db.set_reminder_delivery_status(*args, 'failed', claim_token=second))
        third = db.claim_reminder_delivery(*args, now=222)
        self.assertIsNotNone(third)
        db.set_reminder_delivery_status(*args, 'failed', claim_token=third)
        self.assertIsNone(db.claim_reminder_delivery(*args, now=1000))

    def test_sent_claim_cannot_be_reclaimed(self):
        args = (self.task, 1, '2026-11-12')
        token = db.claim_reminder_delivery(*args, now=0)
        db.set_reminder_delivery_status(*args, 'sent', claim_token=token)
        self.assertIsNone(db.claim_reminder_delivery(*args, now=1000))

    def test_specific_recipient_path_without_payload_target(self):
        response = MagicMock()
        response.__enter__.return_value.status = 200
        settings = reminders.ReminderSettings(enabled=True, base_url='http://example.invalid', token='test')
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.return_value = response
            for name in ['alice', 'bob']:
                ok, _ = reminders.HomeAssistantNotifier(settings).send('t', 'm', f'notify.mobile_app_{name}')
                self.assertTrue(ok)
                request = factory.return_value.open.call_args.args[0]
                self.assertEqual(request.full_url, f'http://example.invalid/api/services/notify/mobile_app_{name}')
                self.assertNotIn('target', json.loads(request.data))

    def test_invalid_configuration_disables_sending(self):
        for opts in [{'reminder_time': '25:00'}, {'reminder_timeout': 'inf'},
                     {'reminder_timeout': 100}, {'reminder_max_retries': 8},
                     {'ha_base_url': 'file:///etc/passwd'}]:
            self.assertFalse(reminders.ReminderSettings.from_options(opts).valid)

    def test_automatic_creation_has_event_and_template_acl(self):
        template = db.create_task_template(1, 'Private', 'New', '', False, 'normal', [])
        task = db.create_task_from_template(self.project, template, 1)
        events = db.list_project_events(self.project)
        self.assertTrue(any(e['task_id'] == task and e['event_type'] == 'task_created' for e in events))
        db.create_user('other', 'hash', 'user')
        foreign = db.create_project('Other', '', 2)
        self.assertIsNone(db.create_task_from_template(foreign, template, 1))


class HttpReleaseTest(unittest.TestCase):
    def test_migration_from_release_schema_is_repeatable(self):
        self.run_isolated(r'''
import sqlite3
from pathlib import Path
import db
schema=Path(__import__('os').environ['RELEASE_SCHEMA']).read_text()
with sqlite3.connect(db.DB_PATH) as c:
 c.executescript(schema)
 c.execute("INSERT INTO users(username,password_hash,role) VALUES ('existing','preserved','admin')")
 c.execute("INSERT INTO projects(name,description,created_by) VALUES ('Old','Keep',1)")
 c.execute("INSERT INTO tasks(project_id,title,description,status,deadline) VALUES (1,'Old task','Keep','done','2026-12-01')")
 c.execute("INSERT INTO task_attachments(task_id,filename,mime,size,content) VALUES (1,'old.txt','text/plain',3,?)",(b'old',))
db.init_db(); db.init_db()
with db.get_connection() as c:
 assert not c.execute('PRAGMA foreign_key_check').fetchall()
 assert c.execute('SELECT password_hash FROM users').fetchone()[0]=='preserved'
 assert c.execute('SELECT status,deadline FROM tasks').fetchone()[:]==('done','2026-12-01')
 assert c.execute('SELECT content FROM task_attachments').fetchone()[0]==b'old'
 assert c.execute('SELECT reminder_target FROM users').fetchone()[0]==''
''')

    def test_search_acl_profile_and_files(self):
        code = r'''
import html,io,re,zipfile
from fastapi.testclient import TestClient
import main,db
from auth import hash_password
db.init_db()
db.create_user('owner',hash_password('test-password-123'),'admin',reminder_target='notify.mobile_app_owner')
db.create_user('member',hash_password('test-password-123'),'user',reminder_target='notify.mobile_app_member')
p=db.create_project('Release','',1)
for i in range(51): db.create_task(p,f'A&B + # Umlaute ä {i}','','open',1)
done=db.create_task(p,'Completed','','done',1)
with TestClient(main.app) as client:
 def login(name):
  page=client.get('/login'); csrf=re.search(r'name="csrf" value="([^"]+)"',page.text)[1]
  client.post('/login',data={'username':name,'password':'test-password-123','csrf':csrf})
  page=client.get('/account')
  return re.search(r'name="csrf" value="([^"]+)"',page.text)[1]
 csrf=login('owner')
 for term in ['A&B','+','#','ä']:
  page=client.get('/projects',params={'project_id':p,'q':term})
  link=html.unescape(re.search(r'href="([^"]*page=2)"',page.text)[1])
  response=client.get(link)
  assert response.request.url.params['q']==term,link
  assert len(re.findall(r'<tr id="task-',response.text))==1
 assert client.get(f'/tasks/{done}').status_code==200
 # Upload, download and ZIP retain file bytes across project changes.
 client.post('/files/folders',data={'csrf':csrf,'name':'Release files'})
 with db.get_connection() as conn:
  folder=conn.execute('SELECT id FROM fs_folders').fetchone()[0]
 response=client.post('/files/upload',data={'csrf':csrf,'parent_id':str(folder)},files={'files':('review-資料.txt',b'file-content','text/plain')})
 assert response.status_code==200
 with db.get_connection() as conn:
  row=conn.execute('SELECT id FROM fs_files').fetchone()
 file_id=row['id']
 assert client.get(f'/files/{file_id}/download').content==b'file-content'
 archive=client.get('/files/download-all')
 assert archive.status_code==200
 with zipfile.ZipFile(io.BytesIO(archive.content)) as z:
  assert any(z.read(name)==b'file-content' for name in z.namelist() if not name.endswith('/'))
 client.get('/logout'); csrf=login('member')
 assert client.get(f'/tasks/{done}',follow_redirects=False).status_code in (303,403,404)
 client.post('/account',data={'csrf':csrf,'reminder_opt_in':'1','reminder_target':'notify.mobile_app_attacker'})
 assert db.get_user_by_id(2)['reminder_target']=='notify.mobile_app_member'
 assert db.get_user_by_id(2)['reminder_opt_in']==1
 client.post('/account',data={'csrf':'forged','reminder_opt_in':'0'})
 assert db.get_user_by_id(2)['reminder_opt_in']==1
'''
        self.run_isolated(code)

    def test_scheduler_start_and_shutdown_are_controlled(self):
        self.run_isolated(r'''
import asyncio,threading,time
from unittest.mock import patch
from fastapi.testclient import TestClient
import main
entered=threading.Event()
def slow_run(**kwargs):
 entered.set()
 assert kwargs['stop_event'].wait(3), 'shutdown did not signal worker'
with patch.object(main.reminders,'run_reminder_once',slow_run):
 with TestClient(main.app) as client:
  assert entered.wait(1)
  assert client.get('/login').status_code==200
 assert main._reminder_thread is None
''')

    def run_isolated(self, code):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, HOUSEHOLD_DATA_DIR=directory, PYTHONPATH=APP,
                       RELEASE_SCHEMA=str(Path(__file__).parent / 'fixtures/schema_0_6_0.sql'))
            result = subprocess.run([sys.executable, '-W', 'error::ResourceWarning', '-c', code],
                                    env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
