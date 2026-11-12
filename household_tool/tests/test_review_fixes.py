import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db
import reminders


BERLIN = ZoneInfo('Europe/Berlin')


class ReviewFixTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = patch.object(db, 'DATA_DIR', Path(self.temp.name))
        self.database = patch.object(db, 'DB_PATH', Path(self.temp.name) / 'test.db')
        self.directory.start()
        self.database.start()
        self.addCleanup(self.directory.stop)
        self.addCleanup(self.database.stop)
        db.init_db()
        db.create_user('owner', 'test-hash', 'admin', reminder_opt_in=True, reminder_target='notify.mobile_app_owner')
        db.create_user('member', 'test-hash', 'user', reminder_opt_in=True, reminder_target='notify.mobile_app_member')
        db.create_user('notarget', 'test-hash', 'user', reminder_opt_in=True)
        self.project = db.create_project('Test', 'Description', 1)
        db.add_project_member(self.project, 2, 'member')
        self.options = {
            'ha_reminders_enabled': '1',
            'ha_base_url': 'http://localhost:8123',
            'ha_token': 'token',
            'reminder_time': '09:00',
            'reminder_quiet_start': '22:00',
            'reminder_quiet_end': '07:00',
            'reminder_max_retries': 3,
            'reminder_timeout': 1.0,
        }
        self.now = datetime(2026, 11, 11, 10, 0, tzinfo=BERLIN)

    def test_delete_user_with_personal_template(self):
        db.create_task_template(2, 'Privat', 'Titel', '', False, 'normal', [])
        self.assertEqual(len(db.list_task_templates(2)), 1)
        result = db.delete_user_with_reassignment(2, 1)
        self.assertEqual(result, 'ok')
        self.assertEqual(len(db.list_task_templates(1)), 0)

    def test_recurrence_validates_assignee_and_copies_milestone(self):
        milestone = db.create_milestone(self.project, 'Release', '2026-12-01')
        task = db.create_task(
            self.project, 'Wiederkehrend', '', 'open', 2,
            deadline='2026-11-11', recurrence='daily', milestone_id=milestone,
        )
        self.assertTrue(db.remove_project_member(self.project, 2))
        db.update_task_status_if_accessible(task, 1, 'done', 'owner')

        followup = db.list_project_tasks(self.project)[0]
        self.assertIsNone(followup['assignee_id'])
        self.assertEqual(followup['milestone_id'], milestone)

    def test_reminder_requires_target(self):
        db.create_task(self.project, 'Due', '', 'open', 2, deadline='2026-11-11')
        # member (id 2) hat kein Ziel? Doch, member hat mobile_app_member.
        # Nutze einen Nutzer ohne Ziel:
        db.add_project_member(self.project, 3, 'member')
        db.create_task(self.project, 'NoTarget', '', 'open', 3, deadline='2026-11-11')

        captured = {}

        class FakeNotifier:
            def send(self, title, message, target=None):
                captured['target'] = target
                return True, 'sent'

        result = reminders.run_reminder_once(self.now, self.options, FakeNotifier())
        # Aufgabe "Due" (member, mit Ziel) wird zugestellt; "NoTarget" wird uebersprungen.
        self.assertEqual(result['sent'], 1)
        self.assertEqual(captured['target'], 'notify.mobile_app_member')

    def test_concurrent_runs_send_once(self):
        db.create_task(self.project, 'Due', '', 'open', 2, deadline='2026-11-11')

        class SlowNotifier:
            def __init__(self):
                self.calls = []
                self._lock = threading.Lock()

            def send(self, title, message, target=None):
                with self._lock:
                    self.calls.append((title, message, target))
                time.sleep(0.15)
                return True, 'sent'

        notifier = SlowNotifier()
        threads = [
            threading.Thread(target=reminders.run_reminder_once, args=(self.now, self.options, notifier))
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(notifier.calls), 1)


class EndpointPathTest(unittest.TestCase):
    def _server(self, captured):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                captured.append(self.path)
                body = b'{}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def test_ha_rest_path_is_domain_service(self):
        captured: list[str] = []
        server = self._server(captured)
        try:
            settings = reminders.ReminderSettings(
                enabled=True,
                base_url=f'http://127.0.0.1:{server.server_port}',
                token='token',
                timeout=2.0,
            )
            ok, detail = reminders.HomeAssistantNotifier(settings).send('t', 'm', 'notify.mobile_app_x')
            self.assertTrue(ok)
            self.assertEqual(captured, ['/api/services/notify/mobile_app_x'])
        finally:
            server.shutdown()
            server.server_close()

    def test_invalid_service_fails_closed(self):
        settings = reminders.ReminderSettings(enabled=True, base_url='http://localhost', token='test')
        notifier = reminders.HomeAssistantNotifier(settings)
        for target in ['notify.notify', 'mobile_app_phone', 'notify.mobile_app_x/../bad', '']:
            self.assertEqual(notifier.send('t', 'm', target), (False, 'invalid_target'))


class CalendarEdgeAndTaskDetailTest(unittest.TestCase):
    def test_calendar_edge_and_task_detail(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, HOUSEHOLD_DATA_DIR=directory)
            env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'app')
            result = subprocess.run([sys.executable, '-c', r'''
import re
from fastapi.testclient import TestClient
import main, db
from auth import hash_password
db.init_db()
db.create_user('tester', hash_password('test-password-123'), 'admin')
with TestClient(main.app) as client:
    page = client.get('/login')
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    client.post('/login', data={'username':'tester','password':'test-password-123','csrf':csrf})
    page = client.get('/projects')
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    client.post('/projects', data={'csrf':csrf,'name':'P'})
    project = db.list_accessible_projects(1)[0]['id']
    client.post(f'/projects/{project}/tasks', data={'csrf':csrf,'title':'T','status':'open'})
    task = db.list_project_tasks(project)[0]['id']

    edge = client.get(f'/projects?project_id={project}&month=9999-12')
    assert edge.status_code == 200, edge.status_code
    edge2 = client.get(f'/projects?project_id={project}&view=calendar&month=0001-01')
    assert edge2.status_code == 200, edge2.status_code

    detail = client.get(f'/tasks/{task}')
    assert detail.status_code == 200, detail.status_code
    assert 'Bearbeiten' in detail.text and 'Checkliste' in detail.text

    # Serverseitige Suche filtert ueber alle Seiten hinweg.
    for i in range(60):
        db.create_task(project, f'Erledigt {i}', '', 'done', None)
    db.create_task(project, 'GesuchterTitel', '', 'open', None)
    search = client.get(f'/projects?project_id={project}&q=GesuchterTitel')
    assert search.status_code == 200
    assert 'GesuchterTitel' in search.text
'''], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
