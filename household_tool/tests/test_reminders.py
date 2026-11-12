import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db
import reminders


BERLIN = ZoneInfo('Europe/Berlin')


class FakeNotifier:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def send(self, title, message, target=None):
        self.calls.append((title, message, target))
        if self.responses:
            return self.responses.pop(0)
        return True, 'sent'


class QuietHoursTest(unittest.TestCase):
    def test_quiet_hours(self):
        evening = datetime(2026, 11, 11, 23, 0, tzinfo=BERLIN)
        morning = datetime(2026, 11, 11, 6, 0, tzinfo=BERLIN)
        daytime = datetime(2026, 11, 11, 12, 0, tzinfo=BERLIN)
        self.assertTrue(reminders.is_within_quiet_hours(evening, '22:00', '07:00'))
        self.assertTrue(reminders.is_within_quiet_hours(morning, '22:00', '07:00'))
        self.assertFalse(reminders.is_within_quiet_hours(daytime, '22:00', '07:00'))

    def test_send_time(self):
        before = datetime(2026, 11, 11, 8, 0, tzinfo=BERLIN)
        after = datetime(2026, 11, 11, 10, 0, tzinfo=BERLIN)
        self.assertTrue(reminders.is_before_send_time(before, '09:00'))
        self.assertFalse(reminders.is_before_send_time(after, '09:00'))


class ReminderSchedulerTest(unittest.TestCase):
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
        self.project = db.create_project('Test', 'Description', 1)
        db.add_project_member(self.project, 2, 'member')
        self.options = {
            'ha_reminders_enabled': '1',
            'ha_base_url': 'http://localhost:8123',
            'ha_token': 'test-token',
            'reminder_time': '09:00',
            'reminder_quiet_start': '22:00',
            'reminder_quiet_end': '07:00',
            'reminder_max_retries': 3,
            'reminder_timeout': 1.0,
        }
        self.now = datetime(2026, 11, 11, 10, 0, tzinfo=BERLIN)

    def test_disabled_and_not_configured(self):
        self.assertEqual(reminders.run_reminder_once(self.now, {}, FakeNotifier())['state'], 'disabled')
        self.assertEqual(
            reminders.run_reminder_once(self.now, {'ha_reminders_enabled': '1'}, FakeNotifier())['state'],
            'not_configured',
        )

    def test_quiet_hours_and_before_time(self):
        quiet = datetime(2026, 11, 11, 23, 0, tzinfo=BERLIN)
        self.assertEqual(reminders.run_reminder_once(quiet, self.options, FakeNotifier())['state'], 'quiet_hours')
        early = datetime(2026, 11, 11, 8, 0, tzinfo=BERLIN)
        self.assertEqual(reminders.run_reminder_once(early, self.options, FakeNotifier())['state'], 'before_time')

    def test_send_and_double_run_dedup(self):
        db.create_task(self.project, 'Due', '', 'open', 2, deadline='2026-11-11')
        notifier = FakeNotifier()
        first = reminders.run_reminder_once(self.now, self.options, notifier)
        self.assertEqual(first['state'], 'ok')
        self.assertEqual(first['sent'], 1)
        self.assertEqual(len(notifier.calls), 1)

        second = reminders.run_reminder_once(self.now, self.options, notifier)
        self.assertEqual(second['sent'], 0)
        self.assertEqual(second['skipped'], 1)
        self.assertEqual(len(notifier.calls), 1)

    def test_no_reminder_for_done_task_or_revoked_access(self):
        task = db.create_task(self.project, 'Due', '', 'open', 2, deadline='2026-11-11')
        db.update_task_status_if_accessible(task, 1, 'done')
        result = reminders.run_reminder_once(self.now, self.options, FakeNotifier())
        self.assertEqual(result['sent'], 0)

        db.update_task_status_if_accessible(task, 1, 'open')
        self.assertTrue(db.remove_project_member(self.project, 2))
        result = reminders.run_reminder_once(self.now, self.options, FakeNotifier())
        self.assertEqual(result['sent'], 0)

    def test_failure_retries_until_limit(self):
        db.create_task(self.project, 'Due', '', 'open', 2, deadline='2026-11-11')
        notifier = FakeNotifier([(False, 'timeout'), (False, 'timeout'), (False, 'timeout')])
        first = reminders.run_reminder_once(self.now, self.options, notifier)
        self.assertEqual(first['failed'], 1)
        second = reminders.run_reminder_once(self.now, self.options, notifier)
        self.assertEqual(second['failed'], 1)
        third = reminders.run_reminder_once(self.now, self.options, notifier)
        self.assertEqual(third['failed'], 1)
        fourth = reminders.run_reminder_once(self.now, self.options, notifier)
        self.assertEqual(fourth['failed'], 0)
        self.assertEqual(fourth['skipped'], 1)
        self.assertEqual(len(notifier.calls), 3)


class NotifierTimeoutTest(unittest.TestCase):
    def _server(self, delay: float, status: int = 200):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                time.sleep(delay)
                body = b'{}'
                self.send_response(status)
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

    def test_timeout_and_success(self):
        slow = self._server(delay=0.4)
        try:
            settings = reminders.ReminderSettings(
                enabled=True,
                base_url=f'http://127.0.0.1:{slow.server_port}',
                token='token',
                timeout=0.1,
            )
            notifier = reminders.HomeAssistantNotifier(settings)
            ok, detail = notifier.send('t', 'm', 'notify.mobile_app_test')
            self.assertFalse(ok)
            self.assertTrue(detail)
        finally:
            slow.shutdown()
            slow.server_close()

        fast = self._server(delay=0.0, status=200)
        try:
            settings = reminders.ReminderSettings(
                enabled=True,
                base_url=f'http://127.0.0.1:{fast.server_port}',
                token='token',
                timeout=2.0,
            )
            notifier = reminders.HomeAssistantNotifier(settings)
            ok, detail = notifier.send('t', 'm', 'notify.mobile_app_test')
            self.assertTrue(ok)
            self.assertEqual(detail, 'sent')
        finally:
            fast.shutdown()
            fast.server_close()


if __name__ == '__main__':
    unittest.main()
