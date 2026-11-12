import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db


class ProjectCommentsTest(unittest.TestCase):
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
        db.create_user('owner', 'test-hash', 'admin')
        db.create_user('other', 'test-hash', 'user')
        db.create_user('member', 'test-hash', 'user')
        self.project = db.create_project('Test', 'Description', 1)
        db.add_project_member(self.project, 3, 'member')

    def test_comments_with_author_and_time(self):
        task = db.create_task(self.project, 'Task', '', 'open', 1, actor_id=1, actor_name='owner')
        comment_id = db.create_task_comment(task, 1, 'owner', 'Hallo Welt')
        comments = db.list_task_comments(task)
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]['content'], 'Hallo Welt')
        self.assertEqual(comments[0]['author_name'], 'owner')
        self.assertEqual(comments[0]['author_current'], 'owner')
        self.assertIsNotNone(comments[0]['created_at'])
        self.assertEqual(comment_id, comments[0]['id'])

    def test_activity_log_records_mutations(self):
        task = db.create_task(self.project, 'Titel', 'Beschreibung', 'open', None, actor_id=1, actor_name='owner')
        events = db.list_task_events(task)
        self.assertEqual([e['event_type'] for e in events], ['task_created'])
        self.assertEqual(events[0]['new_value'], 'open')

        db.update_task_status_if_accessible(task, 1, 'in_progress', 'owner')
        db.update_task_status_if_accessible(task, 1, 'done', 'owner')
        db.update_task_status_if_accessible(task, 1, 'open', 'owner')
        types = [e['event_type'] for e in db.list_task_events(task)]
        self.assertIn('status_changed', types)
        self.assertIn('task_reopened', types)

        db.update_task_if_accessible(
            task, 1, 'Neuer Titel', 'Neue Beschreibung', 'open', 3, True, '2026-12-01', 'owner',
        )
        types = [e['event_type'] for e in db.list_task_events(task)]
        for expected in ('title_changed', 'description_changed', 'assignee_changed', 'focus_changed', 'deadline_changed'):
            self.assertIn(expected, types)

        db.create_attachment(task, 'note.txt', 'text/plain', 4, b'test', 1, 'owner')
        self.assertIn('attachment_added', [e['event_type'] for e in db.list_task_events(task)])

    def test_unauthorized_action_creates_no_event(self):
        task = db.create_task(self.project, 'Task', '', 'open', 1, actor_id=1, actor_name='owner')
        self.assertIsNone(db.update_task_status_if_accessible(task, 2, 'done', 'other'))
        types = [e['event_type'] for e in db.list_task_events(task)]
        self.assertEqual(types, ['task_created'])

    def test_deleted_user_does_not_break_log(self):
        task = db.create_task(self.project, 'Task', '', 'open', 1, actor_id=1, actor_name='owner')
        db.create_task_comment(task, 3, 'member', 'Kommentar eines geloeschten Nutzers')
        result = db.delete_user_with_reassignment(3, 1)
        self.assertEqual(result, 'ok')
        comments = db.list_task_comments(task)
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]['author_name'], 'member')
        self.assertIsNone(comments[0]['author_id'])
        self.assertIsNone(comments[0]['author_current'])


if __name__ == '__main__':
    unittest.main()
