import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db


class ProjectLifecycleTest(unittest.TestCase):
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
        self.project = db.create_project('Test', 'Description', 1)

    def test_history_preserves_details_and_reopens(self):
        task = db.create_task(self.project, 'Task', 'Full description', 'open', 1, True, '2026-11-11')
        attachment = db.create_attachment(task, 'notes.txt', 'text/plain', 4, b'test')
        self.assertEqual(db.update_task_status_if_accessible(task, 1, 'done'), self.project)
        self.assertEqual(db.list_project_tasks(self.project), [])
        record = db.list_project_history(self.project)[0]
        self.assertEqual(record['description'], 'Full description')
        self.assertEqual(record['deadline'], '2026-11-11')
        self.assertEqual(record['focus'], 1)
        self.assertEqual(record['assignee_id'], 1)
        self.assertEqual(record['attachment_count'], 1)
        self.assertIsNotNone(record['completed_at'])
        self.assertIsNone(db.update_task_status_if_accessible(task, 2, 'open'))
        db.update_task_status_if_accessible(task, 1, 'open')
        self.assertEqual(db.list_project_history(self.project), [])
        self.assertEqual(db.get_attachment_if_accessible(attachment, 1)['content'], b'test')
        self.assertEqual(db.list_project_tasks(self.project)[0]['deadline'], '2026-11-11')

    @patch.object(db, 'project_today', return_value=date(2026, 11, 11))
    def test_deadline_filters_and_edit(self, _today):
        for day in ['2026-11-10', '2026-11-11', '2026-11-12', None]:
            db.create_task(self.project, 'Task', '', 'open', None, deadline=day)
        db.create_task(self.project, 'Done', '', 'done', None, deadline='2026-11-11')
        for view in ['today', 'tomorrow', 'overdue']:
            self.assertEqual(len(db.list_project_tasks(self.project, view)), 1)
        task = db.list_project_tasks(self.project, 'today')[0]['id']
        self.assertIsNone(db.update_task_if_accessible(task, 2, 'No', '', 'open', None, False, None))
        db.update_task_if_accessible(task, 1, 'Edited', '', 'open', None, False, None)
        self.assertEqual(db.list_project_tasks(self.project, 'today'), [])
        with self.assertRaises(ValueError):
            db.create_task(self.project, 'Invalid', '', 'open', None, deadline='2026-02-30')

    def test_migration_and_full_history(self):
        with db.get_connection() as conn:
            conn.execute('ALTER TABLE tasks DROP COLUMN deadline')
        db.init_db()
        db.init_db()
        for i in range(30):
            db.create_task(self.project, str(i), 'Kept', 'done', None)
        self.assertEqual(len(db.list_project_history(self.project)), 30)


if __name__ == '__main__':
    unittest.main()
