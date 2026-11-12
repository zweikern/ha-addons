import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db


class MyTasksTest(unittest.TestCase):
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

    @patch.object(db, 'project_today', return_value=date(2026, 11, 11))
    def test_my_tasks_filters_and_priorities(self, _today):
        db.create_task(self.project, 'Heute', '', 'open', 3, deadline='2026-11-11', priority='high')
        db.create_task(self.project, 'Morgen', '', 'open', 3, deadline='2026-11-12', priority='low')
        db.create_task(self.project, 'Ueberfaellig', '', 'open', 3, deadline='2026-11-10')
        db.create_task(self.project, 'Erledigt', '', 'done', 3)
        db.create_task(self.project, 'Fremd', '', 'open', 2)

        self.assertEqual(len(db.list_my_tasks(3)), 3)
        self.assertEqual(len(db.list_my_tasks(3, 'focus')), 0)
        self.assertEqual(len(db.list_my_tasks(3, 'today')), 1)
        self.assertEqual(len(db.list_my_tasks(3, 'tomorrow')), 1)
        self.assertEqual(len(db.list_my_tasks(3, 'overdue')), 1)
        self.assertEqual(len(db.list_my_tasks(3, 'history')), 1)

        task = db.list_my_tasks(3, 'today')[0]
        self.assertEqual(task['priority'], 'high')
        self.assertEqual(task['project_name'], 'Test')

    def test_priority_ordering(self):
        db.create_task(self.project, 'A', '', 'open', 3, priority='low')
        db.create_task(self.project, 'B', '', 'open', 3, priority='high')
        db.create_task(self.project, 'C', '', 'open', 3, priority='normal')
        order = [row['priority'] for row in db.list_my_tasks(3)]
        self.assertEqual(order, ['high', 'normal', 'low'])

    def test_priority_defaults_and_validation(self):
        task = db.create_task(self.project, 'Invalid', '', 'open', 3, priority='urgent')
        self.assertEqual(db.list_my_tasks(3)[0]['priority'], 'normal')
        db.update_task_if_accessible(task, 1, 'Invalid', '', 'open', 3, False, None, 'bogus')
        self.assertEqual(db.list_my_tasks(3)[0]['priority'], 'normal')

    def test_share_revocation_hides_tasks(self):
        db.create_task(self.project, 'Zugewiesen', '', 'open', 3)
        self.assertEqual(len(db.list_my_tasks(3)), 1)
        self.assertTrue(db.remove_project_member(self.project, 3))
        self.assertEqual(len(db.list_my_tasks(3)), 0)


if __name__ == '__main__':
    unittest.main()
