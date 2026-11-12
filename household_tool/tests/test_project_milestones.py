import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db


class MilestonesAndDependenciesTest(unittest.TestCase):
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
        db.create_user('member', 'test-hash', 'user')
        self.project = db.create_project('Test', 'Description', 1)
        self.project2 = db.create_project('Anderes', 'Description', 1)
        db.add_project_member(self.project, 2, 'member')

    def test_milestones(self):
        milestone = db.create_milestone(self.project, 'Release', '2026-12-01')
        milestones = db.list_project_milestones(self.project)
        self.assertEqual(len(milestones), 1)
        self.assertEqual(milestones[0]['name'], 'Release')

        task = db.create_task(self.project, 'Task', '', 'open', 1, milestone_id=milestone)
        self.assertIsNotNone(db.get_task_if_accessible(task, 1))
        db.update_task_if_accessible(task, 1, 'Task', '', 'open', 1, False, None, 'normal', None, milestone)
        row = db.get_task_if_accessible(task, 1)
        self.assertEqual(row['id'], task)

    def test_dependencies_cycle_self_and_cross_project(self):
        task_a = db.create_task(self.project, 'A', '', 'open', 1)
        task_b = db.create_task(self.project, 'B', '', 'open', 1)
        task_c = db.create_task(self.project2, 'C', '', 'open', 1)

        self.assertEqual(db.add_task_dependency(task_a, task_b, 1), 'ok')
        self.assertEqual(db.add_task_dependency(task_a, task_a, 1), 'self_dependency')
        self.assertEqual(db.add_task_dependency(task_b, task_a, 1), 'cycle')
        self.assertEqual(db.add_task_dependency(task_a, task_c, 1), 'different_project')

        deps = db.list_project_dependencies(self.project)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]['blocking_title'], 'B')
        self.assertEqual(deps[0]['blocking_status'], 'open')

        # Geloeste Abhaengigkeit aktualisiert die Anzeige (Status sichtbar).
        db.update_task_status_if_accessible(task_b, 1, 'done')
        deps = db.list_project_dependencies(self.project)
        self.assertEqual(deps[0]['blocking_status'], 'done')


if __name__ == '__main__':
    unittest.main()
