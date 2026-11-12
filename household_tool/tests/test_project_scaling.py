import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db


class ScalingTest(unittest.TestCase):
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
        self.project = db.create_project('Test', 'Description', 1)

    @patch.object(db, 'project_today', return_value=date(2026, 11, 11))
    def test_pagination_and_aggregate_counters(self, _today):
        for i in range(120):
            db.create_task(self.project, f'Erledigt {i}', '', 'done', None)
        for i in range(10):
            db.create_task(self.project, f'Aktiv {i}', '', 'open', None, deadline='2026-11-11')

        self.assertEqual(db.count_project_tasks(self.project, 'history'), 120)
        self.assertEqual(db.count_project_tasks(self.project, 'all'), 10)

        page1 = db.list_project_history(self.project, limit=50, offset=0)
        page2 = db.list_project_history(self.project, limit=50, offset=50)
        page3 = db.list_project_history(self.project, limit=50, offset=100)
        self.assertEqual(len(page1), 50)
        self.assertEqual(len(page2), 50)
        self.assertEqual(len(page3), 20)

        # Zaehler gelten fuer die gesamte Ergebnismenge, nicht nur die Seite.
        self.assertEqual(db.count_project_tasks(self.project, 'today'), 10)

        # Stabile Sortierung mit ID als Tie-Breaker: keine doppelten IDs ueber Seiten.
        ids = [row['id'] for row in page1] + [row['id'] for row in page2] + [row['id'] for row in page3]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == '__main__':
    unittest.main()
