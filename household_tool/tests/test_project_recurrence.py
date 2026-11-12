import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db


class ChecklistAndRecurrenceTest(unittest.TestCase):
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
        db.add_project_member(self.project, 2, 'member')

    def test_checklist_items_and_toggle(self):
        task = db.create_task(self.project, 'Task', '', 'open', 1)
        first = db.add_task_checklist_item(task, 'Punkt 1')
        db.add_task_checklist_item(task, 'Punkt 2')
        items = db.list_task_checklist_items(task)
        self.assertEqual(len(items), 2)
        db.set_task_checklist_item_done(first, True)
        items = db.list_task_checklist_items(task)
        self.assertTrue(items[0]['done'])
        self.assertFalse(items[1]['done'])
        # Checkliste aendert den Aufgabenstatus nicht stillschweigend.
        self.assertEqual(db.list_project_tasks(self.project)[0]['status'], 'open')

    def test_compute_recurrence_deadline(self):
        self.assertEqual(db.compute_recurrence_deadline(date(2026, 11, 11), 'daily'), date(2026, 11, 12))
        self.assertEqual(db.compute_recurrence_deadline(date(2026, 11, 11), 'weekly'), date(2026, 11, 18))
        self.assertEqual(db.compute_recurrence_deadline(date(2026, 1, 15), 'monthly'), date(2026, 2, 15))
        self.assertEqual(db.compute_recurrence_deadline(date(2026, 1, 31), 'monthly'), date(2026, 2, 28))
        self.assertIsNone(db.compute_recurrence_deadline(date(2026, 1, 1), 'yearly'))

    def test_completion_creates_single_followup_with_copy_rules(self):
        task = db.create_task(
            self.project, 'Wiederkehrend', 'Beschreibung', 'open', 1,
            focus=True, deadline='2026-11-11', priority='high', recurrence='daily',
            actor_id=1, actor_name='owner',
        )
        db.add_task_checklist_item(task, 'Punkt A')
        db.create_attachment(task, 'note.txt', 'text/plain', 4, b'test', 1, 'owner')
        db.create_task_comment(task, 1, 'owner', 'Ein Kommentar')

        db.update_task_status_if_accessible(task, 1, 'done', 'owner')

        active = db.list_project_tasks(self.project)
        self.assertEqual(len(active), 1)
        followup = active[0]
        self.assertEqual(followup['title'], 'Wiederkehrend')
        self.assertEqual(followup['deadline'], '2026-11-12')
        self.assertEqual(followup['recurrence'], 'daily')
        self.assertEqual(followup['focus'], 1)
        self.assertEqual(followup['priority'], 'high')

        checklist = db.list_task_checklist_items(int(followup['id']))
        self.assertEqual([item['content'] for item in checklist], ['Punkt A'])
        attachments = db.list_project_attachments(self.project)
        followup_attachments = [a for a in attachments if int(a['task_id']) == int(followup['id'])]
        self.assertEqual(len(followup_attachments), 1)

        # Kommentare und Aktivitaetsverlauf werden nicht kopiert.
        self.assertEqual(len(db.list_task_comments(int(followup['id']))), 0)

        # Wiederoeffnen und erneuter Abschluss erzeugen kein Duplikat.
        db.update_task_status_if_accessible(task, 1, 'open', 'owner')
        db.update_task_status_if_accessible(task, 1, 'done', 'owner')
        self.assertEqual(len(db.list_project_tasks(self.project)), 1)

    def test_template_creates_task_with_checklist(self):
        template_id = db.create_task_template(
            1, 'Wochenputz', 'Putzen', 'Alle Raeume', True, 'normal', ['Staubsaugen', 'Wischen'],
        )
        task_id = db.create_task_from_template(self.project, template_id, 1)
        self.assertIsNotNone(task_id)
        items = db.list_task_checklist_items(task_id)
        self.assertEqual([item['content'] for item in items], ['Staubsaugen', 'Wischen'])
        task = db.get_task_if_accessible(task_id, 1)
        self.assertEqual(task['focus'], 1)
        self.assertEqual(task['title'], 'Putzen')

        # Vorlage eines anderen Nutzers ist nicht nutzbar.
        self.assertIsNone(db.create_task_from_template(self.project, template_id, 2))


if __name__ == '__main__':
    unittest.main()
