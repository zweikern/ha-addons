import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ProjectKanbanCalendarTest(unittest.TestCase):
    def test_kanban_and_calendar_render(self):
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
    client.post('/projects', data={'csrf':csrf,'name':'KB Project'})
    project = db.list_accessible_projects(1)[0]['id']
    client.post(f'/projects/{project}/tasks', data={'csrf':csrf,'title':'Offen','status':'open'})
    client.post(f'/projects/{project}/tasks', data={'csrf':csrf,'title':'InArbeit','status':'in_progress'})
    client.post(f'/projects/{project}/tasks', data={'csrf':csrf,'title':'Dez','status':'open','deadline':'2026-12-31'})
    client.post(f'/projects/{project}/tasks', data={'csrf':csrf,'title':'Jan','status':'open','deadline':'2027-01-01'})

    kanban = client.get(f'/projects?project_id={project}&view=kanban')
    assert kanban.status_code == 200
    assert 'Board' in kanban.text
    assert 'data-board-status="open" data-task-count="3"' in kanban.text
    assert 'data-board-status="in_progress" data-task-count="1"' in kanban.text

    cal_dec = client.get(f'/projects?project_id={project}&view=calendar&month=2026-12')
    assert cal_dec.status_code == 200
    assert 'Dez' in cal_dec.text
    cal_jan = client.get(f'/projects?project_id={project}&view=calendar&month=2027-01')
    assert cal_jan.status_code == 200
    assert 'Jan' in cal_jan.text

    # Status change from kanban moves task and is reflected in the list view.
    task = db.list_project_tasks(project, 'open')[0]['id']
    client.post(f'/tasks/{task}/status', data={'csrf':csrf,'project_id':project,'view':'kanban','status':'in_progress'})
    kanban = client.get(f'/projects?project_id={project}&view=kanban')
    assert 'data-board-status="open" data-task-count="2"' in kanban.text
    assert 'data-board-status="in_progress" data-task-count="2"' in kanban.text
'''], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
