import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ProjectHttpTest(unittest.TestCase):
    def test_http_lifecycle(self):
        # Separate process keeps production /data and other test modules untouched.
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
    assert client.post('/login', data={'username':'tester','password':'test-password-123','csrf':csrf}).status_code == 200
    page = client.get('/projects')
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    page = client.post('/projects', data={'csrf':csrf,'name':'HTTP Project'})
    project = db.list_accessible_projects(1)[0]['id']
    data = {'csrf':csrf,'title':'Deadline task','description':'Keep every detail','deadline':'2026-11-11','focus':'1'}
    assert client.post(f'/projects/{project}/tasks', data=data).status_code == 200
    task = db.list_project_tasks(project)[0]['id']
    invalid = client.post(f'/projects/{project}/tasks', data=dict(data, deadline='invalid'), follow_redirects=False)
    assert 'invalid_deadline' in invalid.headers['location']
    assert client.post(f'/tasks/{task}/attachments', data={'csrf':csrf,'project_id':project}, files={'file':('note.txt',b'keep me')}).status_code == 200
    assert client.post(f'/tasks/{task}/status', data={'csrf':csrf,'project_id':project,'status':'done'}).status_code == 200
    assert 'Deadline task' not in client.get(f'/projects?project_id={project}').text
    history = client.get(f'/projects?project_id={project}&view=history')
    assert history.status_code == 200
    for text in ['Deadline task','Keep every detail','note.txt','2026-11-11']:
        assert text in history.text, text
    assert client.post(f'/tasks/{task}/status', data={'csrf':csrf,'project_id':project,'status':'open','view':'history'}).status_code == 200
    assert len(db.list_project_tasks(project)) == 1
    assert not db.list_project_history(project)
    blocked = client.post(f'/tasks/{task}/status', data={'csrf':'wrong','project_id':project,'status':'done'}, follow_redirects=False)
    assert 'csrf' in blocked.headers['location']
'''], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
