import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ProjectHttpCommentsTest(unittest.TestCase):
    def test_comment_xss_is_escaped(self):
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
    client.post('/projects', data={'csrf':csrf,'name':'XSS Project'})
    project = db.list_accessible_projects(1)[0]['id']
    client.post(f'/projects/{project}/tasks', data={'csrf':csrf,'title':'Task'})
    task = db.list_project_tasks(project)[0]['id']
    payload = '<script>alert(1)</script>'
    client.post(f'/tasks/{task}/comments', data={'csrf':csrf,'project_id':project,'content':payload})
    page = client.get(f'/projects?project_id={project}')
    assert '<script>alert(1)</script>' not in page.text
    assert '&lt;script&gt;' in page.text
'''], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
