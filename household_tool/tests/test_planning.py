import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import db
from planning import build_plan


def task(id=1, start='2026-11-09', end='2026-11-12', **kwargs):
    return dict(id=id, title=f'Task {id}', description='', status='open', start_date=start,
                end_date=end, deadline=None, assignee_name='Owner', **kwargs)


class PlanLayoutTest(unittest.TestCase):
    def plan(self, tasks, dependencies=(), milestones=(), **kwargs):
        return build_plan(tasks, dependencies, milestones, date(2026, 11, 12), **kwargs)

    def test_inclusive_duration_and_one_day_bar(self):
        plan = self.plan([task(), task(2, '2026-11-12', '2026-11-12')])
        self.assertEqual(plan['rows'][0]['duration'], 4)
        self.assertEqual(plan['rows'][1]['width'], plan['day_width'])

    def test_finish_to_start_conflict_and_line(self):
        dep = dict(task_id=2, depends_on_task_id=1)
        plan = self.plan([task(), task(2, '2026-11-12', '2026-11-14')], [dep])
        self.assertEqual(len(plan['paths']), 1)
        self.assertTrue(plan['paths'][0]['conflict'])
        self.assertEqual(plan['conflicts'][0]['reason'], 'dependency')
        plan = self.plan([task(), task(2, '2026-11-13', '2026-11-14')], [dep])
        self.assertFalse(plan['conflicts'])

    def test_deadline_not_used_as_implicit_schedule(self):
        t = task(start=None, end=None)
        t['deadline'] = '2026-11-15'
        plan = self.plan([t])
        self.assertEqual(plan['unscheduled_count'], 1)
        self.assertFalse(plan['rows'][0]['visible'])
        self.assertIsNotNone(plan['rows'][0]['deadline_x'])

    def test_deadline_conflict_and_done_exclusion(self):
        t = task(); t['deadline'] = '2026-11-10'
        done = task(2); done['status'] = 'done'
        plan = self.plan([t, done])
        self.assertEqual(len(plan['rows']), 1)
        self.assertEqual(plan['conflicts'][0]['reason'], 'deadline')

    def test_offscreen_and_clipping(self):
        plan = self.plan([task(1, '2026-01-01', '2027-01-01'), task(2, '2027-04-01', '2027-04-02')],
                         anchor='2026-11-09', scale='day')
        row = plan['rows'][0]
        self.assertTrue(row['clipped_start'] and row['clipped_end'])
        self.assertEqual(row['width'], plan['width'])
        self.assertFalse(plan['rows'][1]['visible'])

    def test_date_extremes_and_bounded_canvas(self):
        for anchor in ['0001-01-01', '9999-12-31']:
            plan = self.plan([], anchor=anchor, scale='month')
            self.assertEqual(plan['days'], 366)
            self.assertLessEqual(plan['width'], 2562)
            self.assertIsNotNone(date.fromisoformat(plan['prev']))
            self.assertIsNotNone(date.fromisoformat(plan['next']))
        with self.assertRaises(ValueError):
            self.plan([], anchor='not-a-date')

    def test_milestones_and_unknown_scale(self):
        plan = self.plan([], milestones=[dict(id=1, name='Release', due_date='2026-11-13')], scale='bogus')
        self.assertTrue(plan['milestones'][0]['visible'])
        self.assertEqual(plan['scale'], 'week')
        self.assertTrue(all(t['x'] + t['width'] <= plan['width'] for t in plan['ticks']))


class PlanDatabaseTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        for name, value in [('DATA_DIR', Path(temp.name)), ('DB_PATH', Path(temp.name) / 'app.db')]:
            p = patch.object(db, name, value); p.start(); self.addCleanup(p.stop)
        db.init_db()
        db.create_user('owner', 'hash', 'admin'); db.create_user('member', 'hash', 'user'); db.create_user('foreign', 'hash', 'user')
        self.project = db.create_project('Plan', '', 1)
        db.add_project_member(self.project, 2, 'member')
        self.task = db.create_task(self.project, 'First', '', 'open', 1)

    def test_schedule_validation(self):
        for start, end in [('2026-11-11', None), (None, '2026-11-11'), ('2026-11-12', '2026-11-11'), ('bad', 'bad')]:
            with self.assertRaises(ValueError):
                db.update_task_schedule(self.task, 1, start, end)
        self.assertIsNone(db.get_task_detail_if_accessible(self.task, 1)['start_date'])

    def test_schedule_acl_event_and_clear(self):
        self.assertFalse(db.update_task_schedule(self.task, 3, '2026-11-11', '2026-11-12'))
        self.assertFalse(db.list_task_events(self.task))
        self.assertTrue(db.update_task_schedule(self.task, 2, '2026-11-11', '2026-11-12'))
        self.assertTrue(db.update_task_schedule(self.task, 2, '2026-11-11', '2026-11-12'))
        self.assertEqual(len(db.list_task_events(self.task)), 1)
        db.update_task_status_if_accessible(self.task, 1, 'done')
        self.assertEqual(db.get_task_detail_if_accessible(self.task, 1)['start_date'], '2026-11-11')
        db.update_task_status_if_accessible(self.task, 1, 'open')
        db.update_task_schedule(self.task, 2, None, None)
        self.assertIsNone(db.get_task_detail_if_accessible(self.task, 1)['end_date'])

    def test_dependency_removal_acl_and_project_integrity(self):
        other = db.create_task(self.project, 'Other', '', 'open', 1)
        self.assertEqual(db.add_task_dependency(other, self.task, 1), 'ok')
        dep = db.list_project_dependencies(self.project)[0]
        self.assertFalse(db.remove_task_dependency(other, dep['id'], 3))
        self.assertFalse(db.remove_task_dependency(self.task, dep['id'], 1))
        self.assertTrue(db.remove_task_dependency(other, dep['id'], 2))
        self.assertFalse(db.list_project_dependencies(self.project))
        self.assertTrue(any(e['event_type'] == 'dependency_removed' for e in db.list_task_events(other)))

    def test_migration_does_not_invent_dates(self):
        with db.get_connection() as c:
            c.execute('ALTER TABLE tasks DROP COLUMN start_date')
            c.execute('ALTER TABLE tasks DROP COLUMN end_date')
        db.init_db(); db.init_db()
        row = db.get_task_detail_if_accessible(self.task, 1)
        self.assertIsNone(row['start_date']); self.assertIsNone(row['end_date'])
        self.assertEqual(row['title'], 'First')

    def test_milestone_delete_keeps_task_and_audits_unassignment(self):
        m = db.create_milestone(self.project, 'Release', '2026-12-01')
        t = db.create_task(self.project, 'Keep', '', 'open', 1, milestone_id=m)
        self.assertTrue(db.edit_project_milestone(self.project, m, '', None, 1, delete=True))
        self.assertIsNone(db.get_task_detail_if_accessible(t, 1)['milestone_id'])
        self.assertEqual(db.list_task_events(t)[0]['event_type'], 'milestone_changed')

    def test_previews_are_scoped_to_visible_tasks_without_blob_content(self):
        for i in range(5):
            db.create_task_comment(self.task, 1, 'owner', f'Comment {i}')
        foreign_project = db.create_project('Foreign', '', 3)
        foreign_task = db.create_task(foreign_project, 'Secret', '', 'open', 3)
        db.create_task_comment(foreign_task, 3, 'foreign', 'Secret comment')
        with db.get_connection() as c:
            c.execute("INSERT INTO task_attachments(task_id,filename,mime,size,content) VALUES (?, 'a.txt','text/plain',3,?)",
                      (self.task, b'abc'))
        attachments, comments = db.task_list_previews(self.project, [self.task, foreign_task])
        self.assertEqual([c['content'] for c in comments], ['Comment 3', 'Comment 4'])
        self.assertEqual(len(attachments), 1)
        self.assertNotIn('content', attachments[0].keys())
        self.assertEqual(db.task_list_previews(self.project, []), ([], []))

    def test_create_stores_schedule_independent_of_deadline(self):
        t = db.create_task(self.project, 'Scheduled', '', 'open', 1,
                           start_date='2026-11-01', end_date='2026-11-09', deadline='2026-11-20')
        row = db.get_task_detail_if_accessible(t, 1)
        self.assertEqual((row['start_date'], row['end_date'], row['deadline']),
                         ('2026-11-01', '2026-11-09', '2026-11-20'))


class PlanningHttpTest(unittest.TestCase):
    def test_plan_mutations_and_permissions(self):
        code = r'''
import re
from fastapi.testclient import TestClient
import main,db
from auth import hash_password
db.init_db()
for name,role in [('owner','admin'),('member','user'),('foreign','admin')]:
 db.create_user(name,hash_password('test-password-123'),role)
p=db.create_project('Plan','',1);db.add_project_member(p,2,'member')
t=db.create_task(p,'<svg onload=alert(1)>','','open',1,start_date='2026-11-09',end_date='2026-11-12')
b=db.create_task(p,'Second','','open',1)
m=db.create_milestone(p,'Release','2026-11-20')
with TestClient(main.app) as client:
 def login(name):
  client.get('/logout'); page=client.get('/login'); csrf=re.search(r'name="csrf" value="([^"]+)"',page.text)[1]
  client.post('/login',data={'username':name,'password':'test-password-123','csrf':csrf})
  return re.search(r'name="csrf" value="([^"]+)"',client.get('/projects').text)[1]
 csrf=login('member')
 page=client.get(f'/projects?project_id={p}&view=timeline')
 assert page.status_code==200 and 'gantt-bar' in page.text
 assert '<svg onload=alert(1)>' not in page.text and '&lt;svg onload=alert(1)&gt;' in page.text
 assert client.get(f'/projects?project_id={p}&view=timeline&anchor=bad').status_code==400
 response=client.post(f'/tasks/{t}/schedule',data={'csrf':'bad','start_date':'2026-11-10','end_date':'2026-11-20'},follow_redirects=False)
 assert 'csrf' in response.headers['location']
 assert db.get_task_detail_if_accessible(t,1)['start_date']=='2026-11-09'
 response=client.post(f'/tasks/{t}/schedule',data={'csrf':csrf,'start_date':'2026-11-10','end_date':'2026-11-20'},follow_redirects=False)
 assert response.headers['location']==f'/tasks/{t}'
 assert db.get_task_detail_if_accessible(t,1)['end_date']=='2026-11-20'
 client.post(f'/tasks/{b}/dependencies',data={'csrf':csrf,'project_id':p,'depends_on_task_id':t,'return_to':'task'})
 dep=db.list_project_dependencies(p)[0]
 response=client.post(f'/tasks/{t}/dependencies',data={'csrf':csrf,'project_id':p,'depends_on_task_id':b,'return_to':'task'},follow_redirects=False)
 assert 'dependency_cycle' in response.headers['location']
 response=client.post(f'/projects/{p}/milestones/{m}/edit',data={'csrf':csrf,'name':'New','due_date':'2026-12-01'},follow_redirects=False)
 assert response.status_code==403
 csrf=login('foreign')
 assert client.post(f'/tasks/{t}/schedule',data={'csrf':csrf,'start_date':'','end_date':''}).status_code==404
 assert client.post(f'/tasks/{b}/dependencies/{dep["id"]}/remove',data={'csrf':csrf}).status_code==404
 assert client.get(f'/tasks/{t}').status_code==404
 csrf=login('owner')
 response=client.post(f'/projects/{p}/milestones/{m}/edit',data={'csrf':csrf,'name':'New','due_date':'2026-12-01'},follow_redirects=False)
 assert response.status_code==303 and db.list_project_milestones(p)[0]['name']=='New'
 response=client.post(f'/tasks/{b}/dependencies/{dep["id"]}/remove',data={'csrf':csrf},follow_redirects=False)
 assert response.status_code==303 and not db.list_project_dependencies(p)
 # A regular metadata edit preserves separately stored scheduling dates.
 response=client.post(f'/tasks/{t}/edit',data={'csrf':csrf,'project_id':p,'title':'Edited','status':'open','return_to':'task'},follow_redirects=False)
 assert response.headers['location']==f'/tasks/{t}'
 assert db.get_task_detail_if_accessible(t,1)['end_date']=='2026-11-20'
 client.post(f'/tasks/{t}/status',data={'csrf':csrf,'project_id':p,'status':'done'})
 page=client.get(f'/projects?project_id={p}&view=timeline')
 assert 'data-plan-row="1"' not in page.text
 assert db.get_task_detail_if_accessible(t,1)['end_date']=='2026-11-20'
'''
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, HOUSEHOLD_DATA_DIR=directory,
                       PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'app'))
            result = subprocess.run([sys.executable, '-W', 'error::ResourceWarning', '-c', code],
                                    env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
