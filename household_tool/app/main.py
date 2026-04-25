from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import hash_password, verify_password
from db import (
    add_project_member,
    create_project,
    create_task,
    create_user,
    ensure_admin_account,
    ensure_admin_credentials,
    get_accessible_project,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_accessible_projects,
    list_project_members,
    list_project_tasks,
    list_users,
    remove_project_member,
    stats,
    update_task_status_if_accessible,
)

DATA_DIR = Path('/data')
OPTIONS_PATH = DATA_DIR / 'options.json'
SECRET_KEY_PATH = DATA_DIR / 'secret_key'
VALID_ROLES = {'admin', 'user'}
VALID_MEMBER_ROLES = {'member', 'manager'}
VALID_TASK_STATUS = {'open', 'in_progress', 'done'}
VALID_PROJECT_VIEWS = {'all', 'open', 'done'}

app = FastAPI(title='Household Tool')
app.mount('/static', StaticFiles(directory='/app/static'), name='static')
templates = Jinja2Templates(directory='/app/templates')


def load_options() -> dict[str, Any]:
    if not OPTIONS_PATH.exists():
        return {}
    try:
        return json.loads(OPTIONS_PATH.read_text(encoding='utf-8'))
    except Exception as err:  # pragma: no cover - defensive log path
        print(f'[warning] Could not parse /data/options.json: {err}')
        return {}


def get_or_create_secret_key() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text(encoding='utf-8').strip()

    key = secrets.token_urlsafe(48)
    SECRET_KEY_PATH.write_text(key, encoding='utf-8')
    return key


def current_user(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    return get_user_by_id(int(user_id))


def csrf_token(request: Request) -> str:
    token = request.session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(24)
        request.session['csrf_token'] = token
    return token


def validate_csrf(request: Request, token: str) -> bool:
    expected = request.session.get('csrf_token', '')
    return bool(expected) and secrets.compare_digest(expected, token or '')


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=303)


def require_login(request: Request):
    user = current_user(request)
    if not user:
        return None, redirect('/login')
    return user, None


def require_admin(request: Request):
    user, response = require_login(request)
    if response:
        return None, response
    if user['role'] != 'admin':
        return None, HTMLResponse('Forbidden', status_code=403)
    return user, None


def normalize_view(view: str | None) -> str:
    if view in VALID_PROJECT_VIEWS:
        return str(view)
    return 'all'


def projects_url(
    project_id: int | None = None,
    view: str = 'all',
    error: str | None = None,
) -> str:
    params: dict[str, str] = {}
    if project_id is not None:
        params['project_id'] = str(project_id)
    if view in VALID_PROJECT_VIEWS and view != 'all':
        params['view'] = view
    if error:
        params['error'] = error
    return '/projects' + (f"?{urlencode(params)}" if params else '')


def can_manage_project(user, project) -> bool:
    if user['role'] == 'admin':
        return True
    if project['created_by'] == user['id']:
        return True
    return project['membership_role'] == 'manager'


def ensure_initial_admin() -> None:
    options = load_options()
    admin_username = str(options.get('admin_username') or 'admin').strip() or 'admin'
    admin_password = str(options.get('admin_password') or '').strip()

    if admin_password:
        created, updated = ensure_admin_credentials(
            admin_username,
            hash_password(admin_password),
        )
        if created:
            print(f'[info] Configured admin account created: {admin_username}')
        elif updated:
            print(f'[info] Configured admin credentials updated: {admin_username}')
        return

    admin_password = secrets.token_urlsafe(12)
    created = ensure_admin_account(admin_username, hash_password(admin_password))
    if created:
        print(f'[info] Initial admin account created: {admin_username}')
        print('[warning] No admin_password configured in add-on options.')
        print(f'[warning] Temporary admin password: {admin_password}')


secret_key = get_or_create_secret_key()
app.add_middleware(
    SessionMiddleware,
    secret_key=secret_key,
    https_only=False,
    same_site='lax',
)


@app.on_event('startup')
def on_startup() -> None:
    init_db()
    ensure_initial_admin()
    print('[info] Database ready at /data/app.db')


@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    if current_user(request):
        return redirect('/apps')
    return redirect('/login')


@app.get('/apps', response_class=HTMLResponse)
def apps_page(request: Request):
    user, response = require_login(request)
    if response:
        return response

    return templates.TemplateResponse(
        request,
        'apps.html',
        {
            'user': user,
            'stats': stats(),
            'csrf_token': csrf_token(request),
        },
    )


@app.get('/dashboard', response_class=HTMLResponse)
def dashboard_redirect(request: Request):
    user, response = require_login(request)
    if response:
        return response
    return redirect('/apps')


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    if current_user(request):
        return redirect('/apps')
    return templates.TemplateResponse(
        request,
        'login.html',
        {
            'error': request.query_params.get('error'),
            'csrf_token': csrf_token(request),
            'user': None,
        },
    )


@app.post('/login')
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
):
    if not validate_csrf(request, csrf):
        return redirect('/login?error=csrf')

    user = get_user_by_username(username.strip())
    if not user or not verify_password(password, user['password_hash']):
        return redirect('/login?error=invalid')

    request.session.clear()
    request.session['user_id'] = int(user['id'])
    request.session['csrf_token'] = secrets.token_urlsafe(24)
    return redirect('/apps')


@app.get('/logout')
def logout(request: Request):
    request.session.clear()
    return redirect('/login')


@app.get('/projects', response_class=HTMLResponse)
def projects_page(
    request: Request,
    project_id: int | None = None,
    view: str = 'all',
):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])
    project_view = normalize_view(view)
    projects = list_accessible_projects(user_id)

    active_project = None
    if project_id is not None:
        active_project = get_accessible_project(project_id, user_id)
        if not active_project and projects:
            return redirect(projects_url(int(projects[0]['id']), project_view, 'project_not_found'))

    if not active_project and projects:
        first_project_id = int(projects[0]['id'])
        active_project = get_accessible_project(first_project_id, user_id)
        project_id = first_project_id

    tasks = []
    members = []
    task_assignees = []
    shareable_users = []
    can_manage = False

    if active_project:
        project_id = int(active_project['id'])
        tasks = list_project_tasks(project_id, project_view)
        members = list_project_members(project_id)
        member_ids = {int(member['id']) for member in members}
        all_users = list_users()
        task_assignees = [u for u in all_users if int(u['id']) in member_ids]
        shareable_users = [u for u in all_users if int(u['id']) not in member_ids]
        can_manage = can_manage_project(user, active_project)

    return templates.TemplateResponse(
        request,
        'projects_app.html',
        {
            'user': user,
            'projects': projects,
            'active_project': active_project,
            'tasks': tasks,
            'members': members,
            'task_assignees': task_assignees,
            'shareable_users': shareable_users,
            'project_view': project_view,
            'can_manage': can_manage,
            'csrf_token': csrf_token(request),
            'error': request.query_params.get('error'),
        },
    )


@app.get('/projects/{project_id}', response_class=HTMLResponse)
def project_compat_redirect(request: Request, project_id: int, view: str = 'all'):
    user, response = require_login(request)
    if response:
        return response
    return redirect(projects_url(project_id, normalize_view(view)))


@app.post('/projects')
def create_project_submit(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=''),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect(projects_url(error='csrf'))

    name = name.strip()
    if not name:
        return redirect(projects_url(error='missing_name'))

    new_id = create_project(name=name, description=description.strip(), created_by=int(user['id']))
    return redirect(projects_url(new_id))


@app.post('/projects/{project_id}/tasks')
def create_task_submit(
    request: Request,
    project_id: int,
    title: str = Form(...),
    description: str = Form(default=''),
    status: str = Form(default='open'),
    assignee_id: str = Form(default=''),
    view: str = Form(default='all'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    active_project = get_accessible_project(project_id, int(user['id']))
    if not active_project:
        return redirect(projects_url(error='project_not_found'))

    title = title.strip()
    if not title:
        return redirect(projects_url(project_id, project_view, 'missing_title'))

    if status not in VALID_TASK_STATUS:
        return redirect(projects_url(project_id, project_view, 'invalid_status'))

    assignee: int | None = None
    assignee_value = assignee_id.strip()
    if assignee_value:
        try:
            assignee = int(assignee_value)
        except ValueError:
            return redirect(projects_url(project_id, project_view, 'invalid_assignee'))

        member_ids = {int(member['id']) for member in list_project_members(project_id)}
        if assignee not in member_ids:
            return redirect(projects_url(project_id, project_view, 'assignee_not_member'))

    create_task(
        project_id=project_id,
        title=title,
        description=description.strip(),
        status=status,
        assignee_id=assignee,
    )
    return redirect(projects_url(project_id, project_view))


@app.post('/tasks/{task_id}/status')
def update_task_status_submit(
    request: Request,
    task_id: int,
    status: str = Form(...),
    project_id: int = Form(...),
    view: str = Form(default='all'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    if status not in VALID_TASK_STATUS:
        return redirect(projects_url(project_id, project_view, 'invalid_status'))

    updated_project_id = update_task_status_if_accessible(task_id, int(user['id']), status)
    if updated_project_id is None:
        return redirect(projects_url(project_id, project_view, 'task_not_found'))

    return redirect(projects_url(updated_project_id, project_view))


@app.post('/projects/{project_id}/share')
def add_project_member_submit(
    request: Request,
    project_id: int,
    target_user_id: int = Form(...),
    member_role: str = Form(default='member'),
    view: str = Form(default='all'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    active_project = get_accessible_project(project_id, int(user['id']))
    if not active_project:
        return redirect(projects_url(error='project_not_found'))

    if not can_manage_project(user, active_project):
        return redirect(projects_url(project_id, project_view, 'forbidden'))

    if member_role not in VALID_MEMBER_ROLES:
        return redirect(projects_url(project_id, project_view, 'invalid_member_role'))

    if not add_project_member(project_id, target_user_id, member_role):
        return redirect(projects_url(project_id, project_view, 'share_failed'))

    return redirect(projects_url(project_id, project_view))


@app.post('/projects/{project_id}/share/{target_user_id}/remove')
def remove_project_member_submit(
    request: Request,
    project_id: int,
    target_user_id: int,
    view: str = Form(default='all'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    active_project = get_accessible_project(project_id, int(user['id']))
    if not active_project:
        return redirect(projects_url(error='project_not_found'))

    if not can_manage_project(user, active_project):
        return redirect(projects_url(project_id, project_view, 'forbidden'))

    if not remove_project_member(project_id, target_user_id):
        return redirect(projects_url(project_id, project_view, 'remove_failed'))

    return redirect(projects_url(project_id, project_view))


@app.get('/users', response_class=HTMLResponse)
def users_page(request: Request):
    user, response = require_admin(request)
    if response:
        return response

    return templates.TemplateResponse(
        request,
        'users.html',
        {
            'user': user,
            'users': list_users(),
            'csrf_token': csrf_token(request),
            'error': request.query_params.get('error'),
        },
    )


@app.post('/users')
def create_user_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(default='user'),
    csrf: str = Form(...),
):
    admin_user, response = require_admin(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/users?error=csrf')

    username = username.strip()
    password = password.strip()
    if not username or not password:
        return redirect('/users?error=missing_fields')

    if role not in VALID_ROLES:
        return redirect('/users?error=invalid_role')

    ok = create_user(username=username, password_hash=hash_password(password), role=role)
    if not ok:
        return redirect('/users?error=user_exists')

    print(f"[info] User created by {admin_user['username']}: {username} ({role})")
    return redirect('/users')


if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8099)
