from __future__ import annotations

import json
import mimetypes
import secrets
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import uvicorn
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.middleware.sessions import SessionMiddleware

from auth import hash_password, verify_password
from db import (
    add_project_member,
    create_attachment,
    create_fs_file,
    create_project,
    create_task,
    create_user,
    delete_fs_file_if_owner,
    ensure_admin_account,
    ensure_admin_credentials,
    ensure_fs_folder_path,
    fs_usage_for_user,
    get_accessible_project,
    get_attachment_if_accessible,
    get_fs_file,
    get_fs_folder,
    has_fs_folder_access,
    get_task_if_accessible,
    get_user_by_id,
    get_user_by_username,
    get_or_create_fs_folder,
    init_db,
    list_accessible_projects,
    list_fs_accessible_root_folders,
    list_fs_breadcrumbs,
    list_fs_descendant_folders,
    list_fs_files_for_folders,
    list_fs_files,
    list_fs_folder_members,
    list_fs_folders,
    list_fs_shareable_users,
    list_project_attachments,
    list_project_history,
    list_project_members,
    list_project_tasks,
    list_users,
    remove_project_member,
    share_fs_folder,
    stats,
    unshare_fs_folder,
    update_project,
    update_task_if_accessible,
    update_task_status_if_accessible,
)

DATA_DIR = Path('/data')
OPTIONS_PATH = DATA_DIR / 'options.json'
SECRET_KEY_PATH = DATA_DIR / 'secret_key'
FILESHARE_DIR = DATA_DIR / 'fileshare'
MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024
MAX_FILESHARE_BYTES = 300 * 1024 * 1024
USER_FILESHARE_QUOTA_BYTES = 2 * 1024 * 1024 * 1024
VALID_ROLES = {'admin', 'user'}
VALID_MEMBER_ROLES = {'member', 'manager'}
VALID_TASK_STATUS = {'open', 'in_progress', 'done'}
VALID_PROJECT_VIEWS = {'all', 'open', 'done', 'focus'}

app = FastAPI(title='Household Tool')
app.mount('/static', StaticFiles(directory='/app/static'), name='static')
templates = Jinja2Templates(directory='/app/templates')


def load_options() -> dict[str, Any]:
    if not OPTIONS_PATH.exists():
        return {}
    try:
        return json.loads(OPTIONS_PATH.read_text(encoding='utf-8'))
    except Exception as err:  # pragma: no cover
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


def parse_optional_int(raw: str | None) -> int | None:
    value = (raw or '').strip()
    if not value:
        return None
    return int(value)



def files_url(folder_id: int | None = None, error: str | None = None) -> str:
    params: dict[str, str] = {}
    if folder_id is not None:
        params['folder_id'] = str(folder_id)
    if error:
        params['error'] = error
    return '/files' + (f"?{urlencode(params)}" if params else '')


def parse_optional_folder_id(raw: str | None) -> int | None:
    value = (raw or '').strip()
    if not value:
        return None
    return int(value)


def normalize_name(raw: str, fallback: str) -> str:
    name = Path(raw.strip()).name.strip()
    if not name or name in {'.', '..'}:
        return fallback
    return name[:160]


def split_relative_dir(relative_path: str) -> list[str]:
    cleaned = relative_path.strip().replace('\\', '/').strip('/')
    if not cleaned:
        return []

    parts = cleaned.split('/')
    if parts:
        parts = parts[:-1]

    result: list[str] = []
    for part in parts:
        segment = part.strip()
        if not segment or segment in {'.', '..'}:
            continue
        result.append(segment[:160])
    return result


def format_bytes(num: int) -> str:
    value = float(max(num, 0))
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == 'B':
                return f'{int(value)} {unit}'
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{num} B'


def is_image_mime(mime: str) -> bool:
    return mime.startswith('image/')


def zip_safe_name(raw: str, fallback: str) -> str:
    name = raw.replace('\\', '/').strip().strip('/')
    name = Path(name).name.strip()
    if not name or name in {'.', '..'}:
        name = fallback
    return name.replace('/', '_')


def _remove_temp_file(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


def create_folder_zip(folder_id: int, user_id: int, zip_prefix: str | None = None) -> tuple[Path | None, str]:
    folders = list_fs_descendant_folders(folder_id, user_id)
    if not folders:
        return None, 'folder_not_found'

    folder_by_id = {int(row['id']): row for row in folders}
    root = folder_by_id.get(folder_id)
    if not root:
        return None, 'folder_not_found'

    prefix = zip_safe_name(zip_prefix or str(root['name']), f'folder-{folder_id}')
    folder_ids = sorted(folder_by_id.keys())
    files = list_fs_files_for_folders(folder_ids)

    _fd, temp_path = tempfile.mkstemp(prefix='household-folder-', suffix='.zip')
    Path(temp_path).unlink(missing_ok=True)
    zip_path = Path(temp_path)

    relative_folder: dict[int, str] = {folder_id: prefix}
    unresolved = set(folder_ids)
    while unresolved:
        progressed = False
        for current_id in list(unresolved):
            if current_id == folder_id:
                unresolved.remove(current_id)
                progressed = True
                continue

            row = folder_by_id[current_id]
            parent = row['parent_id']
            if parent is None:
                relative_folder[current_id] = f"{prefix}/{zip_safe_name(str(row['name']), f'folder-{current_id}')}"
                unresolved.remove(current_id)
                progressed = True
                continue

            parent_id = int(parent)
            if parent_id in relative_folder:
                name = zip_safe_name(str(row['name']), f'folder-{current_id}')
                relative_folder[current_id] = f"{relative_folder[parent_id]}/{name}"
                unresolved.remove(current_id)
                progressed = True
        if not progressed:
            break

    with zipfile.ZipFile(zip_path, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
        for current_id in folder_ids:
            folder_path = relative_folder.get(current_id, prefix)
            archive.writestr(f'{folder_path}/', '')

        for item in files:
            stored_name = str(item['stored_name'])
            file_disk_path = FILESHARE_DIR / stored_name
            if not file_disk_path.exists() or not file_disk_path.is_file():
                continue

            folder_path = relative_folder.get(int(item['folder_id']), prefix)
            target_name = zip_safe_name(str(item['original_name']), f"file-{item['id']}")
            archive_name = f'{folder_path}/{target_name}'
            archive.write(file_disk_path, archive_name)

    return zip_path, f'{prefix}.zip'


def build_project_nav(projects: list[Any]) -> list[dict[str, Any]]:
    by_id: dict[int, dict[str, Any]] = {}
    children: dict[int | None, list[dict[str, Any]]] = defaultdict(list)

    for row in projects:
        item = dict(row)
        item['parent_id'] = int(item['parent_id']) if item['parent_id'] is not None else None
        by_id[int(item['id'])] = item

    for item in by_id.values():
        parent_id = item['parent_id']
        if parent_id in by_id and parent_id != item['id']:
            children[parent_id].append(item)
        else:
            children[None].append(item)

    for key in children:
        children[key].sort(key=lambda x: (str(x.get('name', '')).lower(), int(x['id'])))

    flattened: list[dict[str, Any]] = []
    visited: set[int] = set()

    def walk(parent_id: int | None, depth: int) -> None:
        for child in children.get(parent_id, []):
            child_id = int(child['id'])
            if child_id in visited:
                continue
            visited.add(child_id)
            entry = dict(child)
            entry['depth'] = depth
            flattened.append(entry)
            walk(child_id, depth + 1)

    walk(None, 0)

    # Safety for orphan/cycle leftovers
    for item_id, item in by_id.items():
        if item_id in visited:
            continue
        entry = dict(item)
        entry['depth'] = 0
        flattened.append(entry)

    return flattened


def project_descendants(projects: list[Any], root_id: int) -> set[int]:
    children: dict[int, list[int]] = defaultdict(list)
    for row in projects:
        pid = row['parent_id']
        if pid is None:
            continue
        pid_i = int(pid)
        cid_i = int(row['id'])
        if pid_i != cid_i:
            children[pid_i].append(cid_i)

    result: set[int] = set()
    stack = [root_id]
    while stack:
        current = stack.pop()
        for cid in children.get(current, []):
            if cid in result:
                continue
            result.add(cid)
            stack.append(cid)
    return result


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
    FILESHARE_DIR.mkdir(parents=True, exist_ok=True)
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
    project_nav = build_project_nav(projects)

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
    history = []
    members = []
    task_assignees = []
    shareable_users = []
    parent_options_new = [dict(p) for p in project_nav]
    parent_options_edit = []
    attachments_by_task: dict[int, list[Any]] = defaultdict(list)
    can_manage = False

    if active_project:
        project_id = int(active_project['id'])
        tasks = list_project_tasks(project_id, project_view)
        history = list_project_history(project_id)
        members = list_project_members(project_id)
        member_ids = {int(member['id']) for member in members}
        all_users = list_users()
        task_assignees = [u for u in all_users if int(u['id']) in member_ids]
        shareable_users = [u for u in all_users if int(u['id']) not in member_ids]
        can_manage = can_manage_project(user, active_project)

        descendants = project_descendants(projects, project_id)
        for candidate in project_nav:
            cid = int(candidate['id'])
            if cid == project_id or cid in descendants:
                continue
            parent_options_edit.append(candidate)

        for attachment in list_project_attachments(project_id):
            attachments_by_task[int(attachment['task_id'])].append(attachment)

    return templates.TemplateResponse(
        request,
        'projects_app.html',
        {
            'user': user,
            'projects': project_nav,
            'active_project': active_project,
            'tasks': tasks,
            'history': history,
            'members': members,
            'task_assignees': task_assignees,
            'shareable_users': shareable_users,
            'parent_options_new': parent_options_new,
            'parent_options_edit': parent_options_edit,
            'attachments_by_task': attachments_by_task,
            'project_view': project_view,
            'can_manage': can_manage,
            'max_attachment_mb': MAX_ATTACHMENT_BYTES // (1024 * 1024),
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
    parent_id: str = Form(default=''),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect(projects_url(error='csrf'))

    title = name.strip()
    if not title:
        return redirect(projects_url(error='missing_name'))

    new_parent_id: int | None = None
    if parent_id.strip():
        try:
            new_parent_id = int(parent_id)
        except ValueError:
            return redirect(projects_url(error='invalid_parent'))

        parent_project = get_accessible_project(new_parent_id, int(user['id']))
        if not parent_project:
            return redirect(projects_url(error='invalid_parent'))

    new_id = create_project(
        name=title,
        description=description.strip(),
        created_by=int(user['id']),
        parent_id=new_parent_id,
    )
    return redirect(projects_url(new_id))


@app.post('/projects/{project_id}/edit')
def edit_project_submit(
    request: Request,
    project_id: int,
    name: str = Form(...),
    description: str = Form(default=''),
    parent_id: str = Form(default=''),
    view: str = Form(default='all'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    project = get_accessible_project(project_id, int(user['id']))
    if not project:
        return redirect(projects_url(error='project_not_found'))
    if not can_manage_project(user, project):
        return redirect(projects_url(project_id, project_view, 'forbidden'))

    title = name.strip()
    if not title:
        return redirect(projects_url(project_id, project_view, 'missing_name'))

    all_projects = list_accessible_projects(int(user['id']))
    descendants = project_descendants(all_projects, project_id)

    new_parent_id: int | None = None
    if parent_id.strip():
        try:
            new_parent_id = int(parent_id)
        except ValueError:
            return redirect(projects_url(project_id, project_view, 'invalid_parent'))

        if new_parent_id == project_id or new_parent_id in descendants:
            return redirect(projects_url(project_id, project_view, 'invalid_parent'))

        parent_project = get_accessible_project(new_parent_id, int(user['id']))
        if not parent_project:
            return redirect(projects_url(project_id, project_view, 'invalid_parent'))

    update_project(
        project_id=project_id,
        name=title,
        description=description.strip(),
        parent_id=new_parent_id,
    )
    return redirect(projects_url(project_id, project_view))


@app.post('/projects/{project_id}/tasks')
def create_task_submit(
    request: Request,
    project_id: int,
    title: str = Form(...),
    description: str = Form(default=''),
    status: str = Form(default='open'),
    assignee_id: str = Form(default=''),
    focus: str = Form(default='0'),
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

    task_title = title.strip()
    if not task_title:
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
        title=task_title,
        description=description.strip(),
        status=status,
        assignee_id=assignee,
        focus=focus == '1',
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


@app.post('/tasks/{task_id}/edit')
def edit_task_submit(
    request: Request,
    task_id: int,
    title: str = Form(...),
    description: str = Form(default=''),
    status: str = Form(default='open'),
    assignee_id: str = Form(default=''),
    focus: str = Form(default='0'),
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

    task_title = title.strip()
    if not task_title:
        return redirect(projects_url(project_id, project_view, 'missing_title'))

    if status not in VALID_TASK_STATUS:
        return redirect(projects_url(project_id, project_view, 'invalid_status'))

    task = get_task_if_accessible(task_id, int(user['id']))
    if not task:
        return redirect(projects_url(project_id, project_view, 'task_not_found'))

    actual_project_id = int(task['project_id'])
    member_ids = {int(member['id']) for member in list_project_members(actual_project_id)}

    assignee: int | None = None
    assignee_value = assignee_id.strip()
    if assignee_value:
        try:
            assignee = int(assignee_value)
        except ValueError:
            return redirect(projects_url(actual_project_id, project_view, 'invalid_assignee'))
        if assignee not in member_ids:
            return redirect(projects_url(actual_project_id, project_view, 'assignee_not_member'))

    updated_project_id = update_task_if_accessible(
        task_id=task_id,
        user_id=int(user['id']),
        title=task_title,
        description=description.strip(),
        status=status,
        assignee_id=assignee,
        focus=focus == '1',
    )
    if updated_project_id is None:
        return redirect(projects_url(project_id, project_view, 'task_not_found'))

    return redirect(projects_url(updated_project_id, project_view))


@app.post('/tasks/{task_id}/attachments')
async def upload_attachment_submit(
    request: Request,
    task_id: int,
    project_id: int = Form(...),
    view: str = Form(default='all'),
    csrf: str = Form(...),
    file: UploadFile = File(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    task = get_task_if_accessible(task_id, int(user['id']))
    if not task:
        return redirect(projects_url(project_id, project_view, 'task_not_found'))

    if not file.filename:
        return redirect(projects_url(int(task['project_id']), project_view, 'missing_file'))

    content = await file.read(MAX_ATTACHMENT_BYTES + 1)
    if len(content) > MAX_ATTACHMENT_BYTES:
        return redirect(projects_url(int(task['project_id']), project_view, 'file_too_large'))

    filename = Path(file.filename).name.strip() or 'attachment.bin'
    mime = (file.content_type or 'application/octet-stream').strip()
    create_attachment(task_id, filename, mime, len(content), content)
    return redirect(projects_url(int(task['project_id']), project_view))


@app.get('/attachments/{attachment_id}/download')
def download_attachment(request: Request, attachment_id: int):
    user, response = require_login(request)
    if response:
        return response

    attachment = get_attachment_if_accessible(attachment_id, int(user['id']))
    if not attachment:
        return HTMLResponse('Attachment not found', status_code=404)

    filename = str(attachment['filename']).replace('"', '').replace('\n', '')
    headers = {'Content-Disposition': f'attachment; filename="{filename}"'}
    return Response(
        content=attachment['content'],
        media_type=str(attachment['mime']) or 'application/octet-stream',
        headers=headers,
    )


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



@app.get('/files', response_class=HTMLResponse)
def files_page(request: Request, folder_id: int | None = None):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])

    active_folder = None
    if folder_id is not None:
        active_folder = get_fs_folder(folder_id, user_id)
        if not active_folder:
            return redirect(files_url(error='folder_not_found'))

    folders = list_fs_folders(folder_id, user_id)
    files = [dict(item) for item in list_fs_files(folder_id, user_id)]
    for item in files:
        item['is_image'] = is_image_mime(str(item.get('mime') or ''))

    breadcrumbs = list_fs_breadcrumbs(folder_id, user_id)
    usage_bytes = fs_usage_for_user(user_id)
    quota_bytes = USER_FILESHARE_QUOTA_BYTES
    free_bytes = max(0, quota_bytes - usage_bytes)
    usage_percent = min(100, int((usage_bytes / quota_bytes) * 100)) if quota_bytes else 0

    can_manage_share = bool(
        active_folder
        and (user['role'] == 'admin' or int(active_folder['created_by']) == user_id)
    )
    folder_members = list_fs_folder_members(int(active_folder['id']), user_id) if active_folder else []
    shareable_users = list_fs_shareable_users(int(active_folder['id']), user_id) if active_folder else []

    return templates.TemplateResponse(
        request,
        'files_app.html',
        {
            'user': user,
            'active_folder': active_folder,
            'folders': folders,
            'files': files,
            'breadcrumbs': breadcrumbs,
            'usage_bytes': usage_bytes,
            'usage_text': format_bytes(usage_bytes),
            'quota_bytes': quota_bytes,
            'quota_text': format_bytes(quota_bytes),
            'free_bytes': free_bytes,
            'free_text': format_bytes(free_bytes),
            'usage_percent': usage_percent,
            'max_file_mb': MAX_FILESHARE_BYTES // (1024 * 1024),
            'can_manage_share': can_manage_share,
            'folder_members': folder_members,
            'shareable_users': shareable_users,
            'csrf_token': csrf_token(request),
            'files_error': request.query_params.get('error'),
        },
    )


@app.post('/files/folders')
def create_folder_submit(
    request: Request,
    name: str = Form(...),
    parent_id: str = Form(default=''),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])

    if not validate_csrf(request, csrf):
        return redirect(files_url(error='csrf'))

    try:
        parent_folder_id = parse_optional_folder_id(parent_id)
    except ValueError:
        return redirect(files_url(error='invalid_parent'))

    if parent_folder_id is not None and not has_fs_folder_access(parent_folder_id, user_id):
        return redirect(files_url(error='forbidden'))

    folder_name = name.strip()
    if not folder_name:
        return redirect(files_url(parent_folder_id, 'missing_name'))

    try:
        created_id = get_or_create_fs_folder(parent_folder_id, folder_name, user_id)
    except PermissionError:
        return redirect(files_url(parent_folder_id, 'forbidden'))

    return redirect(files_url(created_id))


@app.post('/files/upload')
async def upload_files_submit(
    request: Request,
    parent_id: str = Form(default=''),
    relative_path: list[str] = Form(default=[]),
    csrf: str = Form(...),
    files: list[UploadFile] = File(default=[]),
):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])

    if not validate_csrf(request, csrf):
        return redirect(files_url(error='csrf'))

    try:
        parent_folder_id = parse_optional_folder_id(parent_id)
    except ValueError:
        return redirect(files_url(error='invalid_parent'))

    if parent_folder_id is not None and not has_fs_folder_access(parent_folder_id, user_id):
        return redirect(files_url(error='forbidden'))

    if not files:
        return redirect(files_url(parent_folder_id, 'missing_file'))

    uploaded = 0
    usage_total = fs_usage_for_user(user_id)
    upload_error: str | None = None

    try:
        for idx, upload in enumerate(files):
            if not upload.filename:
                await upload.close()
                continue

            original_name = normalize_name(upload.filename, f'upload-{idx + 1}.bin')
            rel_path = relative_path[idx] if idx < len(relative_path) else ''
            target_parts = split_relative_dir(rel_path)
            target_folder_id = ensure_fs_folder_path(parent_folder_id, target_parts, user_id)

            guessed_mime = mimetypes.guess_type(original_name)[0]
            mime = (upload.content_type or guessed_mime or 'application/octet-stream').strip()[:255]
            stored_name = secrets.token_hex(24)
            target_path = FILESHARE_DIR / stored_name

            too_large = False
            quota_exceeded = False
            file_size = 0

            with target_path.open('wb') as fh:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    file_size += len(chunk)

                    if file_size > MAX_FILESHARE_BYTES:
                        too_large = True
                        break

                    if usage_total + file_size > USER_FILESHARE_QUOTA_BYTES:
                        quota_exceeded = True
                        break

                    fh.write(chunk)

            await upload.close()

            if too_large or quota_exceeded:
                if target_path.exists():
                    target_path.unlink()
                upload_error = 'file_too_large' if too_large else 'quota_exceeded'
                break

            create_fs_file(
                folder_id=target_folder_id,
                stored_name=stored_name,
                original_name=original_name,
                mime=mime,
                size=file_size,
                uploaded_by=user_id,
            )
            usage_total += file_size
            uploaded += 1
    except PermissionError:
        return redirect(files_url(parent_folder_id, 'forbidden'))
    except Exception as err:  # pragma: no cover
        print(f'[error] Upload failed: {err}')
        return redirect(files_url(parent_folder_id, 'upload_failed'))

    if upload_error:
        return redirect(files_url(parent_folder_id, upload_error))

    if uploaded == 0:
        return redirect(files_url(parent_folder_id, 'missing_file'))

    return redirect(files_url(parent_folder_id))


@app.get('/files/{file_id}/download')
def files_download(request: Request, file_id: int):
    user, response = require_login(request)
    if response:
        return response

    item = get_fs_file(file_id, int(user['id']))
    if not item:
        return HTMLResponse('File not found', status_code=404)

    file_path = FILESHARE_DIR / str(item['stored_name'])
    if not file_path.exists() or not file_path.is_file():
        return HTMLResponse('Stored file missing', status_code=404)

    filename = str(item['original_name']).replace('\"', '').replace('\n', '')
    headers = {'Content-Disposition': f'attachment; filename="{filename}"'}
    return FileResponse(
        path=file_path,
        media_type=str(item['mime']) or 'application/octet-stream',
        filename=filename,
        headers=headers,
    )


@app.get('/files/{file_id}/view')
def files_view(request: Request, file_id: int):
    user, response = require_login(request)
    if response:
        return response

    item = get_fs_file(file_id, int(user['id']))
    if not item:
        return HTMLResponse('File not found', status_code=404)

    file_path = FILESHARE_DIR / str(item['stored_name'])
    if not file_path.exists() or not file_path.is_file():
        return HTMLResponse('Stored file missing', status_code=404)

    filename = str(item['original_name']).replace('\"', '').replace('\n', '')
    headers = {'Content-Disposition': f'inline; filename="{filename}"'}
    return FileResponse(
        path=file_path,
        media_type=str(item['mime']) or 'application/octet-stream',
        filename=filename,
        headers=headers,
    )


@app.get('/files/folders/{folder_id}/download')
def download_folder_zip(request: Request, folder_id: int):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])
    zip_path, zip_name_or_error = create_folder_zip(folder_id, user_id)
    if not zip_path:
        return redirect(files_url(folder_id, zip_name_or_error))

    return FileResponse(
        path=zip_path,
        media_type='application/zip',
        filename=zip_name_or_error,
        background=BackgroundTask(_remove_temp_file, str(zip_path)),
    )


@app.get('/files/download-all')
def download_all_folders_zip(request: Request):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])
    roots = list_fs_accessible_root_folders(user_id)
    if not roots:
        return redirect(files_url(error='no_folders'))

    _fd, temp_path = tempfile.mkstemp(prefix='household-all-folders-', suffix='.zip')
    Path(temp_path).unlink(missing_ok=True)
    zip_path = Path(temp_path)

    with zipfile.ZipFile(zip_path, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
        added = False
        for root in roots:
            root_id = int(root['id'])
            folders = list_fs_descendant_folders(root_id, user_id)
            if not folders:
                continue

            folder_by_id = {int(row['id']): row for row in folders}
            prefix = zip_safe_name(str(root['name']), f'folder-{root_id}')
            relative_folder: dict[int, str] = {root_id: prefix}
            unresolved = set(folder_by_id.keys())

            while unresolved:
                progressed = False
                for current_id in list(unresolved):
                    if current_id == root_id:
                        unresolved.remove(current_id)
                        progressed = True
                        continue

                    row = folder_by_id[current_id]
                    parent = row['parent_id']
                    if parent is None:
                        relative_folder[current_id] = f"{prefix}/{zip_safe_name(str(row['name']), f'folder-{current_id}')}"
                        unresolved.remove(current_id)
                        progressed = True
                        continue

                    parent_id = int(parent)
                    if parent_id in relative_folder:
                        relative_folder[current_id] = f"{relative_folder[parent_id]}/{zip_safe_name(str(row['name']), f'folder-{current_id}')}"
                        unresolved.remove(current_id)
                        progressed = True
                if not progressed:
                    break

            folder_ids = sorted(folder_by_id.keys())
            for fid in folder_ids:
                archive.writestr(f"{relative_folder.get(fid, prefix)}/", '')

            for item in list_fs_files_for_folders(folder_ids):
                file_disk_path = FILESHARE_DIR / str(item['stored_name'])
                if not file_disk_path.exists() or not file_disk_path.is_file():
                    continue
                base = relative_folder.get(int(item['folder_id']), prefix)
                file_name = zip_safe_name(str(item['original_name']), f"file-{item['id']}")
                archive.write(file_disk_path, f'{base}/{file_name}')
                added = True

        if not added:
            archive.writestr('README.txt', 'Keine Dateien vorhanden.')

    return FileResponse(
        path=zip_path,
        media_type='application/zip',
        filename='household-folders.zip',
        background=BackgroundTask(_remove_temp_file, str(zip_path)),
    )


@app.post('/files/{file_id}/delete')
def delete_file_submit(
    request: Request,
    file_id: int,
    folder_id: str = Form(default=''),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    try:
        redirect_folder_id = parse_optional_folder_id(folder_id)
    except ValueError:
        redirect_folder_id = None

    if not validate_csrf(request, csrf):
        return redirect(files_url(redirect_folder_id, 'csrf'))

    row = delete_fs_file_if_owner(file_id, int(user['id']))
    if not row:
        existing = get_fs_file(file_id, int(user['id']))
        if existing:
            return redirect(files_url(redirect_folder_id, 'forbidden_delete'))
        return redirect(files_url(redirect_folder_id, 'file_not_found'))

    file_path = FILESHARE_DIR / str(row['stored_name'])
    if file_path.exists() and file_path.is_file():
        file_path.unlink()

    return redirect(files_url(redirect_folder_id))


@app.post('/files/{folder_id}/share')
def share_folder_submit(
    request: Request,
    folder_id: int,
    target_user_id: int = Form(...),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect(files_url(folder_id, 'csrf'))

    if not share_fs_folder(folder_id, int(user['id']), target_user_id):
        return redirect(files_url(folder_id, 'share_failed'))

    return redirect(files_url(folder_id))


@app.post('/files/{folder_id}/share/{target_user_id}/remove')
def unshare_folder_submit(
    request: Request,
    folder_id: int,
    target_user_id: int,
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect(files_url(folder_id, 'csrf'))

    if not unshare_fs_folder(folder_id, int(user['id']), target_user_id):
        return redirect(files_url(folder_id, 'remove_failed'))

    return redirect(files_url(folder_id))


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
