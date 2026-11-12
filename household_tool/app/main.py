from __future__ import annotations

import asyncio
import calendar as calendar_module
import json
import os
import mimetypes
import secrets
import tempfile
import threading
import zipfile
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, quote

import uvicorn
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.middleware.sessions import SessionMiddleware

from auth import hash_password, verify_password
from db import (
    add_project_member,
    add_task_checklist_item,
    add_task_dependency,
    normalize_schedule,
    update_task_schedule,
    remove_task_dependency,
    edit_project_milestone,
    task_list_previews,
    create_attachment,
    create_fs_file,
    create_milestone,
    create_project,
    create_task,
    create_task_comment,
    create_task_from_template,
    create_task_template,
    create_user,
    delete_user_with_reassignment,
    delete_fs_file_if_owner,
    ensure_admin_account,
    ensure_admin_credentials,
    ensure_fs_folder_path,
    find_reassignment_user,
    fs_usage_for_user,
    get_accessible_project,
    get_attachment_if_accessible,
    get_fs_file,
    get_fs_folder,
    has_fs_folder_access,
    get_task_if_accessible,
    get_task_detail_if_accessible,
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
    list_project_checklist_items,
    list_project_comments,
    list_project_dependencies,
    list_project_events,
    list_project_history,
    list_project_members,
    list_project_milestones,
    list_project_tasks,
    list_my_tasks,
    list_task_template_items,
    list_task_templates,
    list_task_comments,
    list_task_events,
    list_task_checklist_items,
    count_my_tasks,
    count_project_tasks,
    normalize_deadline,
    project_today,
    set_task_checklist_item_done,
    list_music_tracks,
    list_users,
    music_stats,
    remove_music_track,
    remove_project_member,
    share_fs_folder,
    stats,
    unshare_fs_folder,
    update_user_profile,
    update_user_by_admin,
    update_project,
    update_task_if_accessible,
    update_task_status_if_accessible,
    upsert_music_track,
)
from models import MusicTrackIngest, music_track_url
import db
import reminders
from planning import build_plan

DATA_DIR = Path(os.environ.get('HOUSEHOLD_DATA_DIR', '/data'))
OPTIONS_PATH = DATA_DIR / 'options.json'
SECRET_KEY_PATH = DATA_DIR / 'secret_key'
FILESHARE_DIR = DATA_DIR / 'fileshare'
MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024
MAX_FILESHARE_BYTES = 300 * 1024 * 1024
USER_FILESHARE_QUOTA_BYTES = 2 * 1024 * 1024 * 1024
VALID_ROLES = {'admin', 'user'}
VALID_MEMBER_ROLES = {'member', 'manager'}
VALID_TASK_STATUS = {'open', 'in_progress', 'done'}
VALID_PRIORITIES = {'low', 'normal', 'high'}
VALID_RECURRENCES = {'daily', 'weekly', 'monthly'}
VALID_PROJECT_VIEWS = {'all', 'open', 'done', 'history', 'focus', 'today', 'tomorrow', 'overdue', 'in_progress', 'kanban', 'calendar', 'timeline'}
VALID_MY_TASK_VIEWS = {'all', 'open', 'in_progress', 'focus', 'today', 'tomorrow', 'overdue', 'history'}
MIN_PASSWORD_LENGTH = 8

app = FastAPI(title='Household Tool')
APP_DIR = Path(__file__).resolve().parent
app.mount('/static', StaticFiles(directory=APP_DIR / 'static'), name='static')
templates = Jinja2Templates(directory=APP_DIR / 'templates')


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


def validate_music_ingest_token(authorization: str | None) -> None:
    expected = str(load_options().get('music_ingest_token') or '').strip()
    if not expected:
        raise HTTPException(status_code=503, detail='Music ingest is not configured')
    scheme, _, supplied = (authorization or '').partition(' ')
    if scheme.casefold() != 'bearer' or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail='Invalid music ingest token')


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
    if view == 'done':
        return 'history'
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


def task_return_url(task_id: int, return_to: str, project_id: int, view: str = 'all',
                    error: str | None = None) -> str:
    if return_to == 'task':
        return f'/tasks/{task_id}' + (f'?{urlencode({"error": error})}' if error else '')
    return projects_url(project_id, view, error)


@app.post('/tasks/{task_id}/schedule')
def schedule_task_submit(request: Request, task_id: int, csrf: str = Form(...),
                         start_date: str = Form(default=''), end_date: str = Form(default=''),
                         return_to: str = Form(default='task'), anchor: str = Form(default=''),
                         scale: str = Form(default='week')):
    user, response = require_login(request)
    if response:
        return response
    task = get_task_detail_if_accessible(task_id, int(user['id']))
    if not task:
        raise HTTPException(status_code=404, detail='Aufgabe nicht gefunden')
    destination = f'/tasks/{task_id}'
    if return_to == 'timeline':
        params = {'project_id': task['project_id'], 'view': 'timeline', 'scale': scale}
        if anchor:
            params['anchor'] = anchor
        destination = '/projects?' + urlencode(params)
    error = None
    if not validate_csrf(request, csrf):
        error = 'csrf'
    else:
        try:
            if not update_task_schedule(task_id, int(user['id']), start_date or None, end_date or None):
                raise HTTPException(status_code=404, detail='Aufgabe nicht gefunden')
        except ValueError:
            error = 'invalid_schedule'
    if error:
        destination += ('&' if '?' in destination else '?') + urlencode({'error': error})
    return redirect(destination)


@app.post('/tasks/{task_id}/dependencies/{dependency_id}/remove')
def remove_dependency_submit(request: Request, task_id: int, dependency_id: int, csrf: str = Form(...)):
    user, response = require_login(request)
    if response:
        return response
    if not get_task_if_accessible(task_id, int(user['id'])):
        raise HTTPException(status_code=404, detail='Aufgabe nicht gefunden')
    if not validate_csrf(request, csrf):
        return redirect(f'/tasks/{task_id}?error=csrf')
    if not remove_task_dependency(task_id, dependency_id, int(user['id'])):
        raise HTTPException(status_code=404, detail='Abhängigkeit nicht gefunden')
    return redirect(f'/tasks/{task_id}')


@app.post('/projects/{project_id}/milestones/{milestone_id}/edit')
def edit_milestone_submit(request: Request, project_id: int, milestone_id: int,
                          csrf: str = Form(...), name: str = Form(default=''),
                          due_date: str = Form(default=''), action: str = Form(default='save'),
                          view: str = Form(default='timeline')):
    user, response = require_login(request)
    if response:
        return response
    project = get_accessible_project(project_id, int(user['id']))
    if not project:
        raise HTTPException(status_code=404, detail='Projekt nicht gefunden')
    if not can_manage_project(user, project):
        raise HTTPException(status_code=403, detail='Projektverwaltung erforderlich')
    destination = projects_url(project_id, normalize_view(view))
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, normalize_view(view), 'csrf'))
    if action not in {'save', 'delete'} or (action == 'save' and not name.strip()):
        return redirect(projects_url(project_id, normalize_view(view), 'missing_milestone_name'))
    try:
        changed = edit_project_milestone(project_id, milestone_id, name.strip(), due_date or None,
                                         int(user['id']), delete=action == 'delete')
    except ValueError:
        return redirect(projects_url(project_id, normalize_view(view), 'invalid_milestone_date'))
    if not changed:
        raise HTTPException(status_code=404, detail='Meilenstein nicht gefunden')
    return redirect(destination)


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


def parse_month(value: str | None) -> date:
    if value:
        try:
            year, month = value.strip().split('-')
            year_i, month_i = int(year), int(month)
            if 1 <= year_i <= 9999 and 1 <= month_i <= 12:
                return date(year_i, month_i, 1)
        except (ValueError, AttributeError):
            pass
    today = project_today()
    return date(today.year, today.month, 1)


def shift_month(month_start: date, delta: int) -> date | None:
    total = month_start.year * 12 + (month_start.month - 1) + delta
    new_year, remainder = divmod(total, 12)
    new_month = remainder + 1
    if not (1 <= new_year <= 9999):
        return None
    return date(new_year, new_month, 1)


def build_calendar(month_start: date, tasks_by_deadline: dict[str, list[Any]]) -> list[list[dict[str, Any]]]:
    try:
        cal = calendar_module.Calendar(firstweekday=0)  # Montag als Wochenstart
        weeks: list[list[dict[str, Any]]] = []
        for week in cal.monthdatescalendar(month_start.year, month_start.month):
            cells: list[dict[str, Any]] = []
            for day in week:
                cells.append({
                    'day': day,
                    'in_month': day.month == month_start.month,
                    'tasks': tasks_by_deadline.get(day.isoformat(), []),
                })
            weeks.append(cells)
        return weeks
    except (ValueError, OverflowError):
        return []



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
    os.close(_fd)
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


REMINDER_INTERVAL_SECONDS = 300
_reminder_stop = threading.Event()
_reminder_thread: threading.Thread | None = None


def _run_reminders_once() -> None:
    try:
        reminders.run_reminder_once(options=load_options(), stop_event=_reminder_stop)
    except Exception:
        print('[reminders] run failed; retry on next interval')


def _schedule_reminder_loop() -> None:
    global _reminder_thread
    if _reminder_thread is not None and _reminder_thread.is_alive():
        return
    _reminder_stop.clear()

    def worker() -> None:
        while not _reminder_stop.is_set():
            _run_reminders_once()
            if _reminder_stop.wait(REMINDER_INTERVAL_SECONDS):
                break

    _reminder_thread = threading.Thread(target=worker, name='household-reminders', daemon=True)
    _reminder_thread.start()


@app.on_event('shutdown')
async def on_shutdown() -> None:
    global _reminder_thread
    _reminder_stop.set()
    if _reminder_thread is not None:
        await asyncio.to_thread(_reminder_thread.join)
        _reminder_thread = None


@app.on_event('startup')
def on_startup() -> None:
    init_db()
    ensure_initial_admin()
    FILESHARE_DIR.mkdir(parents=True, exist_ok=True)
    _schedule_reminder_loop()
    print('[info] Database ready at /data/app.db')


@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    if current_user(request):
        return redirect('/apps')
    return redirect('/login')


@app.post('/api/music/tracks')
def ingest_music_track(
    payload: MusicTrackIngest,
    authorization: str | None = Header(default=None),
):
    validate_music_ingest_token(authorization)
    track = payload.track
    if not str(track.get('identity') or '').strip():
        raise HTTPException(status_code=422, detail='track.identity is required')
    if not str(track.get('title') or '').strip() or not str(track.get('artist') or '').strip():
        raise HTTPException(status_code=422, detail='track title and artist are required')
    upsert_music_track(payload.model_dump())
    return {'status': 'ok', 'track_key': str(track['identity'])}


@app.delete('/api/music/tracks')
def delete_music_track(
    track_key: str,
    authorization: str | None = Header(default=None),
):
    validate_music_ingest_token(authorization)
    key = track_key.strip()
    if not key:
        raise HTTPException(status_code=422, detail='track_key is required')
    remove_music_track(key)
    return {'status': 'ok', 'track_key': key}


@app.get('/music', response_class=HTMLResponse)
def music_page(request: Request, view: str = 'favorites', q: str = ''):
    user, response = require_login(request)
    if response:
        return response
    selected_view = 'all' if view == 'all' else 'favorites'
    tracks = list_music_tracks(selected_view == 'favorites', q)
    for track in tracks:
        track['external_url'] = music_track_url(
            track.get('uri'), track.get('artist'), track.get('title')
        )
    return templates.TemplateResponse(
        request,
        'music.html',
        {
            'user': user,
            'tracks': tracks,
            'music_stats': music_stats(),
            'view': selected_view,
            'query': q.strip(),
            'csrf_token': csrf_token(request),
        },
    )


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
    month: str | None = None,
    page: int = 1,
    q: str = '',
    anchor: str | None = None,
    scale: str = 'week',
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

    plan = None
    tasks = []
    members = []
    task_assignees = []
    shareable_users = []
    parent_options_new = [dict(p) for p in project_nav]
    parent_options_edit = []
    attachments_by_task: dict[int, list[Any]] = defaultdict(list)
    comments_by_task: dict[int, list[Any]] = defaultdict(list)
    events_by_task: dict[int, list[Any]] = defaultdict(list)
    checklist_items_by_task: dict[int, list[Any]] = defaultdict(list)
    dependencies_by_task: dict[int, list[Any]] = defaultdict(list)
    dependency_options: list[Any] = []
    milestones: list[Any] = []
    can_manage = False
    deadline_counts = {'today': 0, 'tomorrow': 0, 'overdue': 0}
    kanban_open: list[Any] = []
    kanban_progress: list[Any] = []
    calendar_weeks: list[list[dict[str, Any]]] = []
    calendar_month_start = project_today()
    calendar_prev_month: date | None = None
    calendar_next_month: date | None = None
    page_num = 1
    per_page = 50
    total_tasks = 0
    total_pages = 1
    history_total = 0

    if active_project:
        project_id = int(active_project['id'])
        if project_view in {'kanban', 'timeline'}:
            tasks = list_project_tasks(project_id, 'all', q=q)
            total_tasks = len(tasks)
        elif project_view == 'calendar':
            tasks = []
            total_tasks = 0
        else:
            total_tasks = count_project_tasks(project_id, project_view, q=q)
            total_pages = max(1, (total_tasks + per_page - 1) // per_page)
            page_num = min(max(1, page), total_pages)
            offset = (page_num - 1) * per_page
            tasks = list_project_tasks(project_id, project_view, limit=per_page, offset=offset, q=q)

        kanban_open = [t for t in tasks if t['status'] == 'open']
        kanban_progress = [t for t in tasks if t['status'] == 'in_progress']
        for deadline_view in deadline_counts:
            deadline_counts[deadline_view] = count_project_tasks(project_id, deadline_view)
        history_total = count_project_tasks(project_id, 'history')
        members = list_project_members(project_id)
        member_ids = {int(member['id']) for member in members}
        all_users = list_users()
        task_assignees = [u for u in all_users if int(u['id']) in member_ids]
        shareable_users = [u for u in all_users if int(u['id']) not in member_ids]
        can_manage = can_manage_project(user, active_project)

        calendar_month_start = parse_month(month)
        calendar_prev_month = shift_month(calendar_month_start, -1) or calendar_month_start
        calendar_next_month = shift_month(calendar_month_start, 1) or calendar_month_start
        if project_view == 'calendar':
            tasks_by_deadline: dict[str, list[Any]] = defaultdict(list)
            for task in list_project_tasks(project_id, 'all'):
                if task['deadline']:
                    tasks_by_deadline[task['deadline']].append(task)
            calendar_weeks = build_calendar(calendar_month_start, tasks_by_deadline)

        descendants = project_descendants(projects, project_id)
        for candidate in project_nav:
            cid = int(candidate['id'])
            if cid == project_id or cid in descendants:
                continue
            parent_options_edit.append(candidate)

        if project_view not in {'timeline', 'calendar', 'kanban'}:
            visible_ids = [int(task['id']) for task in tasks]
            preview_attachments, preview_comments = task_list_previews(project_id, visible_ids)
            for attachment in preview_attachments:
                attachments_by_task[int(attachment['task_id'])].append(attachment)
            for comment in preview_comments:
                comments_by_task[int(comment['task_id'])].append(comment)
        milestones = list_project_milestones(project_id)
        project_dependencies = list_project_dependencies(project_id)
        if project_view == 'timeline':
            try:
                plan = build_plan(tasks, project_dependencies, milestones, project_today(), anchor, scale)
            except ValueError:
                raise HTTPException(status_code=400, detail='Ungültiges Startdatum für den Zeitstrahl')
        for dependency in project_dependencies:
            dependencies_by_task[int(dependency['task_id'])].append(dependency)

    return templates.TemplateResponse(
        request,
        'projects_app.html',
        {
            'plan': plan,
            'user': user,
            'projects': project_nav,
            'active_project': active_project,
            'tasks': tasks,
            'deadline_counts': deadline_counts,
            'today': project_today().isoformat(),
            'members': members,
            'task_assignees': task_assignees,
            'shareable_users': shareable_users,
            'parent_options_new': parent_options_new,
            'parent_options_edit': parent_options_edit,
            'attachments_by_task': attachments_by_task,
            'comments_by_task': comments_by_task,
            'events_by_task': events_by_task,
            'checklist_items_by_task': checklist_items_by_task,
            'dependencies_by_task': dependencies_by_task,
            'dependency_options': dependency_options,
            'milestones': milestones,
            'kanban_open': kanban_open,
            'kanban_progress': kanban_progress,
            'calendar_weeks': calendar_weeks,
            'calendar_month_start': calendar_month_start,
            'calendar_prev_month': calendar_prev_month,
            'calendar_next_month': calendar_next_month,
            'project_view': project_view,
            'history_total': history_total,
            'total_tasks': total_tasks,
            'total_pages': total_pages,
            'page': page_num,
            'per_page': per_page,
            'q': q,
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


@app.get('/tasks/{task_id}', response_class=HTMLResponse)
def task_detail_page(request: Request, task_id: int):
    user, response = require_login(request)
    if response:
        return response

    task = get_task_detail_if_accessible(task_id, int(user['id']))
    if not task:
        return HTMLResponse('Aufgabe nicht gefunden', status_code=404)

    project_id = int(task['project_id'])
    members = list_project_members(project_id)
    member_ids = {int(member['id']) for member in members}
    task_assignees = [u for u in list_users() if int(u['id']) in member_ids]
    milestones = list_project_milestones(project_id)

    comments = list_task_comments(task_id)
    events = list_task_events(task_id)
    checklist = list_task_checklist_items(task_id)
    attachments, _ = task_list_previews(project_id, [task_id])
    dependencies = [d for d in list_project_dependencies(project_id) if int(d['task_id']) == task_id]

    return templates.TemplateResponse(
        request,
        'task_detail.html',
        {
            'user': user,
            'task': task,
            'task_assignees': task_assignees,
            'milestones': milestones,
            'comments': comments,
            'events': events,
            'checklist': checklist,
            'attachments': attachments,
            'dependencies': dependencies,
            'dependency_options': [t for t in list_project_tasks(project_id) if int(t['id']) != task_id],
            'error': request.query_params.get('error'),
            'today': project_today().isoformat(),
            'max_attachment_mb': MAX_ATTACHMENT_BYTES // (1024 * 1024),
            'csrf_token': csrf_token(request),
        },
    )


def my_tasks_view(view: str | None) -> str:
    if view in VALID_MY_TASK_VIEWS:
        return str(view)
    return 'all'


@app.get('/my-tasks', response_class=HTMLResponse)
def my_tasks_page(request: Request, view: str = 'all'):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])
    selected_view = my_tasks_view(view)
    tasks = list_my_tasks(user_id, selected_view)

    counters = {
        'all': count_my_tasks(user_id, 'all'),
        'focus': count_my_tasks(user_id, 'focus'),
        'today': count_my_tasks(user_id, 'today'),
        'tomorrow': count_my_tasks(user_id, 'tomorrow'),
        'overdue': count_my_tasks(user_id, 'overdue'),
        'history': count_my_tasks(user_id, 'history'),
    }

    return templates.TemplateResponse(
        request,
        'my_tasks.html',
        {
            'user': user,
            'tasks': tasks,
            'counters': counters,
            'selected_view': selected_view,
            'today': project_today().isoformat(),
            'csrf_token': csrf_token(request),
            'error': request.query_params.get('error'),
        },
    )


@app.get('/templates', response_class=HTMLResponse)
def templates_page(request: Request):
    user, response = require_login(request)
    if response:
        return response

    user_id = int(user['id'])
    templates_list = list_task_templates(user_id)
    templates_with_items = []
    for template in templates_list:
        templates_with_items.append({
            'template': template,
            'items': list_task_template_items(int(template['id'])),
        })

    return templates.TemplateResponse(
        request,
        'templates.html',
        {
            'user': user,
            'templates': templates_with_items,
            'projects': build_project_nav(list_accessible_projects(user_id)),
            'csrf_token': csrf_token(request),
            'error': request.query_params.get('error'),
        },
    )


@app.post('/templates')
def create_template_submit(
    request: Request,
    name: str = Form(...),
    title: str = Form(...),
    description: str = Form(default=''),
    focus: str = Form(default='0'),
    priority: str = Form(default='normal'),
    checklist: str = Form(default=''),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/templates?error=csrf')

    name = name.strip()
    title = title.strip()
    if not name or not title:
        return redirect('/templates?error=missing_fields')

    if priority not in VALID_PRIORITIES:
        return redirect('/templates?error=invalid_priority')

    lines = [line for line in (checklist or '').splitlines() if line.strip()]
    create_task_template(
        user_id=int(user['id']),
        name=name,
        title=title,
        description=description.strip(),
        focus=focus == '1',
        priority=priority,
        checklist_lines=lines,
    )
    return redirect('/templates')


@app.post('/templates/{template_id}/use')
def use_template_submit(
    request: Request,
    template_id: int,
    project_id: int = Form(...),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/templates?error=csrf')

    project = get_accessible_project(project_id, int(user['id']))
    if not project:
        return redirect('/templates?error=project_not_found')

    task_id = create_task_from_template(project_id, template_id, int(user['id']))
    if task_id is None:
        return redirect('/templates?error=template_not_found')

    return redirect(projects_url(project_id))


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
    deadline: str = Form(default=''),
    start_date: str = Form(default=''),
    end_date: str = Form(default=''),
    priority: str = Form(default='normal'),
    recurrence: str = Form(default=''),
    milestone_id: str = Form(default=''),
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

    if priority not in VALID_PRIORITIES:
        return redirect(projects_url(project_id, project_view, 'invalid_priority'))

    recurrence_value = recurrence.strip() or None
    if recurrence_value and recurrence_value not in VALID_RECURRENCES:
        return redirect(projects_url(project_id, project_view, 'invalid_recurrence'))

    milestone: int | None = None
    milestone_value = milestone_id.strip()
    if milestone_value:
        try:
            milestone = int(milestone_value)
        except ValueError:
            return redirect(projects_url(project_id, project_view, 'invalid_milestone'))
        valid_milestone_ids = {int(m['id']) for m in list_project_milestones(project_id)}
        if milestone not in valid_milestone_ids:
            return redirect(projects_url(project_id, project_view, 'invalid_milestone'))

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

    try:
        deadline_value = normalize_deadline(deadline)
    except ValueError:
        return redirect(projects_url(project_id, project_view, 'invalid_deadline'))

    try:
        planned_start, planned_end = normalize_schedule(start_date, end_date)
    except ValueError:
        return redirect(projects_url(project_id, project_view, 'invalid_schedule'))

    create_task(
        project_id=project_id,
        title=task_title,
        description=description.strip(),
        status=status,
        assignee_id=assignee,
        focus=focus == '1',
        deadline=deadline_value,
        priority=priority,
        recurrence=recurrence_value,
        milestone_id=milestone,
        actor_id=int(user['id']),
        actor_name=user['username'],
        start_date=planned_start,
        end_date=planned_end,
    )
    return redirect(projects_url(project_id, project_view))


@app.post('/tasks/{task_id}/status')
def update_task_status_submit(
    request: Request,
    task_id: int,
    status: str = Form(...),
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'csrf'))

    if status not in VALID_TASK_STATUS:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'invalid_status'))

    updated_project_id = update_task_status_if_accessible(task_id, int(user['id']), status, user['username'])
    if updated_project_id is None:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'task_not_found'))

    return redirect(task_return_url(task_id, return_to, updated_project_id, project_view))


@app.post('/tasks/{task_id}/edit')
def edit_task_submit(
    request: Request,
    task_id: int,
    title: str = Form(...),
    description: str = Form(default=''),
    status: str = Form(default='open'),
    assignee_id: str = Form(default=''),
    focus: str = Form(default='0'),
    deadline: str = Form(default=''),
    priority: str = Form(default='normal'),
    recurrence: str = Form(default=''),
    milestone_id: str = Form(default=''),
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'csrf'))

    task_title = title.strip()
    if not task_title:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'missing_title'))

    if status not in VALID_TASK_STATUS:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'invalid_status'))

    if priority not in VALID_PRIORITIES:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'invalid_priority'))

    recurrence_value = recurrence.strip() or None
    if recurrence_value and recurrence_value not in VALID_RECURRENCES:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'invalid_recurrence'))

    task = get_task_if_accessible(task_id, int(user['id']))
    if not task:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'task_not_found'))

    actual_project_id = int(task['project_id'])
    member_ids = {int(member['id']) for member in list_project_members(actual_project_id)}

    milestone: int | None = None
    milestone_value = milestone_id.strip()
    if milestone_value:
        try:
            milestone = int(milestone_value)
        except ValueError:
            return redirect(task_return_url(task_id, return_to, actual_project_id, project_view, 'invalid_milestone'))
        valid_milestone_ids = {int(m['id']) for m in list_project_milestones(actual_project_id)}
        if milestone not in valid_milestone_ids:
            return redirect(task_return_url(task_id, return_to, actual_project_id, project_view, 'invalid_milestone'))

    assignee: int | None = None
    assignee_value = assignee_id.strip()
    if assignee_value:
        try:
            assignee = int(assignee_value)
        except ValueError:
            return redirect(task_return_url(task_id, return_to, actual_project_id, project_view, 'invalid_assignee'))
        if assignee not in member_ids:
            return redirect(task_return_url(task_id, return_to, actual_project_id, project_view, 'assignee_not_member'))

    try:
        deadline_value = normalize_deadline(deadline)
    except ValueError:
        return redirect(task_return_url(task_id, return_to, actual_project_id, project_view, 'invalid_deadline'))

    updated_project_id = update_task_if_accessible(
        task_id=task_id,
        user_id=int(user['id']),
        title=task_title,
        description=description.strip(),
        status=status,
        assignee_id=assignee,
        focus=focus == '1',
        deadline=deadline_value,
        priority=priority,
        recurrence=recurrence_value,
        milestone_id=milestone,
        actor_name=user['username'],
    )
    if updated_project_id is None:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'task_not_found'))

    return redirect(task_return_url(task_id, return_to, updated_project_id, project_view))


@app.post('/projects/{project_id}/milestones')
def create_milestone_submit(
    request: Request,
    project_id: int,
    name: str = Form(...),
    due_date: str = Form(default=''),
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

    milestone_name = name.strip()
    if not milestone_name:
        return redirect(projects_url(project_id, project_view, 'missing_milestone_name'))

    try:
        due_value = normalize_deadline(due_date)
    except ValueError:
        return redirect(projects_url(project_id, project_view, 'invalid_milestone_date'))

    create_milestone(project_id, milestone_name, due_value)
    return redirect(projects_url(project_id, project_view))


@app.post('/tasks/{task_id}/dependencies')
def add_task_dependency_submit(
    request: Request,
    task_id: int,
    depends_on_task_id: int = Form(...),
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'csrf'))

    result = add_task_dependency(task_id, depends_on_task_id, int(user['id']))
    if result != 'ok':
        return redirect(task_return_url(task_id, return_to, project_id, project_view, f'dependency_{result}'))

    return redirect(task_return_url(task_id, return_to, project_id, project_view))


@app.post('/tasks/{task_id}/comments')
def create_task_comment_submit(
    request: Request,
    task_id: int,
    content: str = Form(...),
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'csrf'))

    task = get_task_if_accessible(task_id, int(user['id']))
    if not task:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'task_not_found'))

    comment = content.strip()
    if not comment:
        return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view, 'missing_comment'))

    create_task_comment(
        task_id=task_id,
        author_id=int(user['id']),
        author_name=user['username'],
        content=comment,
    )
    return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view))


@app.post('/tasks/{task_id}/checklist')
def create_checklist_item_submit(
    request: Request,
    task_id: int,
    content: str = Form(...),
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'csrf'))

    task = get_task_if_accessible(task_id, int(user['id']))
    if not task:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'task_not_found'))

    item_content = content.strip()
    if not item_content:
        return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view, 'missing_checklist_item'))

    add_task_checklist_item(task_id, item_content)
    return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view))


@app.post('/checklist/{item_id}/toggle')
def toggle_checklist_item_submit(
    request: Request,
    item_id: int,
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(projects_url(project_id, project_view, 'csrf'))

    with db.get_connection() as conn:
        item = conn.execute(
            '''
            SELECT c.id, c.task_id, c.done
            FROM task_checklist_items c
            JOIN tasks t ON t.id = c.task_id
            WHERE c.id = ?
            LIMIT 1
            ''',
            (item_id,),
        ).fetchone()

    if not item:
        return redirect(projects_url(project_id, project_view, 'checklist_item_not_found'))

    task = get_task_if_accessible(int(item['task_id']), int(user['id']))
    if not task:
        return redirect(projects_url(project_id, project_view, 'task_not_found'))

    set_task_checklist_item_done(item_id, not bool(item['done']))
    return redirect(task_return_url(int(item['task_id']), return_to, int(task['project_id']), project_view))


@app.post('/tasks/{task_id}/attachments')
async def upload_attachment_submit(
    request: Request,
    task_id: int,
    project_id: int = Form(...),
    view: str = Form(default='all'),
    return_to: str = Form(default='project'),
    csrf: str = Form(...),
    file: UploadFile = File(...),
):
    user, response = require_login(request)
    if response:
        return response

    project_view = normalize_view(view)
    if not validate_csrf(request, csrf):
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'csrf'))

    task = get_task_if_accessible(task_id, int(user['id']))
    if not task:
        return redirect(task_return_url(task_id, return_to, project_id, project_view, 'task_not_found'))

    if not file.filename:
        return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view, 'missing_file'))

    content = await file.read(MAX_ATTACHMENT_BYTES + 1)
    if len(content) > MAX_ATTACHMENT_BYTES:
        return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view, 'file_too_large'))

    filename = Path(file.filename).name.strip() or 'attachment.bin'
    mime = (file.content_type or 'application/octet-stream').strip()
    create_attachment(task_id, filename, mime, len(content), content, int(user['id']), user['username'])
    return redirect(task_return_url(task_id, return_to, int(task['project_id']), project_view))


@app.get('/attachments/{attachment_id}/download')
def download_attachment(request: Request, attachment_id: int):
    user, response = require_login(request)
    if response:
        return response

    attachment = get_attachment_if_accessible(attachment_id, int(user['id']))
    if not attachment:
        return HTMLResponse('Attachment not found', status_code=404)

    filename = str(attachment['filename']).replace('"', '').replace('\n', '')
    headers = {'Content-Disposition': "attachment; filename*=UTF-8''" + quote(filename, safe='')}
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
    headers = {'Content-Disposition': "attachment; filename*=UTF-8''" + quote(filename, safe='')}
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
    headers = {'Content-Disposition': "inline; filename*=UTF-8''" + quote(filename, safe='')}
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
    os.close(_fd)
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


@app.get('/account', response_class=HTMLResponse)
def account_page(request: Request):
    user, response = require_login(request)
    if response:
        return response

    return templates.TemplateResponse(
        request,
        'account.html',
        {
            'user': user,
            'csrf_token': csrf_token(request),
            'account_error': request.query_params.get('error'),
        },
    )


@app.post('/account')
def account_submit(
    request: Request,
    email: str = Form(default=''),
    mail_opt_in: str = Form(default='0'),
    reminder_opt_in: str = Form(default='0'),
    reminder_target: str = Form(default=''),
    current_password: str = Form(default=''),
    new_password: str = Form(default=''),
    confirm_password: str = Form(default=''),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/account?error=csrf')

    email_clean = email.strip()
    opt_in = mail_opt_in == '1'

    current_password = current_password.strip()
    new_password = new_password.strip()
    confirm_password = confirm_password.strip()

    new_hash: str | None = None
    wants_password_change = bool(current_password or new_password or confirm_password)
    if wants_password_change:
        if not current_password or not new_password or not confirm_password:
            return redirect('/account?error=password_fields_required')
        if not verify_password(current_password, user['password_hash']):
            return redirect('/account?error=current_password_invalid')
        if new_password != confirm_password:
            return redirect('/account?error=password_mismatch')
        if len(new_password) < MIN_PASSWORD_LENGTH:
            return redirect('/account?error=password_too_short')
        new_hash = hash_password(new_password)

    ok = update_user_profile(
        user_id=int(user['id']),
        email=email_clean,
        mail_opt_in=opt_in,
        reminder_opt_in=reminder_opt_in == '1',
        reminder_target=user['reminder_target'],
        new_password_hash=new_hash,
    )
    if not ok:
        return redirect('/account?error=update_failed')

    return redirect('/account?error=profile_saved')


@app.post('/account/delete')
def account_delete_submit(
    request: Request,
    current_password: str = Form(...),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/account?error=csrf')

    if not verify_password(current_password.strip(), user['password_hash']):
        return redirect('/account?error=current_password_invalid')

    replacement_user_id = find_reassignment_user(exclude_user_id=int(user['id']))
    if replacement_user_id is None:
        return redirect('/account?error=cannot_delete_last_user')

    result = delete_user_with_reassignment(
        user_id=int(user['id']),
        reassignment_user_id=replacement_user_id,
    )
    if result == 'last_admin':
        return redirect('/account?error=cannot_delete_last_admin')
    if result != 'ok':
        return redirect('/account?error=delete_failed')

    request.session.clear()
    return redirect('/login')


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
            'current_user_id': int(user['id']),
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
    email: str = Form(default=''),
    mail_opt_in: str = Form(default='0'),
    reminder_opt_in: str = Form(default='0'),
    reminder_target: str = Form(default=''),
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
    if len(password) < MIN_PASSWORD_LENGTH:
        return redirect('/users?error=password_too_short')

    reminder_target = reminder_target.strip()
    if reminder_target and not reminders.valid_target(reminder_target):
        return redirect('/users?error=invalid_reminder_target')

    if role not in VALID_ROLES:
        return redirect('/users?error=invalid_role')

    ok = create_user(
        username=username,
        password_hash=hash_password(password),
        role=role,
        email=email.strip(),
        mail_opt_in=mail_opt_in == '1',
        reminder_opt_in=reminder_opt_in == '1',
        reminder_target=reminder_target,
    )
    if not ok:
        return redirect('/users?error=user_exists')

    print(f"[info] User created by {admin_user['username']}: {username} ({role})")
    return redirect('/users')


@app.post('/users/{target_user_id}/edit')
def edit_user_submit(
    request: Request,
    target_user_id: int,
    username: str = Form(...),
    role: str = Form(default='user'),
    email: str = Form(default=''),
    mail_opt_in: str = Form(default='0'),
    reminder_opt_in: str = Form(default='0'),
    reminder_target: str = Form(default=''),
    new_password: str = Form(default=''),
    csrf: str = Form(...),
):
    admin_user, response = require_admin(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/users?error=csrf')

    username = username.strip()
    if not username:
        return redirect('/users?error=missing_fields')
    reminder_target = reminder_target.strip()
    if reminder_target and not reminders.valid_target(reminder_target):
        return redirect('/users?error=invalid_reminder_target')

    if role not in VALID_ROLES:
        return redirect('/users?error=invalid_role')

    pw = new_password.strip()
    new_hash: str | None = None
    if pw:
        if len(pw) < MIN_PASSWORD_LENGTH:
            return redirect('/users?error=password_too_short')
        new_hash = hash_password(pw)

    result = update_user_by_admin(
        user_id=target_user_id,
        username=username,
        role=role,
        email=email.strip(),
        mail_opt_in=mail_opt_in == '1',
        new_password_hash=new_hash,
        reminder_opt_in=reminder_opt_in == '1',
        reminder_target=reminder_target,
    )
    if result == 'not_found':
        return redirect('/users?error=user_not_found')
    if result == 'last_admin':
        return redirect('/users?error=last_admin')
    if result == 'username_taken':
        return redirect('/users?error=user_exists')

    print(f"[info] User edited by {admin_user['username']}: {username} ({role})")
    return redirect('/users?error=user_updated')


@app.post('/users/{target_user_id}/delete')
def delete_user_submit(
    request: Request,
    target_user_id: int,
    csrf: str = Form(...),
):
    actor, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect('/users?error=csrf' if actor['role'] == 'admin' else '/account?error=csrf')

    actor_id = int(actor['id'])
    is_admin = actor['role'] == 'admin'
    if not is_admin and actor_id != target_user_id:
        return HTMLResponse('Forbidden', status_code=403)

    replacement = find_reassignment_user(
        exclude_user_id=target_user_id,
        preferred_user_id=actor_id if actor_id != target_user_id else None,
    )
    if replacement is None:
        if is_admin:
            return redirect('/users?error=cannot_delete_last_user')
        return redirect('/account?error=cannot_delete_last_user')

    result = delete_user_with_reassignment(
        user_id=target_user_id,
        reassignment_user_id=replacement,
    )
    if result == 'last_admin':
        if is_admin:
            return redirect('/users?error=last_admin')
        return redirect('/account?error=cannot_delete_last_admin')
    if result != 'ok':
        if is_admin:
            return redirect('/users?error=delete_failed')
        return redirect('/account?error=delete_failed')

    if actor_id == target_user_id:
        request.session.clear()
        return redirect('/login')

    return redirect('/users?error=user_deleted')


if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8099)
