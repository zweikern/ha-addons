from __future__ import annotations

import calendar
import json
import sqlite3
import os
import time
import uuid
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.environ.get('HOUSEHOLD_DATA_DIR', '/data'))
DB_PATH = DATA_DIR / 'app.db'


class _ManagedConnection:
    """Wrappt eine sqlite3.Connection, damit ``with get_connection()`` die
    Verbindung nach dem Block zuverlaessig schliesst, waehrend Commit/Rollback
    weiterhin ueber den sqlite3-Context-Manager ablaufen."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def __getattr__(self, name: str):
        return getattr(self._conn, name)

    def __enter__(self):
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return self._conn.__exit__(exc_type, exc_value, traceback)
        finally:
            self._conn.close()


def get_connection() -> _ManagedConnection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return _ManagedConnection(conn)


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f'PRAGMA table_info({table})').fetchall()
    return any(row['name'] == column for row in rows)


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                reminder_opt_in INTEGER NOT NULL DEFAULT 0,
                reminder_target TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                parent_id INTEGER,
                created_by INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'done')),
                focus INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low', 'normal', 'high')),
                recurrence TEXT,
                milestone_id INTEGER,
                assignee_id INTEGER,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(assignee_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS project_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member', 'manager')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, user_id),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS task_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                mime TEXT NOT NULL,
                size INTEGER NOT NULL,
                content BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS fs_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER,
                name TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(parent_id) REFERENCES fs_folders(id) ON DELETE CASCADE,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS fs_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id INTEGER,
                stored_name TEXT NOT NULL,
                original_name TEXT NOT NULL,
                mime TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(folder_id) REFERENCES fs_folders(id) ON DELETE SET NULL,
                FOREIGN KEY(uploaded_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS fs_folder_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(folder_id, user_id),
                FOREIGN KEY(folder_id) REFERENCES fs_folders(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_fs_folders_parent_name
                ON fs_folders(parent_id, name);

            CREATE INDEX IF NOT EXISTS idx_fs_files_folder_id
                ON fs_files(folder_id);

            CREATE INDEX IF NOT EXISTS idx_fs_files_uploaded_by
                ON fs_files(uploaded_by);

            CREATE INDEX IF NOT EXISTS idx_fs_folder_members_folder
                ON fs_folder_members(folder_id);

            CREATE TABLE IF NOT EXISTS music_tracks (
                track_key TEXT PRIMARY KEY,
                artist TEXT NOT NULL,
                title TEXT NOT NULL,
                album TEXT,
                uri TEXT,
                source TEXT,
                image_url TEXT,
                analyzer_bpm REAL,
                analyzer_confidence REAL,
                researched_bpm REAL,
                primary_genre TEXT,
                subgenres_json TEXT NOT NULL DEFAULT '[]',
                tags_json TEXT NOT NULL DEFAULT '[]',
                genre_confidence REAL,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                favorite INTEGER NOT NULL DEFAULT 0,
                favorited_at TEXT,
                accepted_at TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_music_tracks_accepted_at
                ON music_tracks(accepted_at DESC);

            CREATE TABLE IF NOT EXISTS task_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                author_id INTEGER,
                author_name TEXT NOT NULL DEFAULT '',
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                actor_id INTEGER,
                actor_name TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_task_comments_task
                ON task_comments(task_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_task_events_task
                ON task_events(task_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_tasks_project_status
                ON tasks(project_id, status);

            CREATE INDEX IF NOT EXISTS idx_tasks_assignee
                ON tasks(assignee_id);

            CREATE TABLE IF NOT EXISTS reminder_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                assignee_id INTEGER NOT NULL,
                delivery_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed')),
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(task_id, assignee_id, delivery_date),
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY(assignee_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_reminder_deliveries_date
                ON reminder_deliveries(delivery_date, status);

            CREATE TABLE IF NOT EXISTS task_checklist_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                done INTEGER NOT NULL DEFAULT 0,
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_task_checklist_items_task
                ON task_checklist_items(task_id, position);

            CREATE TABLE IF NOT EXISTS task_recurrence_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_task_id INTEGER NOT NULL,
                followup_task_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(source_task_id),
                FOREIGN KEY(source_task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY(followup_task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS task_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                focus INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'normal',
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS task_template_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                template_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(template_id) REFERENCES task_templates(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS milestones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                due_date TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_milestones_project
                ON milestones(project_id, due_date);

            CREATE TABLE IF NOT EXISTS task_dependencies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                depends_on_task_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(task_id, depends_on_task_id),
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY(depends_on_task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );
            '''
        )

        # Schema migrations for existing databases
        if not _has_column(conn, 'tasks', 'deadline'):
            conn.execute('ALTER TABLE tasks ADD COLUMN deadline TEXT')
        if not _has_column(conn, 'projects', 'parent_id'):
            conn.execute('ALTER TABLE projects ADD COLUMN parent_id INTEGER')

        if not _has_column(conn, 'tasks', 'focus'):
            conn.execute('ALTER TABLE tasks ADD COLUMN focus INTEGER NOT NULL DEFAULT 0')

        if not _has_column(conn, 'tasks', 'completed_at'):
            conn.execute('ALTER TABLE tasks ADD COLUMN completed_at TEXT')

        if not _has_column(conn, 'tasks', 'priority'):
            conn.execute("ALTER TABLE tasks ADD COLUMN priority TEXT NOT NULL DEFAULT 'normal'")

        if not _has_column(conn, 'tasks', 'recurrence'):
            conn.execute('ALTER TABLE tasks ADD COLUMN recurrence TEXT')

        if not _has_column(conn, 'tasks', 'milestone_id'):
            conn.execute('ALTER TABLE tasks ADD COLUMN milestone_id INTEGER')

        # Indizes auf Spaet-Migrationsspalten erst nach den ALTER-Anweisungen.
        conn.execute('CREATE INDEX IF NOT EXISTS idx_tasks_project_deadline ON tasks(project_id, deadline)')

        if not _has_column(conn, 'users', 'email'):
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")

        if not _has_column(conn, 'users', 'mail_opt_in'):
            conn.execute('ALTER TABLE users ADD COLUMN mail_opt_in INTEGER NOT NULL DEFAULT 0')

        if not _has_column(conn, 'users', 'reminder_opt_in'):
            conn.execute('ALTER TABLE users ADD COLUMN reminder_opt_in INTEGER NOT NULL DEFAULT 0')

        if not _has_column(conn, 'users', 'reminder_target'):
            conn.execute("ALTER TABLE users ADD COLUMN reminder_target TEXT NOT NULL DEFAULT ''")

        if not _has_column(conn, 'reminder_deliveries', 'claim_token'):
            conn.execute("ALTER TABLE reminder_deliveries ADD COLUMN claim_token TEXT")
        if not _has_column(conn, 'reminder_deliveries', 'lease_until'):
            conn.execute("ALTER TABLE reminder_deliveries ADD COLUMN lease_until REAL NOT NULL DEFAULT 0")

        if not _has_column(conn, 'music_tracks', 'favorite'):
            conn.execute('ALTER TABLE music_tracks ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0')

        if not _has_column(conn, 'music_tracks', 'favorited_at'):
            conn.execute('ALTER TABLE music_tracks ADD COLUMN favorited_at TEXT')

        if not _has_column(conn, 'music_tracks', 'image_url'):
            conn.execute('ALTER TABLE music_tracks ADD COLUMN image_url TEXT')


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def list_users() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT id, username, role, email, mail_opt_in, reminder_opt_in, reminder_target, created_at
            FROM users
            ORDER BY username ASC
            '''
        ).fetchall()


def create_user(
    username: str,
    password_hash: str,
    role: str,
    email: str = '',
    mail_opt_in: bool = False,
    reminder_opt_in: bool = False,
    reminder_target: str = '',
) -> bool:
    try:
        with get_connection() as conn:
            conn.execute(
                '''
                INSERT INTO users (username, password_hash, role, email, mail_opt_in, reminder_opt_in, reminder_target)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    username,
                    password_hash,
                    role,
                    email.strip(),
                    1 if mail_opt_in else 0,
                    1 if reminder_opt_in else 0,
                    reminder_target.strip(),
                ),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def update_user_profile(
    user_id: int,
    email: str,
    mail_opt_in: bool,
    new_password_hash: str | None = None,
    reminder_opt_in: bool = False,
    reminder_target: str = '',
) -> bool:
    with get_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM users WHERE id = ? LIMIT 1',
            (user_id,),
        ).fetchone()
        if not existing:
            return False

        if new_password_hash:
            conn.execute(
                '''
                UPDATE users
                SET email = ?, mail_opt_in = ?, reminder_opt_in = ?, password_hash = ?
                WHERE id = ?
                ''',
                (
                    email.strip(),
                    1 if mail_opt_in else 0,
                    1 if reminder_opt_in else 0,
                    new_password_hash,
                    user_id,
                ),
            )
        else:
            conn.execute(
                '''
                UPDATE users
                SET email = ?, mail_opt_in = ?, reminder_opt_in = ?
                WHERE id = ?
                ''',
                (
                    email.strip(),
                    1 if mail_opt_in else 0,
                    1 if reminder_opt_in else 0,
                    user_id,
                ),
            )
    return True


def count_admin_users() -> int:
    with get_connection() as conn:
        value = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        return int(value or 0)


def find_reassignment_user(
    exclude_user_id: int,
    preferred_user_id: int | None = None,
) -> int | None:
    with get_connection() as conn:
        if preferred_user_id and preferred_user_id != exclude_user_id:
            preferred = conn.execute(
                'SELECT id FROM users WHERE id = ? LIMIT 1',
                (preferred_user_id,),
            ).fetchone()
            if preferred:
                return int(preferred['id'])

        row = conn.execute(
            '''
            SELECT id
            FROM users
            WHERE id != ?
            ORDER BY
              CASE WHEN role = 'admin' THEN 0 ELSE 1 END,
              id ASC
            LIMIT 1
            ''',
            (exclude_user_id,),
        ).fetchone()
        if not row:
            return None
        return int(row['id'])


def update_user_by_admin(
    user_id: int,
    username: str,
    role: str,
    email: str,
    mail_opt_in: bool,
    new_password_hash: str | None = None,
    reminder_opt_in: bool = False,
    reminder_target: str = '',
) -> str:
    with get_connection() as conn:
        target = conn.execute(
            'SELECT id, role FROM users WHERE id = ? LIMIT 1',
            (user_id,),
        ).fetchone()
        if not target:
            return 'not_found'

        if target['role'] == 'admin' and role != 'admin':
            admin_count = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin'"
            ).fetchone()[0]
            if int(admin_count or 0) <= 1:
                return 'last_admin'

        try:
            if new_password_hash:
                conn.execute(
                    '''
                    UPDATE users
                    SET username = ?, role = ?, email = ?, mail_opt_in = ?, reminder_opt_in = ?, password_hash = ?
                    WHERE id = ?
                    ''',
                    (
                        username.strip(),
                        role,
                        email.strip(),
                        1 if mail_opt_in else 0,
                        1 if reminder_opt_in else 0,
                            new_password_hash,
                        user_id,
                    ),
                )
            else:
                conn.execute(
                    '''
                    UPDATE users
                    SET username = ?, role = ?, email = ?, mail_opt_in = ?, reminder_opt_in = ?
                    WHERE id = ?
                    ''',
                    (
                        username.strip(),
                        role,
                        email.strip(),
                        1 if mail_opt_in else 0,
                        1 if reminder_opt_in else 0,
                            user_id,
                    ),
                )
        except sqlite3.IntegrityError:
            return 'username_taken'

    return 'ok'


def delete_user_with_reassignment(user_id: int, reassignment_user_id: int) -> str:
    if user_id == reassignment_user_id:
        return 'invalid_reassignment'

    with get_connection() as conn:
        target = conn.execute(
            'SELECT id, role FROM users WHERE id = ? LIMIT 1',
            (user_id,),
        ).fetchone()
        if not target:
            return 'not_found'

        replacement = conn.execute(
            'SELECT id FROM users WHERE id = ? LIMIT 1',
            (reassignment_user_id,),
        ).fetchone()
        if not replacement:
            return 'invalid_reassignment'

        if target['role'] == 'admin':
            admin_count = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin'"
            ).fetchone()[0]
            if int(admin_count or 0) <= 1:
                return 'last_admin'

        conn.execute(
            'UPDATE projects SET created_by = ? WHERE created_by = ?',
            (reassignment_user_id, user_id),
        )
        conn.execute(
            'UPDATE fs_folders SET created_by = ? WHERE created_by = ?',
            (reassignment_user_id, user_id),
        )
        conn.execute(
            'UPDATE fs_files SET uploaded_by = ? WHERE uploaded_by = ?',
            (reassignment_user_id, user_id),
        )
        conn.execute(
            'UPDATE tasks SET assignee_id = NULL WHERE assignee_id = ?',
            (user_id,),
        )

        # Persoenliche Vorlagen sind privat und werden beim Loeschen des
        # Kontos entfernt (keine stillschweigende Weitergabe an andere Nutzer).
        conn.execute(
            'DELETE FROM task_templates WHERE created_by = ?',
            (user_id,),
        )

        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))

    return 'ok'


def ensure_admin_account(username: str, password_hash: str) -> bool:
    with get_connection() as conn:
        admin_exists = conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        if admin_exists:
            return False

        existing = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?",
                (password_hash, existing['id']),
            )
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (username, password_hash),
            )
    return True


def ensure_admin_credentials(username: str, password_hash: str) -> tuple[bool, bool]:
    with get_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?",
                (password_hash, existing['id']),
            )
            return False, True

        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, password_hash),
        )
    return True, False


def create_project(
    name: str,
    description: str,
    created_by: int | None,
    parent_id: int | None = None,
) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            'INSERT INTO projects (name, description, parent_id, created_by) VALUES (?, ?, ?, ?)',
            (name, description, parent_id, created_by),
        )
        return int(cur.lastrowid)


def update_project(project_id: int, name: str, description: str, parent_id: int | None) -> None:
    with get_connection() as conn:
        conn.execute(
            'UPDATE projects SET name = ?, description = ?, parent_id = ? WHERE id = ?',
            (name, description, parent_id, project_id),
        )


def list_accessible_projects(user_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                p.id,
                p.name,
                p.description,
                p.parent_id,
                p.created_by,
                p.created_at,
                owner.username AS owner_name,
                COALESCE(pm.role, '') AS membership_role,
                CASE WHEN p.created_by = ? THEN 'own' ELSE 'shared' END AS access_type,
                (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count,
                (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.status != 'done') AS open_task_count,
                (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.focus = 1 AND t.status != 'done') AS focus_count
            FROM projects p
            LEFT JOIN users owner ON owner.id = p.created_by
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE p.created_by = ? OR pm.user_id = ?
            ORDER BY
                CASE WHEN p.created_by = ? THEN 0 ELSE 1 END,
                LOWER(p.name) ASC,
                p.id ASC
            ''',
            (user_id, user_id, user_id, user_id, user_id),
        ).fetchall()


def get_accessible_project(project_id: int, user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                p.id,
                p.name,
                p.description,
                p.parent_id,
                p.created_by,
                p.created_at,
                owner.username AS owner_name,
                COALESCE(pm.role, '') AS membership_role,
                CASE WHEN p.created_by = ? THEN 'own' ELSE 'shared' END AS access_type,
                (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count,
                (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.status != 'done') AS open_task_count,
                (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.focus = 1 AND t.status != 'done') AS focus_count
            FROM projects p
            LEFT JOIN users owner ON owner.id = p.created_by
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE p.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, user_id, project_id, user_id, user_id),
        ).fetchone()


def _username(conn: sqlite3.Connection, user_id: int | None) -> str | None:
    if user_id is None:
        return None
    row = conn.execute('SELECT username FROM users WHERE id = ? LIMIT 1', (user_id,)).fetchone()
    return str(row['username']) if row else str(user_id)


def _record_event(
    conn: sqlite3.Connection,
    task_id: int,
    actor_id: int | None,
    actor_name: str,
    event_type: str,
    old_value: str | None = None,
    new_value: str | None = None,
) -> None:
    conn.execute(
        '''
        INSERT INTO task_events (task_id, actor_id, actor_name, event_type, old_value, new_value)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (task_id, actor_id, actor_name or '', event_type, old_value, new_value),
    )


def create_task(
    project_id: int,
    title: str,
    description: str,
    status: str,
    assignee_id: int | None,
    focus: bool = False,
    deadline: str | None = None,
    priority: str = 'normal',
    recurrence: str | None = None,
    milestone_id: int | None = None,
    actor_id: int | None = None,
    actor_name: str = '',
) -> int:
    deadline = normalize_deadline(deadline)
    if priority not in {'low', 'normal', 'high'}:
        priority = 'normal'
    if recurrence not in {'daily', 'weekly', 'monthly'}:
        recurrence = None
    with get_connection() as conn:
        completed_at = 'CURRENT_TIMESTAMP' if status == 'done' else None
        if completed_at:
            cur = conn.execute(
                '''
                INSERT INTO tasks (project_id, title, description, status, focus, priority, recurrence, milestone_id, assignee_id, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''',
                (project_id, title, description, status, 1 if focus else 0, priority, recurrence, milestone_id, assignee_id),
            )
        else:
            cur = conn.execute(
                '''
                INSERT INTO tasks (project_id, title, description, status, focus, priority, recurrence, milestone_id, assignee_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (project_id, title, description, status, 1 if focus else 0, priority, recurrence, milestone_id, assignee_id),
            )
        conn.execute('UPDATE tasks SET deadline = ? WHERE id = ?', (deadline, cur.lastrowid))
        if actor_id is not None:
            _record_event(conn, int(cur.lastrowid), actor_id, actor_name, 'task_created', None, status)
        if status == 'done':
            _handle_recurrence(conn, int(cur.lastrowid), status)
        return int(cur.lastrowid)


def normalize_deadline(value: str | None) -> str | None:
    return date.fromisoformat(value).isoformat() if value else None


def project_today() -> date:
    return datetime.now(ZoneInfo('Europe/Berlin')).date()


def _task_filter(view: str, q: str = '') -> tuple[str, list[Any]]:
    where = 'WHERE t.project_id = ?'
    params: list[Any] = []

    if view not in {'done', 'history'}:
        where += " AND t.status != 'done'"
    if view == 'open':
        where += " AND t.status = 'open'"
    elif view in {'done', 'history'}:
        where += " AND t.status = 'done'"
    elif view == 'focus':
        where += " AND t.focus = 1 AND t.status IN ('open', 'in_progress')"
    elif view in {'today', 'tomorrow'}:
        where += ' AND t.deadline = ?'
        params.append((project_today() + timedelta(days=view == 'tomorrow')).isoformat())
    elif view == 'overdue':
        where += ' AND t.deadline < ?'
        params.append(project_today().isoformat())
    elif view == 'in_progress':
        where += " AND t.status = 'in_progress'"

    search = (q or '').strip()
    if search:
        pattern = f'%{search}%'
        where += (
            ' AND (t.title LIKE ? OR t.description LIKE ?'
            ' OR EXISTS (SELECT 1 FROM users u2 WHERE u2.id = t.assignee_id AND u2.username LIKE ?))'
        )
        params.extend([pattern, pattern, pattern])
    return where, params


_TASK_SELECT = '''
        SELECT
            t.id,
            t.project_id,
            t.title,
            t.description,
            t.deadline,
            t.status,
            t.focus,
            t.priority,
            t.recurrence,
            t.milestone_id,
            t.created_at,
            t.completed_at,
            t.assignee_id,
            u.username AS assignee_name,
            (SELECT COUNT(*) FROM task_attachments a WHERE a.task_id = t.id) AS attachment_count
        FROM tasks t
        LEFT JOIN users u ON u.id = t.assignee_id
'''

_TASK_ORDER = '''
        ORDER BY
            t.completed_at DESC,
            t.deadline IS NULL,
            t.deadline ASC,
            t.focus DESC,
            CASE WHEN t.status = 'done' THEN 1 ELSE 0 END,
            t.created_at DESC,
            t.id DESC
'''


def list_project_tasks(
    project_id: int,
    view: str = 'all',
    limit: int | None = None,
    offset: int | None = None,
    q: str = '',
) -> list[sqlite3.Row]:
    where, extra = _task_filter(view, q)
    params: list[Any] = [project_id] + extra
    query = f'{_TASK_SELECT} {where} {_TASK_ORDER}'
    if limit is not None:
        query += ' LIMIT ?'
        params.append(int(limit))
        if offset is not None:
            query += ' OFFSET ?'
            params.append(int(offset))
    with get_connection() as conn:
        return conn.execute(query, tuple(params)).fetchall()


def count_project_tasks(project_id: int, view: str = 'all', q: str = '') -> int:
    where, extra = _task_filter(view, q)
    params: list[Any] = [project_id] + extra
    with get_connection() as conn:
        value = conn.execute(f'SELECT COUNT(*) FROM tasks t {where}', tuple(params)).fetchone()[0]
        return int(value or 0)


def list_project_history(
    project_id: int,
    limit: int | None = None,
    offset: int | None = None,
) -> list[sqlite3.Row]:
    return list_project_tasks(project_id, 'history', limit=limit, offset=offset)


def _my_task_filter(view: str) -> tuple[str, list[Any]]:
    extra = ''
    params: list[Any] = []
    if view not in {'history', 'done'}:
        extra += " AND t.status != 'done'"
    if view == 'focus':
        extra += " AND t.focus = 1 AND t.status IN ('open', 'in_progress')"
    elif view in {'history', 'done'}:
        extra += " AND t.status = 'done'"
    elif view in {'today', 'tomorrow'}:
        extra += ' AND t.deadline = ?'
        params.append((project_today() + timedelta(days=view == 'tomorrow')).isoformat())
    elif view == 'overdue':
        extra += ' AND t.deadline < ?'
        params.append(project_today().isoformat())
    elif view == 'in_progress':
        extra += " AND t.status = 'in_progress'"
    elif view == 'open':
        extra += " AND t.status = 'open'"
    return extra, params


_MY_TASK_FROM = '''
        FROM tasks t
        JOIN projects p ON p.id = t.project_id
        LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
        WHERE t.assignee_id = ?
'''


def list_my_tasks(user_id: int, view: str = 'all') -> list[sqlite3.Row]:
    extra, filter_params = _my_task_filter(view)
    params: list[Any] = [user_id, user_id] + filter_params + [user_id, user_id]
    query = f'''
        SELECT
            t.id,
            t.project_id,
            p.name AS project_name,
            t.title,
            t.deadline,
            t.status,
            t.focus,
            t.priority,
            t.created_at,
            t.completed_at
        {_MY_TASK_FROM}
        {extra}
          AND (p.created_by = ? OR pm.user_id = ?)
        ORDER BY
            t.deadline IS NULL,
            t.deadline ASC,
            CASE t.priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END,
            t.focus DESC,
            t.created_at DESC,
            t.id DESC
    '''
    with get_connection() as conn:
        return conn.execute(query, tuple(params)).fetchall()


def count_my_tasks(user_id: int, view: str) -> int:
    extra, filter_params = _my_task_filter(view)
    params: list[Any] = [user_id, user_id] + filter_params + [user_id, user_id]
    query = f'''
        SELECT COUNT(*)
        {_MY_TASK_FROM}
        {extra}
          AND (p.created_by = ? OR pm.user_id = ?)
    '''
    with get_connection() as conn:
        value = conn.execute(query, tuple(params)).fetchone()[0]
        return int(value or 0)


def get_reminder_candidate(task_id: int, assignee_id: int, delivery_date: str) -> sqlite3.Row | None:
    """Rechte, Status, Opt-in und Faelligkeitsdatum unmittelbar vor dem Versand erneut pruefen."""
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT t.id, t.title, t.deadline, t.status, t.assignee_id, u.username, u.reminder_target
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            JOIN users u ON u.id = t.assignee_id
            WHERE t.id = ? AND t.assignee_id = ?
              AND t.status != 'done'
              AND t.deadline = ?
              AND u.reminder_opt_in = 1
              AND (p.created_by = t.assignee_id OR pm.user_id = t.assignee_id)
            LIMIT 1
            ''',
            (assignee_id, task_id, assignee_id, delivery_date),
        ).fetchone()


def list_due_reminders(delivery_date: str) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT t.id, t.title, t.deadline, t.assignee_id, u.username, u.reminder_target
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = t.assignee_id
            JOIN users u ON u.id = t.assignee_id
            WHERE t.deadline = ? AND t.status != 'done'
              AND u.reminder_opt_in = 1
              AND u.reminder_target != ''
              AND (p.created_by = t.assignee_id OR pm.user_id = t.assignee_id)
            ORDER BY t.id ASC
            ''',
            (delivery_date,),
        ).fetchall()


def get_reminder_delivery(task_id: int, assignee_id: int, delivery_date: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT id, task_id, assignee_id, delivery_date, status, attempts, last_error
            FROM reminder_deliveries
            WHERE task_id = ? AND assignee_id = ? AND delivery_date = ?
            LIMIT 1
            ''',
            (task_id, assignee_id, delivery_date),
        ).fetchone()


def claim_reminder_delivery(task_id: int, assignee_id: int, delivery_date: str,
                            max_attempts: int = 3, lease_seconds: int = 120,
                            now: float | None = None) -> str | None:
    """Reserve one bounded attempt across processes; expired leases may retry."""
    timestamp = time.time() if now is None else now
    token = uuid.uuid4().hex
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT * FROM reminder_deliveries WHERE task_id=? AND assignee_id=? AND delivery_date=?',
            (task_id, assignee_id, delivery_date),
        ).fetchone()
        if max_attempts <= 0 or (row and (row['status'] == 'sent' or
                row['attempts'] >= max_attempts or row['lease_until'] > timestamp)):
            return None
        conn.execute(
            '''
            INSERT INTO reminder_deliveries
                (task_id, assignee_id, delivery_date, status, attempts, claim_token, lease_until)
            VALUES (?, ?, ?, 'pending', 1, ?, ?)
            ON CONFLICT(task_id, assignee_id, delivery_date) DO UPDATE SET
                attempts = reminder_deliveries.attempts + 1,
                status = 'pending', claim_token = excluded.claim_token,
                lease_until = excluded.lease_until,
                updated_at = CURRENT_TIMESTAMP
            ''',
            (task_id, assignee_id, delivery_date, token, timestamp + lease_seconds),
        )
        return token


def set_reminder_delivery_status(
    task_id: int,
    assignee_id: int,
    delivery_date: str,
    status: str,
    error: str | None = None,
    *, claim_token: str,
) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            '''
            UPDATE reminder_deliveries
            SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP,
                claim_token = NULL, lease_until = 0
            WHERE task_id = ? AND assignee_id = ? AND delivery_date = ? AND claim_token = ?
            ''',
            (status, error, task_id, assignee_id, delivery_date, claim_token),
        )
        return cursor.rowcount == 1


def compute_recurrence_deadline(base: date, recurrence: str) -> date | None:
    if recurrence == 'daily':
        return base + timedelta(days=1)
    if recurrence == 'weekly':
        return base + timedelta(days=7)
    if recurrence == 'monthly':
        year = base.year + (1 if base.month == 12 else 0)
        month = base.month % 12 + 1
        last_day = calendar.monthrange(year, month)[1]
        return date(year, month, min(base.day, last_day))
    return None


def list_task_checklist_items(task_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT id, task_id, content, done, position
            FROM task_checklist_items
            WHERE task_id = ?
            ORDER BY position ASC, id ASC
            ''',
            (task_id,),
        ).fetchall()


def list_project_checklist_items(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT c.id, c.task_id, c.content, c.done, c.position
            FROM task_checklist_items c
            JOIN tasks t ON t.id = c.task_id
            WHERE t.project_id = ?
            ORDER BY c.position ASC, c.id ASC
            ''',
            (project_id,),
        ).fetchall()


def add_task_checklist_item(task_id: int, content: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            'INSERT INTO task_checklist_items (task_id, content, position) VALUES (?, ?, 0)',
            (task_id, content),
        )
        return int(cur.lastrowid)


def set_task_checklist_item_done(item_id: int, done: bool) -> None:
    with get_connection() as conn:
        conn.execute(
            'UPDATE task_checklist_items SET done = ? WHERE id = ?',
            (1 if done else 0, item_id),
        )


def _recurrence_of(conn: sqlite3.Connection, task_id: int) -> str | None:
    row = conn.execute('SELECT recurrence FROM tasks WHERE id = ? LIMIT 1', (task_id,)).fetchone()
    if not row:
        return None
    return row['recurrence'] or None


def _is_project_member(conn: sqlite3.Connection, project_id: int, user_id: int) -> bool:
    row = conn.execute(
        '''
        SELECT p.created_by
        FROM projects p
        LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
        WHERE p.id = ? AND (p.created_by = ? OR pm.user_id = ?)
        LIMIT 1
        ''',
        (user_id, project_id, user_id, user_id),
    ).fetchone()
    return row is not None


def _copy_checklist_to_task(conn: sqlite3.Connection, source_task_id: int, target_task_id: int) -> None:
    items = conn.execute(
        'SELECT content, done, position FROM task_checklist_items WHERE task_id = ? ORDER BY position ASC, id ASC',
        (source_task_id,),
    ).fetchall()
    for item in items:
        conn.execute(
            'INSERT INTO task_checklist_items (task_id, content, done, position) VALUES (?, ?, ?, ?)',
            (target_task_id, item['content'], item['done'], item['position']),
        )


def _copy_attachments_to_task(conn: sqlite3.Connection, source_task_id: int, target_task_id: int) -> None:
    attachments = conn.execute(
        'SELECT filename, mime, size, content FROM task_attachments WHERE task_id = ? ORDER BY id ASC',
        (source_task_id,),
    ).fetchall()
    for attachment in attachments:
        conn.execute(
            'INSERT INTO task_attachments (task_id, filename, mime, size, content) VALUES (?, ?, ?, ?, ?)',
            (target_task_id, attachment['filename'], attachment['mime'], attachment['size'], attachment['content']),
        )


def _handle_recurrence(conn: sqlite3.Connection, task_id: int, new_status: str) -> bool:
    """Erzeugt hoechstens eine Folgeaufgabe, wenn eine Wiederholungsaufgabe abgeschlossen wird."""
    if new_status != 'done':
        return False
    recurrence = _recurrence_of(conn, task_id)
    if not recurrence:
        return False

    existing = conn.execute(
        'SELECT 1 FROM task_recurrence_links WHERE source_task_id = ? LIMIT 1',
        (task_id,),
    ).fetchone()
    if existing:
        return False

    task = conn.execute('SELECT * FROM tasks WHERE id = ? LIMIT 1', (task_id,)).fetchone()
    if not task:
        return False

    base = project_today()
    if task['deadline']:
        try:
            base = date.fromisoformat(task['deadline'])
        except ValueError:
            base = project_today()

    next_deadline = compute_recurrence_deadline(base, recurrence)
    if next_deadline is None:
        return False

    # Zuweisung erneut validieren: nach Freigabeentzug darf die Folgeaufgabe
    # niemandem zugewiesen bleiben, der das Projekt nicht mehr bearbeiten kann.
    assignee_id = task['assignee_id']
    if assignee_id is not None and not _is_project_member(conn, task['project_id'], int(assignee_id)):
        assignee_id = None

    # Produktregel: Meilenstein wird uebernommen, Abhaengigkeiten nicht.
    cur = conn.execute(
        '''
        INSERT INTO tasks (project_id, title, description, status, focus, priority, recurrence, milestone_id, assignee_id, deadline)
        VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
        ''',
        (
            task['project_id'],
            task['title'],
            task['description'],
            task['focus'],
            task['priority'],
            recurrence,
            task['milestone_id'],
            assignee_id,
            next_deadline.isoformat(),
        ),
    )
    followup_id = int(cur.lastrowid)
    _record_event(conn, followup_id, None, 'System (Wiederholung)', 'task_created', None, 'open')
    _copy_checklist_to_task(conn, task_id, followup_id)
    _copy_attachments_to_task(conn, task_id, followup_id)
    conn.execute(
        'INSERT INTO task_recurrence_links (source_task_id, followup_task_id) VALUES (?, ?)',
        (task_id, followup_id),
    )
    return True


def list_task_templates(user_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT id, name, title, description, focus, priority, created_at
            FROM task_templates
            WHERE created_by = ?
            ORDER BY LOWER(name) ASC, id ASC
            ''',
            (user_id,),
        ).fetchall()


def list_task_template_items(template_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT id, template_id, content, position
            FROM task_template_items
            WHERE template_id = ?
            ORDER BY position ASC, id ASC
            ''',
            (template_id,),
        ).fetchall()


def create_task_template(
    user_id: int,
    name: str,
    title: str,
    description: str,
    focus: bool,
    priority: str,
    checklist_lines: list[str],
) -> int:
    if priority not in {'low', 'normal', 'high'}:
        priority = 'normal'
    with get_connection() as conn:
        cur = conn.execute(
            '''
            INSERT INTO task_templates (name, title, description, focus, priority, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (name, title, description, 1 if focus else 0, priority, user_id),
        )
        template_id = int(cur.lastrowid)
        for position, line in enumerate(checklist_lines):
            cleaned = line.strip()
            if cleaned:
                conn.execute(
                    'INSERT INTO task_template_items (template_id, content, position) VALUES (?, ?, ?)',
                    (template_id, cleaned, position),
                )
        return template_id


def create_task_from_template(project_id: int, template_id: int, user_id: int) -> int | None:
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        if not _is_project_member(conn, project_id, user_id):
            return None
        template = conn.execute(
            'SELECT * FROM task_templates WHERE id = ? AND created_by = ? LIMIT 1',
            (template_id, user_id),
        ).fetchone()
        if not template:
            return None

        cur = conn.execute(
            '''
            INSERT INTO tasks (project_id, title, description, status, focus, priority)
            VALUES (?, ?, ?, 'open', ?, ?)
            ''',
            (project_id, template['title'], template['description'], template['focus'], template['priority']),
        )
        task_id = int(cur.lastrowid)
        actor = conn.execute('SELECT username FROM users WHERE id=?', (user_id,)).fetchone()
        _record_event(conn, task_id, user_id, actor['username'], 'task_created', None, 'open')
        items = conn.execute(
            'SELECT content, position FROM task_template_items WHERE template_id = ? ORDER BY position ASC, id ASC',
            (template_id,),
        ).fetchall()
        for item in items:
            conn.execute(
                'INSERT INTO task_checklist_items (task_id, content, position) VALUES (?, ?, ?)',
                (task_id, item['content'], item['position']),
            )
        return task_id


def create_milestone(project_id: int, name: str, due_date: str | None) -> int:
    due_date = normalize_deadline(due_date)
    with get_connection() as conn:
        cur = conn.execute(
            'INSERT INTO milestones (project_id, name, due_date) VALUES (?, ?, ?)',
            (project_id, name, due_date),
        )
        return int(cur.lastrowid)


def list_project_milestones(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT id, project_id, name, due_date, created_at
            FROM milestones
            WHERE project_id = ?
            ORDER BY due_date IS NULL, due_date ASC, id ASC
            ''',
            (project_id,),
        ).fetchall()


def _reaches(conn: sqlite3.Connection, start_id: int, target_id: int) -> bool:
    """Prueft, ob start_id transitiv von target_id abhaengt."""
    stack = [start_id]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        rows = conn.execute(
            'SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?',
            (current,),
        ).fetchall()
        for row in rows:
            nxt = int(row['depends_on_task_id'])
            if nxt == target_id:
                return True
            stack.append(nxt)
    return False


def add_task_dependency(task_id: int, depends_on_task_id: int, user_id: int) -> str:
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        task = conn.execute(
            '''
            SELECT t.id, t.project_id
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE t.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, task_id, user_id, user_id),
        ).fetchone()
        if not task:
            return 'not_found'

        blocker = conn.execute(
            '''
            SELECT t.id, t.project_id
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE t.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, depends_on_task_id, user_id, user_id),
        ).fetchone()
        if not blocker:
            return 'not_found'

        if int(task['project_id']) != int(blocker['project_id']):
            return 'different_project'

        if task_id == depends_on_task_id:
            return 'self_dependency'

        if _reaches(conn, depends_on_task_id, task_id):
            return 'cycle'

        conn.execute(
            '''
            INSERT INTO task_dependencies (task_id, depends_on_task_id)
            VALUES (?, ?)
            ON CONFLICT(task_id, depends_on_task_id) DO NOTHING
            ''',
            (task_id, depends_on_task_id),
        )
        return 'ok'


def list_project_dependencies(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                d.id,
                d.task_id,
                d.depends_on_task_id,
                b.title AS blocking_title,
                b.status AS blocking_status
            FROM task_dependencies d
            JOIN tasks t ON t.id = d.task_id
            JOIN tasks b ON b.id = d.depends_on_task_id
            WHERE t.project_id = ?
            ORDER BY d.id ASC
            ''',
            (project_id,),
        ).fetchall()


def get_task_if_accessible(task_id: int, user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                t.id,
                t.project_id,
                t.title,
                t.description,
                t.status,
                t.focus,
                t.assignee_id
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE t.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, task_id, user_id, user_id),
        ).fetchone()


def get_task_detail_if_accessible(task_id: int, user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                t.id,
                t.project_id,
                p.name AS project_name,
                t.title,
                t.description,
                t.status,
                t.focus,
                t.priority,
                t.recurrence,
                t.milestone_id,
                m.name AS milestone_name,
                t.deadline,
                t.created_at,
                t.completed_at,
                t.assignee_id,
                u.username AS assignee_name
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN users u ON u.id = t.assignee_id
            LEFT JOIN milestones m ON m.id = t.milestone_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE t.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, task_id, user_id, user_id),
        ).fetchone()


def update_task_status_if_accessible(task_id: int, user_id: int, status: str, actor_name: str = '') -> int | None:
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            '''
            SELECT t.project_id, t.status
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE t.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, task_id, user_id, user_id),
        ).fetchone()
        if not row:
            return None

        old_status = str(row['status'])
        conn.execute(
            '''
            UPDATE tasks
            SET status = ?,
                completed_at = CASE
                    WHEN ? = 'done' THEN COALESCE(completed_at, CURRENT_TIMESTAMP)
                    ELSE NULL
                END
            WHERE id = ?
            ''',
            (status, status, task_id),
        )
        if old_status != status:
            event_type = 'task_reopened' if (old_status == 'done' and status != 'done') else 'status_changed'
            _record_event(conn, task_id, user_id, actor_name, event_type, old_status, status)
        if status == 'done':
            _handle_recurrence(conn, task_id, status)
        return int(row['project_id'])


def update_task_if_accessible(
    task_id: int,
    user_id: int,
    title: str,
    description: str,
    status: str,
    assignee_id: int | None,
    focus: bool,
    deadline: str | None = None,
    priority: str = 'normal',
    recurrence: str | None = None,
    milestone_id: int | None = None,
    actor_name: str = '',
) -> int | None:
    deadline = normalize_deadline(deadline)
    if priority not in {'low', 'normal', 'high'}:
        priority = 'normal'
    if recurrence not in {'daily', 'weekly', 'monthly'}:
        recurrence = None
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            '''
            SELECT t.project_id, t.title, t.description, t.status, t.focus, t.assignee_id, t.deadline, t.priority, t.recurrence, t.milestone_id
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE t.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, task_id, user_id, user_id),
        ).fetchone()
        if not row:
            return None

        conn.execute(
            '''
            UPDATE tasks
            SET title = ?,
                description = ?,
                status = ?,
                focus = ?,
                priority = ?,
                recurrence = ?,
                milestone_id = ?,
                assignee_id = ?,
                deadline = ?,
                completed_at = CASE
                    WHEN ? = 'done' THEN COALESCE(completed_at, CURRENT_TIMESTAMP)
                    ELSE NULL
                END
            WHERE id = ?
            ''',
            (title, description, status, 1 if focus else 0, priority, recurrence, milestone_id, assignee_id, deadline, status, task_id),
        )

        if str(row['title']) != title:
            _record_event(conn, task_id, user_id, actor_name, 'title_changed', str(row['title']), title)
        if str(row['description']) != description:
            _record_event(conn, task_id, user_id, actor_name, 'description_changed', str(row['description']), description)
        if str(row['status']) != status:
            event_type = 'task_reopened' if (str(row['status']) == 'done' and status != 'done') else 'status_changed'
            _record_event(conn, task_id, user_id, actor_name, event_type, str(row['status']), status)
        if int(row['focus'] or 0) != (1 if focus else 0):
            _record_event(
                conn, task_id, user_id, actor_name, 'focus_changed',
                '1' if int(row['focus'] or 0) else '0',
                '1' if focus else '0',
            )
        if str(row['priority'] or 'normal') != priority:
            _record_event(conn, task_id, user_id, actor_name, 'priority_changed', str(row['priority'] or 'normal'), priority)
        if (row['recurrence'] or None) != recurrence:
            _record_event(conn, task_id, user_id, actor_name, 'recurrence_changed', row['recurrence'] or None, recurrence)
        old_milestone = int(row['milestone_id']) if row['milestone_id'] is not None else None
        if old_milestone != milestone_id:
            _record_event(
                conn, task_id, user_id, actor_name, 'milestone_changed',
                str(old_milestone) if old_milestone is not None else None,
                str(milestone_id) if milestone_id is not None else None,
            )
        old_assignee = int(row['assignee_id']) if row['assignee_id'] is not None else None
        if old_assignee != assignee_id:
            _record_event(
                conn, task_id, user_id, actor_name, 'assignee_changed',
                _username(conn, old_assignee),
                _username(conn, assignee_id),
            )
        old_deadline = row['deadline']
        if (old_deadline or None) != (deadline or None):
            _record_event(conn, task_id, user_id, actor_name, 'deadline_changed', old_deadline, deadline)

        if status == 'done':
            _handle_recurrence(conn, task_id, status)

        return int(row['project_id'])


def list_project_members(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        owner = conn.execute(
            '''
            SELECT u.id, u.username, u.role AS account_role, 'owner' AS project_role, p.created_at AS added_at
            FROM projects p
            JOIN users u ON u.id = p.created_by
            WHERE p.id = ?
            ''',
            (project_id,),
        ).fetchone()

        members = conn.execute(
            '''
            SELECT u.id, u.username, u.role AS account_role, pm.role AS project_role, pm.created_at AS added_at
            FROM project_members pm
            JOIN users u ON u.id = pm.user_id
            WHERE pm.project_id = ?
            ORDER BY pm.created_at ASC
            ''',
            (project_id,),
        ).fetchall()

    rows: list[sqlite3.Row] = []
    if owner:
        rows.append(owner)
    rows.extend(members)
    return rows


def add_project_member(project_id: int, user_id: int, role: str) -> bool:
    try:
        with get_connection() as conn:
            owner = conn.execute(
                'SELECT created_by FROM projects WHERE id = ? LIMIT 1',
                (project_id,),
            ).fetchone()
            if not owner:
                return False
            if owner['created_by'] == user_id:
                return False

            conn.execute(
                '''
                INSERT INTO project_members (project_id, user_id, role)
                VALUES (?, ?, ?)
                ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role
                ''',
                (project_id, user_id, role),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def remove_project_member(project_id: int, user_id: int) -> bool:
    with get_connection() as conn:
        owner = conn.execute(
            'SELECT created_by FROM projects WHERE id = ? LIMIT 1',
            (project_id,),
        ).fetchone()
        if not owner or owner['created_by'] == user_id:
            return False

        conn.execute(
            'DELETE FROM project_members WHERE project_id = ? AND user_id = ?',
            (project_id, user_id),
        )
    return True


def create_attachment(
    task_id: int,
    filename: str,
    mime: str,
    size: int,
    content: bytes,
    actor_id: int | None = None,
    actor_name: str = '',
) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            '''
            INSERT INTO task_attachments (task_id, filename, mime, size, content)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (task_id, filename, mime, size, content),
        )
        if actor_id is not None:
            _record_event(conn, task_id, actor_id, actor_name, 'attachment_added', None, filename)
        return int(cur.lastrowid)


def list_project_attachments(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                a.id,
                a.task_id,
                a.filename,
                a.mime,
                a.size,
                a.created_at
            FROM task_attachments a
            JOIN tasks t ON t.id = a.task_id
            WHERE t.project_id = ?
            ORDER BY a.created_at DESC, a.id DESC
            ''',
            (project_id,),
        ).fetchall()


def create_task_comment(task_id: int, author_id: int | None, author_name: str, content: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            '''
            INSERT INTO task_comments (task_id, author_id, author_name, content)
            VALUES (?, ?, ?, ?)
            ''',
            (task_id, author_id, author_name or '', content),
        )
        return int(cur.lastrowid)


def list_task_comments(task_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                c.id,
                c.task_id,
                c.author_id,
                c.author_name,
                c.content,
                c.created_at,
                u.username AS author_current
            FROM task_comments c
            LEFT JOIN users u ON u.id = c.author_id
            WHERE c.task_id = ?
            ORDER BY c.created_at ASC, c.id ASC
            ''',
            (task_id,),
        ).fetchall()


def list_task_events(task_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                e.id,
                e.task_id,
                e.actor_id,
                e.actor_name,
                e.event_type,
                e.old_value,
                e.new_value,
                e.created_at,
                u.username AS actor_current
            FROM task_events e
            LEFT JOIN users u ON u.id = e.actor_id
            WHERE e.task_id = ?
            ORDER BY e.created_at ASC, e.id ASC
            ''',
            (task_id,),
        ).fetchall()


def list_project_comments(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                c.id,
                c.task_id,
                c.author_id,
                c.author_name,
                c.content,
                c.created_at,
                u.username AS author_current
            FROM task_comments c
            JOIN tasks t ON t.id = c.task_id
            LEFT JOIN users u ON u.id = c.author_id
            WHERE t.project_id = ?
            ORDER BY c.created_at ASC, c.id ASC
            ''',
            (project_id,),
        ).fetchall()


def list_project_events(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                e.id,
                e.task_id,
                e.actor_id,
                e.actor_name,
                e.event_type,
                e.old_value,
                e.new_value,
                e.created_at,
                u.username AS actor_current
            FROM task_events e
            JOIN tasks t ON t.id = e.task_id
            LEFT JOIN users u ON u.id = e.actor_id
            WHERE t.project_id = ?
            ORDER BY e.created_at ASC, e.id ASC
            ''',
            (project_id,),
        ).fetchall()


def get_attachment_if_accessible(attachment_id: int, user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                a.id,
                a.task_id,
                a.filename,
                a.mime,
                a.size,
                a.content
            FROM task_attachments a
            JOIN tasks t ON t.id = a.task_id
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?
            WHERE a.id = ? AND (p.created_by = ? OR pm.user_id = ?)
            LIMIT 1
            ''',
            (user_id, attachment_id, user_id, user_id),
        ).fetchone()



def _is_admin_user(conn: sqlite3.Connection, user_id: int) -> bool:
    row = conn.execute('SELECT role FROM users WHERE id = ? LIMIT 1', (user_id,)).fetchone()
    return bool(row and row['role'] == 'admin')


def has_fs_folder_access(folder_id: int, user_id: int) -> bool:
    with get_connection() as conn:
        if _is_admin_user(conn, user_id):
            return True

        current_id: int | None = folder_id
        while current_id is not None:
            row = conn.execute(
                'SELECT id, parent_id, created_by FROM fs_folders WHERE id = ? LIMIT 1',
                (current_id,),
            ).fetchone()
            if not row:
                return False
            if int(row['created_by']) == user_id:
                return True

            membership = conn.execute(
                'SELECT 1 FROM fs_folder_members WHERE folder_id = ? AND user_id = ? LIMIT 1',
                (current_id, user_id),
            ).fetchone()
            if membership:
                return True

            parent = row['parent_id']
            current_id = int(parent) if parent is not None else None

    return False


def fs_folder_access_type(folder_id: int, user_id: int) -> str:
    with get_connection() as conn:
        if _is_admin_user(conn, user_id):
            return 'own'

        row = conn.execute(
            'SELECT created_by FROM fs_folders WHERE id = ? LIMIT 1',
            (folder_id,),
        ).fetchone()
        if not row:
            return 'none'
        if int(row['created_by']) == user_id:
            return 'own'

    return 'shared' if has_fs_folder_access(folder_id, user_id) else 'none'


def get_fs_folder(folder_id: int, user_id: int) -> sqlite3.Row | None:
    if not has_fs_folder_access(folder_id, user_id):
        return None

    with get_connection() as conn:
        row = conn.execute(
            '''
            SELECT
                f.id,
                f.parent_id,
                f.name,
                f.created_by,
                f.created_at,
                u.username AS created_by_name
            FROM fs_folders f
            JOIN users u ON u.id = f.created_by
            WHERE f.id = ?
            LIMIT 1
            ''',
            (folder_id,),
        ).fetchone()
        if not row:
            return None

    as_dict = dict(row)
    as_dict['access_type'] = fs_folder_access_type(folder_id, user_id)
    return as_dict


def list_fs_folders(parent_id: int | None, user_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        if parent_id is not None and not has_fs_folder_access(parent_id, user_id):
            return []

        if parent_id is None:
            rows = conn.execute(
                '''
                SELECT
                    f.id,
                    f.parent_id,
                    f.name,
                    f.created_by,
                    f.created_at,
                    u.username AS created_by_name,
                    (SELECT COUNT(*) FROM fs_files ff WHERE ff.folder_id = f.id) AS file_count,
                    (SELECT COUNT(*) FROM fs_folders cf WHERE cf.parent_id = f.id) AS folder_count
                FROM fs_folders f
                JOIN users u ON u.id = f.created_by
                WHERE f.parent_id IS NULL
                ORDER BY LOWER(f.name) ASC, f.id ASC
                '''
            ).fetchall()
        else:
            rows = conn.execute(
                '''
                SELECT
                    f.id,
                    f.parent_id,
                    f.name,
                    f.created_by,
                    f.created_at,
                    u.username AS created_by_name,
                    (SELECT COUNT(*) FROM fs_files ff WHERE ff.folder_id = f.id) AS file_count,
                    (SELECT COUNT(*) FROM fs_folders cf WHERE cf.parent_id = f.id) AS folder_count
                FROM fs_folders f
                JOIN users u ON u.id = f.created_by
                WHERE f.parent_id = ?
                ORDER BY LOWER(f.name) ASC, f.id ASC
                ''',
                (parent_id,),
            ).fetchall()

    result: list[sqlite3.Row] = []
    for row in rows:
        folder_id = int(row['id'])
        access_type = fs_folder_access_type(folder_id, user_id)
        if access_type == 'none':
            continue
        row_dict = dict(row)
        row_dict['access_type'] = access_type
        result.append(row_dict)
    return result


def list_fs_files(parent_id: int | None, user_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        if parent_id is not None and not has_fs_folder_access(parent_id, user_id):
            return []

        if parent_id is None:
            rows = conn.execute(
                '''
                SELECT
                    ff.id,
                    ff.folder_id,
                    ff.stored_name,
                    ff.original_name,
                    ff.mime,
                    ff.size,
                    ff.uploaded_by,
                    ff.created_at,
                    u.username AS uploaded_by_name
                FROM fs_files ff
                JOIN users u ON u.id = ff.uploaded_by
                WHERE ff.folder_id IS NULL
                ORDER BY ff.created_at DESC, ff.id DESC
                '''
            ).fetchall()

            current = conn.execute('SELECT role FROM users WHERE id = ? LIMIT 1', (user_id,)).fetchone()
            is_admin = bool(current and current['role'] == 'admin')
            if is_admin:
                return rows
            return [row for row in rows if int(row['uploaded_by']) == user_id]

        return conn.execute(
            '''
            SELECT
                ff.id,
                ff.folder_id,
                ff.stored_name,
                ff.original_name,
                ff.mime,
                ff.size,
                ff.uploaded_by,
                ff.created_at,
                u.username AS uploaded_by_name
            FROM fs_files ff
            JOIN users u ON u.id = ff.uploaded_by
            WHERE ff.folder_id = ?
            ORDER BY ff.created_at DESC, ff.id DESC
            ''',
            (parent_id,),
        ).fetchall()


def list_fs_breadcrumbs(folder_id: int | None, user_id: int) -> list[sqlite3.Row]:
    if folder_id is None or not has_fs_folder_access(folder_id, user_id):
        return []

    with get_connection() as conn:
        crumbs: list[sqlite3.Row] = []
        current = folder_id
        while True:
            row = conn.execute(
                'SELECT id, parent_id, name FROM fs_folders WHERE id = ? LIMIT 1',
                (current,),
            ).fetchone()
            if not row:
                break
            crumbs.append(row)
            if row['parent_id'] is None:
                break
            current = int(row['parent_id'])

    crumbs.reverse()
    return crumbs


def _find_folder_child(conn: sqlite3.Connection, parent_id: int | None, name: str) -> sqlite3.Row | None:
    clean_name = name.strip()
    if not clean_name:
        return None

    if parent_id is None:
        return conn.execute(
            '''
            SELECT id, parent_id, name
            FROM fs_folders
            WHERE parent_id IS NULL AND LOWER(name) = LOWER(?)
            LIMIT 1
            ''',
            (clean_name,),
        ).fetchone()

    return conn.execute(
        '''
        SELECT id, parent_id, name
        FROM fs_folders
        WHERE parent_id = ? AND LOWER(name) = LOWER(?)
        LIMIT 1
        ''',
        (parent_id, clean_name),
    ).fetchone()


def get_or_create_fs_folder(parent_id: int | None, name: str, created_by: int) -> int:
    clean_name = name.strip()
    if not clean_name:
        raise ValueError('folder name required')

    if parent_id is not None and not has_fs_folder_access(parent_id, created_by):
        raise PermissionError('no access to parent folder')

    with get_connection() as conn:
        existing = _find_folder_child(conn, parent_id, clean_name)
        if existing:
            return int(existing['id'])

        cur = conn.execute(
            'INSERT INTO fs_folders (parent_id, name, created_by) VALUES (?, ?, ?)',
            (parent_id, clean_name, created_by),
        )
        return int(cur.lastrowid)


def ensure_fs_folder_path(base_parent_id: int | None, relative_parts: list[str], created_by: int) -> int | None:
    parent_id = base_parent_id
    if base_parent_id is not None and not has_fs_folder_access(base_parent_id, created_by):
        raise PermissionError('no access to parent folder')

    if not relative_parts:
        return parent_id

    with get_connection() as conn:
        for raw_part in relative_parts:
            part = raw_part.strip()
            if not part:
                continue

            existing = _find_folder_child(conn, parent_id, part)
            if existing:
                parent_id = int(existing['id'])
                continue

            cur = conn.execute(
                'INSERT INTO fs_folders (parent_id, name, created_by) VALUES (?, ?, ?)',
                (parent_id, part, created_by),
            )
            parent_id = int(cur.lastrowid)

    return parent_id


def create_fs_file(
    folder_id: int | None,
    stored_name: str,
    original_name: str,
    mime: str,
    size: int,
    uploaded_by: int,
) -> int:
    if folder_id is not None and not has_fs_folder_access(folder_id, uploaded_by):
        raise PermissionError('no access to folder')

    with get_connection() as conn:
        cur = conn.execute(
            '''
            INSERT INTO fs_files (folder_id, stored_name, original_name, mime, size, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (folder_id, stored_name, original_name, mime, size, uploaded_by),
        )
        return int(cur.lastrowid)


def get_fs_file(file_id: int, user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        row = conn.execute(
            '''
            SELECT
                ff.id,
                ff.folder_id,
                ff.stored_name,
                ff.original_name,
                ff.mime,
                ff.size,
                ff.uploaded_by,
                ff.created_at,
                u.username AS uploaded_by_name
            FROM fs_files ff
            JOIN users u ON u.id = ff.uploaded_by
            WHERE ff.id = ?
            LIMIT 1
            ''',
            (file_id,),
        ).fetchone()
        if not row:
            return None

        folder_id = row['folder_id']
        if folder_id is None:
            current = conn.execute('SELECT role FROM users WHERE id = ? LIMIT 1', (user_id,)).fetchone()
            is_admin = bool(current and current['role'] == 'admin')
            if not is_admin and int(row['uploaded_by']) != user_id:
                return None
            return row

    if not has_fs_folder_access(int(folder_id), user_id):
        return None
    return row


def delete_fs_file_if_owner(file_id: int, user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        row = conn.execute(
            '''
            SELECT id, folder_id, stored_name, original_name, uploaded_by
            FROM fs_files
            WHERE id = ?
            LIMIT 1
            ''',
            (file_id,),
        ).fetchone()
        if not row:
            return None
        if int(row['uploaded_by']) != user_id:
            return None

        conn.execute('DELETE FROM fs_files WHERE id = ?', (file_id,))
        return row


def fs_usage_for_user(user_id: int) -> int:
    with get_connection() as conn:
        value = conn.execute(
            'SELECT COALESCE(SUM(size), 0) FROM fs_files WHERE uploaded_by = ?',
            (user_id,),
        ).fetchone()[0]
        return int(value or 0)


def list_fs_folder_members(folder_id: int, user_id: int) -> list[sqlite3.Row]:
    if not has_fs_folder_access(folder_id, user_id):
        return []

    with get_connection() as conn:
        owner = conn.execute(
            '''
            SELECT u.id, u.username, 'owner' AS share_role
            FROM fs_folders f
            JOIN users u ON u.id = f.created_by
            WHERE f.id = ?
            LIMIT 1
            ''',
            (folder_id,),
        ).fetchone()

        shared = conn.execute(
            '''
            SELECT u.id, u.username, 'shared' AS share_role
            FROM fs_folder_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.folder_id = ?
            ORDER BY LOWER(u.username) ASC
            ''',
            (folder_id,),
        ).fetchall()

    members: list[sqlite3.Row] = []
    if owner:
        members.append(owner)
    members.extend(shared)
    return members


def list_fs_shareable_users(folder_id: int, user_id: int) -> list[sqlite3.Row]:
    if not has_fs_folder_access(folder_id, user_id):
        return []

    with get_connection() as conn:
        folder = conn.execute(
            'SELECT created_by FROM fs_folders WHERE id = ? LIMIT 1',
            (folder_id,),
        ).fetchone()
        if not folder:
            return []

        owner_id = int(folder['created_by'])
        shared_ids = {
            int(row['user_id'])
            for row in conn.execute(
                'SELECT user_id FROM fs_folder_members WHERE folder_id = ?',
                (folder_id,),
            ).fetchall()
        }

        users = conn.execute(
            'SELECT id, username, role FROM users ORDER BY LOWER(username) ASC',
        ).fetchall()

    return [row for row in users if int(row['id']) != owner_id and int(row['id']) not in shared_ids]


def share_fs_folder(folder_id: int, owner_user_id: int, target_user_id: int) -> bool:
    with get_connection() as conn:
        folder = conn.execute(
            'SELECT created_by FROM fs_folders WHERE id = ? LIMIT 1',
            (folder_id,),
        ).fetchone()
        if not folder:
            return False

        is_admin = _is_admin_user(conn, owner_user_id)
        if not is_admin and int(folder['created_by']) != owner_user_id:
            return False

        if int(folder['created_by']) == target_user_id:
            return False

        target = conn.execute('SELECT id FROM users WHERE id = ? LIMIT 1', (target_user_id,)).fetchone()
        if not target:
            return False

        conn.execute(
            '''
            INSERT INTO fs_folder_members (folder_id, user_id)
            VALUES (?, ?)
            ON CONFLICT(folder_id, user_id) DO NOTHING
            ''',
            (folder_id, target_user_id),
        )
    return True


def unshare_fs_folder(folder_id: int, owner_user_id: int, target_user_id: int) -> bool:
    with get_connection() as conn:
        folder = conn.execute(
            'SELECT created_by FROM fs_folders WHERE id = ? LIMIT 1',
            (folder_id,),
        ).fetchone()
        if not folder:
            return False

        is_admin = _is_admin_user(conn, owner_user_id)
        if not is_admin and int(folder['created_by']) != owner_user_id:
            return False

        conn.execute(
            'DELETE FROM fs_folder_members WHERE folder_id = ? AND user_id = ?',
            (folder_id, target_user_id),
        )
    return True


def list_fs_descendant_folders(root_folder_id: int, user_id: int) -> list[sqlite3.Row]:
    if not has_fs_folder_access(root_folder_id, user_id):
        return []

    with get_connection() as conn:
        return conn.execute(
            '''
            WITH RECURSIVE descendants AS (
                SELECT id, parent_id, name
                FROM fs_folders
                WHERE id = ?
                UNION ALL
                SELECT f.id, f.parent_id, f.name
                FROM fs_folders f
                JOIN descendants d ON f.parent_id = d.id
            )
            SELECT id, parent_id, name
            FROM descendants
            ORDER BY id ASC
            ''',
            (root_folder_id,),
        ).fetchall()


def list_fs_files_for_folders(folder_ids: list[int]) -> list[sqlite3.Row]:
    if not folder_ids:
        return []

    placeholders = ','.join(['?'] * len(folder_ids))
    query = f'''
        SELECT
            id,
            folder_id,
            stored_name,
            original_name,
            mime,
            size,
            uploaded_by,
            created_at
        FROM fs_files
        WHERE folder_id IN ({placeholders})
        ORDER BY folder_id ASC, id ASC
    '''

    with get_connection() as conn:
        return conn.execute(query, tuple(folder_ids)).fetchall()


def list_fs_accessible_root_folders(user_id: int) -> list[sqlite3.Row]:
    rows = list_fs_folders(None, user_id)
    return [row for row in rows if row['parent_id'] is None]


def fs_total_usage() -> int:
    with get_connection() as conn:
        value = conn.execute('SELECT COALESCE(SUM(size), 0) FROM fs_files').fetchone()[0]
        return int(value or 0)


def fs_files_count() -> int:
    with get_connection() as conn:
        value = conn.execute('SELECT COUNT(*) FROM fs_files').fetchone()[0]
        return int(value or 0)


def stats() -> dict[str, Any]:
    with get_connection() as conn:
        users_total = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        projects_total = conn.execute('SELECT COUNT(*) FROM projects').fetchone()[0]
        tasks_total = conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
        open_tasks = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE status IN ('open', 'in_progress')"
        ).fetchone()[0]
        files_total = conn.execute('SELECT COUNT(*) FROM fs_files').fetchone()[0]
    return {
        'users_total': users_total,
        'projects_total': projects_total,
        'tasks_total': tasks_total,
        'open_tasks': open_tasks,
        'files_total': files_total,
    }


def upsert_music_track(payload: dict[str, Any]) -> None:
    track = payload['track']
    analyzer = payload.get('analyzer') or {}
    research = payload.get('research') or {}
    genres = research.get('genres') or {}
    tempo = research.get('tempo') or {}
    with get_connection() as conn:
        conn.execute(
            '''
            INSERT INTO music_tracks (
                track_key, artist, title, album, uri, source, image_url,
                analyzer_bpm, analyzer_confidence, researched_bpm,
                primary_genre, subgenres_json, tags_json, genre_confidence,
                evidence_json, favorite, favorited_at, accepted_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(track_key) DO UPDATE SET
                artist=excluded.artist,
                title=excluded.title,
                album=excluded.album,
                uri=excluded.uri,
                source=excluded.source,
                image_url=excluded.image_url,
                analyzer_bpm=excluded.analyzer_bpm,
                analyzer_confidence=excluded.analyzer_confidence,
                researched_bpm=excluded.researched_bpm,
                primary_genre=excluded.primary_genre,
                subgenres_json=excluded.subgenres_json,
                tags_json=excluded.tags_json,
                genre_confidence=excluded.genre_confidence,
                evidence_json=excluded.evidence_json,
                favorite=MAX(music_tracks.favorite, excluded.favorite),
                favorited_at=COALESCE(excluded.favorited_at, music_tracks.favorited_at),
                accepted_at=excluded.accepted_at,
                updated_at=CURRENT_TIMESTAMP
            ''',
            (
                str(track['identity'])[:256],
                str(track.get('artist') or '')[:300],
                str(track.get('title') or '')[:300],
                str(track.get('album') or '')[:300] or None,
                str(track.get('uri') or '')[:500] or None,
                str(track.get('source') or '')[:80] or None,
                str(track.get('image_url') or '')[:500] or None,
                analyzer.get('bpm'),
                analyzer.get('confidence'),
                tempo.get('bpm'),
                str(genres.get('primary') or '')[:120] or None,
                json.dumps(list(genres.get('subgenres') or [])[:8], ensure_ascii=True),
                json.dumps(list(genres.get('tags') or [])[:20], ensure_ascii=True),
                genres.get('confidence'),
                json.dumps(list(research.get('evidence') or [])[:20], ensure_ascii=True),
                1 if payload.get('favorite') else 0,
                str(payload.get('favorited_at') or '')[:64] or None,
                str(payload['accepted_at'])[:64],
            ),
        )


def remove_music_track(track_key: str) -> None:
    with get_connection() as conn:
        conn.execute('DELETE FROM music_tracks WHERE track_key=?', (track_key,))


def list_music_tracks(
    favorites_only: bool = True,
    query: str = '',
    limit: int = 500,
) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if favorites_only:
        clauses.append('favorite = 1')
    normalized_query = query.strip()
    if normalized_query:
        clauses.append("(artist LIKE ? OR title LIKE ? OR album LIKE ? OR primary_genre LIKE ?)")
        pattern = f'%{normalized_query[:120]}%'
        params.extend([pattern, pattern, pattern, pattern])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    params.append(max(1, min(int(limit), 1000)))
    with get_connection() as conn:
        rows = conn.execute(
            f'''
            SELECT * FROM music_tracks
            {where}
            ORDER BY favorite DESC,
                     COALESCE(favorited_at, accepted_at) DESC,
                     artist COLLATE NOCASE ASC,
                     title COLLATE NOCASE ASC
            LIMIT ?
            ''',
            tuple(params),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item['subgenres'] = json.loads(item.pop('subgenres_json') or '[]')
        item['tags'] = json.loads(item.pop('tags_json') or '[]')
        item['evidence'] = json.loads(item.pop('evidence_json') or '[]')
        result.append(item)
    return result


def music_stats() -> dict[str, int]:
    with get_connection() as conn:
        total = int(conn.execute('SELECT COUNT(*) FROM music_tracks').fetchone()[0] or 0)
        favorites = int(
            conn.execute('SELECT COUNT(*) FROM music_tracks WHERE favorite = 1').fetchone()[0] or 0
        )
    return {'total': total, 'favorites': favorites}
