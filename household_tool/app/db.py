from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

DATA_DIR = Path('/data')
DB_PATH = DATA_DIR / 'app.db'


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


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
            '''
        )

        # Schema migrations for existing databases
        if not _has_column(conn, 'projects', 'parent_id'):
            conn.execute('ALTER TABLE projects ADD COLUMN parent_id INTEGER')

        if not _has_column(conn, 'tasks', 'focus'):
            conn.execute('ALTER TABLE tasks ADD COLUMN focus INTEGER NOT NULL DEFAULT 0')

        if not _has_column(conn, 'tasks', 'completed_at'):
            conn.execute('ALTER TABLE tasks ADD COLUMN completed_at TEXT')

        if not _has_column(conn, 'users', 'email'):
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")

        if not _has_column(conn, 'users', 'mail_opt_in'):
            conn.execute('ALTER TABLE users ADD COLUMN mail_opt_in INTEGER NOT NULL DEFAULT 0')


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
            SELECT id, username, role, email, mail_opt_in, created_at
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
) -> bool:
    try:
        with get_connection() as conn:
            conn.execute(
                '''
                INSERT INTO users (username, password_hash, role, email, mail_opt_in)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (username, password_hash, role, email.strip(), 1 if mail_opt_in else 0),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def update_user_profile(
    user_id: int,
    email: str,
    mail_opt_in: bool,
    new_password_hash: str | None = None,
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
                SET email = ?, mail_opt_in = ?, password_hash = ?
                WHERE id = ?
                ''',
                (email.strip(), 1 if mail_opt_in else 0, new_password_hash, user_id),
            )
        else:
            conn.execute(
                '''
                UPDATE users
                SET email = ?, mail_opt_in = ?
                WHERE id = ?
                ''',
                (email.strip(), 1 if mail_opt_in else 0, user_id),
            )
    return True


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


def create_task(
    project_id: int,
    title: str,
    description: str,
    status: str,
    assignee_id: int | None,
    focus: bool = False,
) -> int:
    with get_connection() as conn:
        completed_at = 'CURRENT_TIMESTAMP' if status == 'done' else None
        if completed_at:
            cur = conn.execute(
                '''
                INSERT INTO tasks (project_id, title, description, status, focus, assignee_id, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''',
                (project_id, title, description, status, 1 if focus else 0, assignee_id),
            )
        else:
            cur = conn.execute(
                '''
                INSERT INTO tasks (project_id, title, description, status, focus, assignee_id)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (project_id, title, description, status, 1 if focus else 0, assignee_id),
            )
        return int(cur.lastrowid)


def list_project_tasks(project_id: int, view: str = 'all') -> list[sqlite3.Row]:
    where = 'WHERE t.project_id = ?'
    params: list[Any] = [project_id]

    if view == 'open':
        where += " AND t.status IN ('open', 'in_progress')"
    elif view == 'done':
        where += " AND t.status = 'done'"
    elif view == 'focus':
        where += " AND t.focus = 1 AND t.status IN ('open', 'in_progress')"

    query = f'''
        SELECT
            t.id,
            t.project_id,
            t.title,
            t.description,
            t.status,
            t.focus,
            t.created_at,
            t.completed_at,
            t.assignee_id,
            u.username AS assignee_name,
            (SELECT COUNT(*) FROM task_attachments a WHERE a.task_id = t.id) AS attachment_count
        FROM tasks t
        LEFT JOIN users u ON u.id = t.assignee_id
        {where}
        ORDER BY
            t.focus DESC,
            CASE WHEN t.status = 'done' THEN 1 ELSE 0 END,
            t.created_at DESC,
            t.id DESC
    '''

    with get_connection() as conn:
        return conn.execute(query, tuple(params)).fetchall()


def list_project_history(project_id: int, limit: int = 25) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            '''
            SELECT
                t.id,
                t.title,
                t.description,
                t.completed_at,
                t.focus,
                u.username AS assignee_name
            FROM tasks t
            LEFT JOIN users u ON u.id = t.assignee_id
            WHERE t.project_id = ? AND t.completed_at IS NOT NULL
            ORDER BY t.completed_at DESC, t.id DESC
            LIMIT ?
            ''',
            (project_id, limit),
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


def update_task_status_if_accessible(task_id: int, user_id: int, status: str) -> int | None:
    with get_connection() as conn:
        row = conn.execute(
            '''
            SELECT t.project_id
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
            SET status = ?,
                completed_at = CASE
                    WHEN ? = 'done' THEN COALESCE(completed_at, CURRENT_TIMESTAMP)
                    ELSE NULL
                END
            WHERE id = ?
            ''',
            (status, status, task_id),
        )
        return int(row['project_id'])


def update_task_if_accessible(
    task_id: int,
    user_id: int,
    title: str,
    description: str,
    status: str,
    assignee_id: int | None,
    focus: bool,
) -> int | None:
    with get_connection() as conn:
        row = conn.execute(
            '''
            SELECT t.project_id
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
                assignee_id = ?,
                completed_at = CASE
                    WHEN ? = 'done' THEN COALESCE(completed_at, CURRENT_TIMESTAMP)
                    ELSE NULL
                END
            WHERE id = ?
            ''',
            (title, description, status, 1 if focus else 0, assignee_id, status, task_id),
        )
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


def create_attachment(task_id: int, filename: str, mime: str, size: int, content: bytes) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            '''
            INSERT INTO task_attachments (task_id, filename, mime, size, content)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (task_id, filename, mime, size, content),
        )
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
