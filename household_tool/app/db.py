from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

DATA_DIR = Path("/data")
DB_PATH = DATA_DIR / "app.db"


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
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
                assignee_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(assignee_id) REFERENCES users(id)
            );
            """
        )


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_users() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY username ASC"
        ).fetchall()


def create_user(username: str, password_hash: str, role: str) -> bool:
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def ensure_admin_account(username: str, password_hash: str) -> bool:
    with get_connection() as conn:
        admin_exists = conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        if admin_exists:
            return False

        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?",
                (password_hash, existing["id"]),
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
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?",
                (password_hash, existing["id"]),
            )
            return False, True

        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, password_hash),
        )
    return True, False


def create_project(name: str, description: str, created_by: int | None) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO projects (name, description, created_by) VALUES (?, ?, ?)",
            (name, description, created_by),
        )
        return int(cur.lastrowid)


def list_projects() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT p.id, p.name, p.description, p.created_at, u.username AS creator_name,
                   COUNT(t.id) AS task_count
            FROM projects p
            LEFT JOIN users u ON u.id = p.created_by
            LEFT JOIN tasks t ON t.project_id = p.id
            GROUP BY p.id
            ORDER BY p.created_at DESC
            """
        ).fetchall()


def get_project(project_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT p.id, p.name, p.description, p.created_at, u.username AS creator_name
            FROM projects p
            LEFT JOIN users u ON u.id = p.created_by
            WHERE p.id = ?
            """,
            (project_id,),
        ).fetchone()


def create_task(
    project_id: int,
    title: str,
    description: str,
    status: str,
    assignee_id: int | None,
) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO tasks (project_id, title, description, status, assignee_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (project_id, title, description, status, assignee_id),
        )
        return int(cur.lastrowid)


def list_project_tasks(project_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT t.id, t.title, t.description, t.status, t.created_at, u.username AS assignee_name
            FROM tasks t
            LEFT JOIN users u ON u.id = t.assignee_id
            WHERE t.project_id = ?
            ORDER BY t.created_at DESC
            """,
            (project_id,),
        ).fetchall()


def stats() -> dict[str, Any]:
    with get_connection() as conn:
        users_total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        projects_total = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        tasks_total = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        open_tasks = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE status IN ('open', 'in_progress')"
        ).fetchone()[0]
    return {
        "users_total": users_total,
        "projects_total": projects_total,
        "tasks_total": tasks_total,
        "open_tasks": open_tasks,
    }
