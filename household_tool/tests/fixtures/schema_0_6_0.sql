-- Generated from db.py at 9654bb1 (0.6.0), schema only; no user data.
BEGIN TRANSACTION;
CREATE TABLE fs_files (
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
CREATE TABLE fs_folder_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(folder_id, user_id),
                FOREIGN KEY(folder_id) REFERENCES fs_folders(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
CREATE TABLE fs_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER,
                name TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(parent_id) REFERENCES fs_folders(id) ON DELETE CASCADE,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );
CREATE TABLE music_tracks (
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
CREATE TABLE project_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member', 'manager')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, user_id),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                parent_id INTEGER,
                created_by INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );
CREATE TABLE task_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                mime TEXT NOT NULL,
                size INTEGER NOT NULL,
                content BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );
CREATE TABLE tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'done')),
                focus INTEGER NOT NULL DEFAULT 0,
                assignee_id INTEGER,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, deadline TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(assignee_id) REFERENCES users(id)
            );
CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            , email TEXT NOT NULL DEFAULT '', mail_opt_in INTEGER NOT NULL DEFAULT 0);
CREATE INDEX idx_fs_folders_parent_name
                ON fs_folders(parent_id, name);
CREATE INDEX idx_fs_files_folder_id
                ON fs_files(folder_id);
CREATE INDEX idx_fs_files_uploaded_by
                ON fs_files(uploaded_by);
CREATE INDEX idx_fs_folder_members_folder
                ON fs_folder_members(folder_id);
CREATE INDEX idx_music_tracks_accepted_at
                ON music_tracks(accepted_at DESC);
DELETE FROM "sqlite_sequence";
COMMIT;
