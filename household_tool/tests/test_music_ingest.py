import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

import db


class MusicIngestTest(unittest.TestCase):
    def test_upsert_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            original_dir, original_path = db.DATA_DIR, db.DB_PATH
            try:
                db.DATA_DIR = Path(directory)
                db.DB_PATH = db.DATA_DIR / "app.db"
                db.init_db()
                payload = {
                    "accepted_at": "2026-08-28T18:00:00+00:00",
                    "track": {
                        "identity": "spotify:track:123",
                        "artist": "Example Artist",
                        "title": "Night Drive",
                        "album": "After Dark",
                        "uri": "spotify:track:123",
                        "source": "spotify",
                    },
                    "analyzer": {"bpm": 124, "confidence": 0.8},
                    "research": {
                        "genres": {
                            "primary": "Electronic",
                            "subgenres": ["Indie Dance"],
                            "tags": ["electronic"],
                            "confidence": 0.9,
                        },
                        "tempo": {"bpm": 122},
                        "evidence": [{"source": "MusicBrainz"}],
                    },
                }
                db.upsert_music_track(payload)
                payload["analyzer"]["bpm"] = 126
                payload["favorite"] = True
                payload["favorited_at"] = "2026-08-28T18:05:00+00:00"
                db.upsert_music_track(payload)
                with sqlite3.connect(db.DB_PATH) as connection:
                    row = connection.execute(
                        "SELECT analyzer_bpm, subgenres_json, favorite, favorited_at FROM music_tracks"
                    ).fetchone()
                    count = connection.execute("SELECT COUNT(*) FROM music_tracks").fetchone()[0]
                self.assertEqual(count, 1)
                self.assertEqual(row[0], 126)
                self.assertEqual(json.loads(row[1]), ["Indie Dance"])
                self.assertEqual(row[2], 1)
                self.assertEqual(row[3], "2026-08-28T18:05:00+00:00")
            finally:
                db.DATA_DIR, db.DB_PATH = original_dir, original_path


if __name__ == "__main__":
    unittest.main()
