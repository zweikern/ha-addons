import sys
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

from models import music_track_url


class MusicTemplateTest(unittest.TestCase):
    def test_all_templates_compile(self):
        environment = Environment(loader=FileSystemLoader(APP_DIR / "templates"))
        for path in sorted((APP_DIR / "templates").glob("*.html")):
            environment.get_template(path.name)

    def test_spotify_uri_becomes_shareable_url(self):
        self.assertEqual(
            music_track_url("spotify:track:abc123"),
            "https://open.spotify.com/track/abc123",
        )
        self.assertIsNone(music_track_url("spotify:album:abc123"))


if __name__ == "__main__":
    unittest.main()
