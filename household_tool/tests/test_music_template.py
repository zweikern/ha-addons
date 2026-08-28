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

    def test_shazam_uri_becomes_shazam_url(self):
        self.assertEqual(
            music_track_url("shazam:track:10276368"),
            "https://www.shazam.com/track/10276368",
        )

    def test_radio_uri_falls_back_to_spotify_search(self):
        self.assertEqual(
            music_track_url("radio:https://example/stream", "Air", "Sexy Boy"),
            "https://open.spotify.com/search/Air%20Sexy%20Boy",
        )


if __name__ == "__main__":
    unittest.main()
