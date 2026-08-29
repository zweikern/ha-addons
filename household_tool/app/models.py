from __future__ import annotations

import re
from urllib.parse import quote

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str = Field(default="", max_length=2000)


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    status: str = Field(default="open")
    assignee_id: int | None = None


class MusicTrackIngest(BaseModel):
    schema_version: int = Field(ge=1, le=10)
    accepted_at: str = Field(min_length=10, max_length=64)
    event: str = Field(default="library", max_length=32)
    favorite: bool = False
    favorited_at: str | None = Field(default=None, max_length=64)
    track: dict
    analyzer: dict
    research: dict = Field(default_factory=dict)


_STATION_MARKERS = (
    'radio',
    'fm',
    'channel',
    'stream',
    'germany',
    'deutschland',
    'austria',
    'france',
    'switzerland',
    'united kingdom',
    'netherlands',
    'italy',
    'spain',
)


def _looks_like_station(artist: str) -> bool:
    """True wenn der Artist-Wert offensichtlich ein Sender/Channel-Name ist.

    Radio-Streams liefern haeufig den Kanal als Artist (z.B. "90s / Germany")
    statt des echten Kuenstlers.
    """
    text = str(artist or '').strip().casefold()
    if not text:
        return False
    if '/' in text:
        return True
    if any(marker in text for marker in _STATION_MARKERS):
        return True
    return bool(re.match(r'^\d{2,4}s(?:\b|$)', text))


def _search_parts(artist: str | None, title: str | None) -> str:
    artist = str(artist or '').strip()
    title = str(title or '').strip()
    # Bei Sender-Artist (z.B. "90s / Germany") steckt der echte Kuenstler im
    # Titel "Artist - Track". Dann Artist und Track aus dem Titel uebernehmen.
    if artist and ' - ' in title:
        title_artist, _, title_track = title.partition(' - ')
        title_artist = title_artist.strip()
        title_track = title_track.strip()
        if title_artist and title_track and _looks_like_station(artist):
            artist, title = title_artist, title_track
    return ' '.join(part for part in (artist, title) if part).strip()


def music_track_url(
    uri: str | None,
    artist: str | None = None,
    title: str | None = None,
) -> str | None:
    value = str(uri or '').strip()
    prefix = 'spotify:track:'
    if value.startswith(prefix):
        track_id = value[len(prefix):].split('?', 1)[0]
        return f'https://open.spotify.com/track/{track_id}' if track_id else None
    shazam_prefix = 'shazam:track:'
    if value.startswith(shazam_prefix):
        track_key = value[len(shazam_prefix):].strip()
        return f'https://www.shazam.com/track/{track_key}' if track_key else None
    if value.startswith(('https://', 'http://')):
        return value
    query = _search_parts(artist, title)
    return f'https://open.spotify.com/search/{quote(query)}' if query else None
