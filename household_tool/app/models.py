from __future__ import annotations

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
    query = ' '.join(
        part for part in (artist, title)
        if part and str(part).strip()
    ).strip()
    return f'https://open.spotify.com/search/{quote(query)}' if query else None
