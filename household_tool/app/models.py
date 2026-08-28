from __future__ import annotations

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
