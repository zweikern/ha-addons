from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import hash_password, verify_password
from db import (
    create_project,
    create_task,
    create_user,
    ensure_admin_account,
    get_project,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_project_tasks,
    list_projects,
    list_users,
    stats,
)

DATA_DIR = Path("/data")
OPTIONS_PATH = DATA_DIR / "options.json"
SECRET_KEY_PATH = DATA_DIR / "secret_key"
VALID_ROLES = {"admin", "user"}
VALID_TASK_STATUS = {"open", "in_progress", "done"}

app = FastAPI(title="Household Tool")
app.mount("/static", StaticFiles(directory="/app/static"), name="static")
templates = Jinja2Templates(directory="/app/templates")


def load_options() -> dict[str, Any]:
    if not OPTIONS_PATH.exists():
        return {}
    try:
        return json.loads(OPTIONS_PATH.read_text(encoding="utf-8"))
    except Exception as err:  # pragma: no cover - defensive log path
        print(f"[warning] Could not parse /data/options.json: {err}")
        return {}


def get_or_create_secret_key() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text(encoding="utf-8").strip()

    key = secrets.token_urlsafe(48)
    SECRET_KEY_PATH.write_text(key, encoding="utf-8")
    return key


def current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(int(user_id))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(24)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, token: str) -> bool:
    expected = request.session.get("csrf_token", "")
    return bool(expected) and secrets.compare_digest(expected, token or "")


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=303)


def require_login(request: Request):
    user = current_user(request)
    if not user:
        return None, redirect("/login")
    return user, None


def require_admin(request: Request):
    user, response = require_login(request)
    if response:
        return None, response
    if user["role"] != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def ensure_initial_admin() -> None:
    options = load_options()
    admin_username = str(options.get("admin_username") or "admin").strip() or "admin"
    admin_password = str(options.get("admin_password") or "").strip()

    generated_pw = False
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)
        generated_pw = True

    created = ensure_admin_account(admin_username, hash_password(admin_password))
    if created:
        print(f"[info] Initial admin account created: {admin_username}")
        if generated_pw:
            print("[warning] No admin_password configured in add-on options.")
            print(f"[warning] Temporary admin password: {admin_password}")


secret_key = get_or_create_secret_key()
app.add_middleware(
    SessionMiddleware,
    secret_key=secret_key,
    https_only=False,
    same_site="lax",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    ensure_initial_admin()
    print("[info] Database ready at /data/app.db")


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if current_user(request):
        return redirect("/dashboard")
    return redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if current_user(request):
        return redirect("/dashboard")
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": request.query_params.get("error"),
            "csrf_token": csrf_token(request),
            "user": None,
        },
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
):
    if not validate_csrf(request, csrf):
        return redirect("/login?error=csrf")

    user = get_user_by_username(username.strip())
    if not user or not verify_password(password, user["password_hash"]):
        return redirect("/login?error=invalid")

    request.session.clear()
    request.session["user_id"] = int(user["id"])
    request.session["csrf_token"] = secrets.token_urlsafe(24)
    return redirect("/dashboard")


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user, response = require_login(request)
    if response:
        return response

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "stats": stats(),
            "csrf_token": csrf_token(request),
        },
    )


@app.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request):
    user, response = require_login(request)
    if response:
        return response

    return templates.TemplateResponse(
        request,
        "projects.html",
        {
            "user": user,
            "projects": list_projects(),
            "csrf_token": csrf_token(request),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/projects")
def create_project_submit(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=""),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect("/projects?error=csrf")

    name = name.strip()
    if not name:
        return redirect("/projects?error=missing_name")

    create_project(name=name, description=description.strip(), created_by=int(user["id"]))
    return redirect("/projects")


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int):
    user, response = require_login(request)
    if response:
        return response

    project = get_project(project_id)
    if not project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)

    return templates.TemplateResponse(
        request,
        "project_detail.html",
        {
            "user": user,
            "project": project,
            "tasks": list_project_tasks(project_id),
            "users": list_users(),
            "csrf_token": csrf_token(request),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/projects/{project_id}/tasks")
def create_task_submit(
    request: Request,
    project_id: int,
    title: str = Form(...),
    description: str = Form(default=""),
    status: str = Form(default="open"),
    assignee_id: str = Form(default=""),
    csrf: str = Form(...),
):
    user, response = require_login(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect(f"/projects/{project_id}?error=csrf")

    project = get_project(project_id)
    if not project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)

    title = title.strip()
    if not title:
        return redirect(f"/projects/{project_id}?error=missing_title")

    if status not in VALID_TASK_STATUS:
        return redirect(f"/projects/{project_id}?error=invalid_status")

    assignee_value = assignee_id.strip()
    assignee: int | None = None
    if assignee_value:
        try:
            assignee = int(assignee_value)
        except ValueError:
            return redirect(f"/projects/{project_id}?error=invalid_assignee")

    create_task(
        project_id=project_id,
        title=title,
        description=description.strip(),
        status=status,
        assignee_id=assignee,
    )
    return redirect(f"/projects/{project_id}")


@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user, response = require_admin(request)
    if response:
        return response

    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "user": user,
            "users": list_users(),
            "csrf_token": csrf_token(request),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/users")
def create_user_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(default="user"),
    csrf: str = Form(...),
):
    admin_user, response = require_admin(request)
    if response:
        return response

    if not validate_csrf(request, csrf):
        return redirect("/users?error=csrf")

    username = username.strip()
    password = password.strip()
    if not username or not password:
        return redirect("/users?error=missing_fields")

    if role not in VALID_ROLES:
        return redirect("/users?error=invalid_role")

    ok = create_user(username=username, password_hash=hash_password(password), role=role)
    if not ok:
        return redirect("/users?error=user_exists")

    print(f"[info] User created by {admin_user['username']}: {username} ({role})")
    return redirect("/users")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8099)
