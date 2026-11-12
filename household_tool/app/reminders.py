"""Opt-in Companion notifications with bounded, persistent delivery attempts.

Best effort, not exactly once: after a crash/expired lease a retry may duplicate
an externally accepted message. Never fall back to a shared notify service.
"""
from __future__ import annotations

import json
import math
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from threading import Event
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import db

BERLIN = ZoneInfo('Europe/Berlin')


def valid_target(value: str) -> bool:
    return bool(re.fullmatch(r'notify\.mobile_app_[a-z0-9_]+', value))


def _minutes(value: str) -> int:
    hour, minute = map(int, value.split(':'))
    return hour * 60 + minute


def is_within_quiet_hours(now: datetime, quiet_start: str, quiet_end: str) -> bool:
    start, end = _minutes(quiet_start), _minutes(quiet_end)
    current = now.hour * 60 + now.minute
    if start == end:
        return False
    return start <= current < end if start < end else current >= start or current < end


def is_before_send_time(now: datetime, send_time: str) -> bool:
    return now.hour * 60 + now.minute < _minutes(send_time)


@dataclass
class ReminderSettings:
    enabled: bool = False
    base_url: str = ''
    token: str = ''
    send_time: str = '09:00'
    quiet_start: str = '22:00'
    quiet_end: str = '07:00'
    timeout: float = 5.0
    max_retries: int = 3
    valid: bool = True

    @classmethod
    def from_options(cls, options: dict[str, Any]) -> 'ReminderSettings':
        settings = cls(
            enabled=str(options.get('ha_reminders_enabled', '')).lower() in {'true', '1', 'on'},
            base_url=str(options.get('ha_base_url') or '').strip().rstrip('/'),
            token=str(options.get('ha_token') or '').strip(),
        )
        try:
            for field, key in [('send_time', 'reminder_time'), ('quiet_start', 'reminder_quiet_start'),
                               ('quiet_end', 'reminder_quiet_end')]:
                value = str(options.get(key, getattr(settings, field)))
                if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', value):
                    raise ValueError('invalid_time')
                setattr(settings, field, value)
            settings.timeout = float(options.get('reminder_timeout', 5))
            settings.max_retries = int(options.get('reminder_max_retries', 3))
            if not math.isfinite(settings.timeout) or not 1 <= settings.timeout <= 10:
                raise ValueError('invalid_timeout')
            if not 0 <= settings.max_retries <= 5:
                raise ValueError('invalid_retries')
            parsed = urlparse(settings.base_url)
            if settings.base_url and (parsed.scheme not in {'http', 'https'} or not parsed.hostname
                                      or parsed.username or parsed.password or parsed.query or parsed.fragment):
                raise ValueError('invalid_url')
        except (ValueError, TypeError):
            settings.valid = False
        return settings


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a HA bearer token to a redirected host.
        return None


class HomeAssistantNotifier:
    def __init__(self, settings: ReminderSettings):
        self.settings = settings

    def send(self, title: str, message: str, target: str | None = None) -> tuple[bool, str]:
        if not self.settings.enabled:
            return False, 'disabled'
        if not self.settings.valid or not self.settings.base_url or not self.settings.token:
            return False, 'not_configured'
        if not valid_target(target or ''):
            return False, 'invalid_target'
        domain, service = target.split('.', 1)
        request = urllib.request.Request(
            f'{self.settings.base_url}/api/services/{domain}/{service}',
            data=json.dumps({'title': title, 'message': message}).encode('utf-8'),
            headers={'Authorization': f'Bearer {self.settings.token}', 'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=self.settings.timeout) as response:
                return (True, 'sent') if 200 <= response.status < 300 else (False, 'http_error')
        except Exception:
            # Exceptions may contain URLs or credentials; persist no raw exception.
            return False, 'delivery_failed'


def run_reminder_once(now: datetime | None = None, options: dict[str, Any] | None = None,
                      notifier: HomeAssistantNotifier | None = None,
                      stop_event: Event | None = None) -> dict[str, Any]:
    current = now or datetime.now(BERLIN)
    current = current.replace(tzinfo=BERLIN) if current.tzinfo is None else current.astimezone(BERLIN)
    settings = ReminderSettings.from_options(options or {})
    notifier = notifier or HomeAssistantNotifier(settings)
    result = {'state': 'ok', 'sent': 0, 'failed': 0, 'skipped': 0, 'deliveries': []}
    if not settings.enabled:
        result['state'] = 'disabled'
    elif not settings.valid or not settings.base_url or not settings.token:
        result['state'] = 'not_configured'
    elif is_before_send_time(current, settings.send_time):
        result['state'] = 'before_time'
    elif is_within_quiet_hours(current, settings.quiet_start, settings.quiet_end):
        result['state'] = 'quiet_hours'
    if result['state'] != 'ok':
        return result
    delivery_date = current.date().isoformat()
    attempted = 0
    for row in db.list_due_reminders(delivery_date):
        if attempted >= 25 or (stop_event and stop_event.is_set()):
            break
        task_id, user_id = int(row['id']), int(row['assignee_id'])
        candidate = db.get_reminder_candidate(task_id, user_id, delivery_date)
        if not candidate or not valid_target(str(candidate['reminder_target'])):
            result['skipped'] += 1
            continue
        token = db.claim_reminder_delivery(task_id, user_id, delivery_date, settings.max_retries)
        if token is None:
            result['skipped'] += 1
            continue
        attempted += 1
        # Recheck after reserving: membership/assignment may have changed meanwhile.
        candidate = db.get_reminder_candidate(task_id, user_id, delivery_date)
        if not candidate or not valid_target(str(candidate['reminder_target'])) or (stop_event and stop_event.is_set()):
            db.set_reminder_delivery_status(task_id, user_id, delivery_date, 'failed', 'cancelled', claim_token=token)
            result['skipped'] += 1
            continue
        try:
            ok, detail = notifier.send(title=f"Erinnerung: {candidate['title']}",
                                       message=f"Faellig am {candidate['deadline']}: {candidate['title']}",
                                       target=candidate['reminder_target'])
        except Exception:
            ok, detail = False, 'delivery_failed'
        db.set_reminder_delivery_status(task_id, user_id, delivery_date,
                                        'sent' if ok else 'failed', None if ok else 'delivery_failed',
                                        claim_token=token)
        result['sent' if ok else 'failed'] += 1
        result['deliveries'].append({'task_id': task_id, 'assignee_id': user_id, 'detail': detail})
    return result
