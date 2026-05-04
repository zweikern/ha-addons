#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover - handled at runtime in the add-on image.
    mqtt = None


APP_NAME = "HA Uptime & Outage Monitor"
APP_VERSION = "0.1.0"
DEVICE_ID = "ha_uptime_outage_monitor"
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
OPTIONS_PATH = DATA_DIR / "options.json"
DB_PATH = DATA_DIR / "downtime_monitor.sqlite3"
BASE_TOPIC = "ha_uptime_outage_monitor"
STATE_TOPIC = f"{BASE_TOPIC}/state"
BINARY_STATE_TOPIC = f"{BASE_TOPIC}/connectivity"
AVAILABILITY_TOPIC = f"{BASE_TOPIC}/status"
DISCOVERY_PREFIX = "homeassistant"


DEFAULT_OPTIONS: dict[str, Any] = {
    "heartbeat_interval_seconds": 60,
    "outage_threshold_seconds": 120,
    "mqtt_host": "core-mosquitto",
    "mqtt_port": 1883,
    "mqtt_username": "",
    "mqtt_password": "",
    "router_host": "192.168.178.1",
    "internet_host": "1.1.1.1",
    "enable_ping_monitoring": True,
}


SENSOR_DEFINITIONS = [
    {
        "key": "downtime_today",
        "object_id": "ha_outage_downtime_today",
        "name": "Downtime Today",
        "field": "downtime_today_minutes",
        "unit": "min",
        "icon": "mdi:timer-off-outline",
    },
    {
        "key": "downtime_7d",
        "object_id": "ha_outage_downtime_7d",
        "name": "Downtime 7 Days",
        "field": "downtime_7d_minutes",
        "unit": "min",
        "icon": "mdi:timer-off-outline",
    },
    {
        "key": "downtime_30d",
        "object_id": "ha_outage_downtime_30d",
        "name": "Downtime 30 Days",
        "field": "downtime_30d_minutes",
        "unit": "min",
        "icon": "mdi:timer-off-outline",
    },
    {
        "key": "outage_count_today",
        "object_id": "ha_outage_count_today",
        "name": "Outage Count Today",
        "field": "outage_count_today",
        "icon": "mdi:counter",
    },
    {
        "key": "outage_count_7d",
        "object_id": "ha_outage_count_7d",
        "name": "Outage Count 7 Days",
        "field": "outage_count_7d",
        "icon": "mdi:counter",
    },
    {
        "key": "outage_count_30d",
        "object_id": "ha_outage_count_30d",
        "name": "Outage Count 30 Days",
        "field": "outage_count_30d",
        "icon": "mdi:counter",
    },
    {
        "key": "last_outage_start",
        "object_id": "ha_outage_last_start",
        "name": "Last Outage Start",
        "field": "last_outage_start",
        "icon": "mdi:clock-start",
    },
    {
        "key": "last_outage_end",
        "object_id": "ha_outage_last_end",
        "name": "Last Outage End",
        "field": "last_outage_end",
        "icon": "mdi:clock-end",
    },
    {
        "key": "last_outage_duration",
        "object_id": "ha_outage_last_duration",
        "name": "Last Outage Duration",
        "field": "last_outage_duration_minutes",
        "unit": "min",
        "icon": "mdi:timer-sand",
    },
    {
        "key": "addon_uptime",
        "object_id": "ha_outage_addon_uptime",
        "name": "Add-on Uptime",
        "field": "addon_uptime_seconds",
        "unit": "s",
        "icon": "mdi:timer-outline",
    },
    {
        "key": "internet_outage_7d",
        "object_id": "ha_outage_internet_outage_7d",
        "name": "Internet Outage 7 Days",
        "field": "internet_outage_7d_minutes",
        "unit": "min",
        "icon": "mdi:web-off",
    },
    {
        "key": "router_outage_7d",
        "object_id": "ha_outage_router_outage_7d",
        "name": "Router Outage 7 Days",
        "field": "router_outage_7d_minutes",
        "unit": "min",
        "icon": "mdi:router-network",
    },
]


BINARY_SENSOR_DEFINITIONS = [
    {
        "key": "internet_online",
        "object_id": "ha_outage_internet_online",
        "name": "Internet Online",
        "field": "internet_online",
    },
    {
        "key": "router_online",
        "object_id": "ha_outage_router_online",
        "name": "Router Online",
        "field": "router_online",
    },
]


def setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s: %(message)s",
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime) -> str:
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def round_minutes(seconds: float) -> float:
    return round(max(0.0, seconds) / 60.0, 2)


def clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


@dataclass(frozen=True)
class Options:
    heartbeat_interval_seconds: int
    outage_threshold_seconds: int
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str
    router_host: str
    internet_host: str
    enable_ping_monitoring: bool


def load_options() -> Options:
    raw = DEFAULT_OPTIONS.copy()
    if OPTIONS_PATH.exists():
        try:
            with OPTIONS_PATH.open("r", encoding="utf-8") as options_file:
                loaded = json.load(options_file)
            if isinstance(loaded, dict):
                raw.update(loaded)
            else:
                logging.warning("Ignoring options.json because it does not contain an object")
        except json.JSONDecodeError as exc:
            logging.warning("Ignoring invalid options.json: %s", exc)
        except OSError as exc:
            logging.warning("Could not read options.json: %s", exc)

    return Options(
        heartbeat_interval_seconds=clamp_int(
            raw.get("heartbeat_interval_seconds"), 60, 10, 3600
        ),
        outage_threshold_seconds=clamp_int(
            raw.get("outage_threshold_seconds"), 120, 0, 86400
        ),
        mqtt_host=str(raw.get("mqtt_host", "")).strip(),
        mqtt_port=clamp_int(raw.get("mqtt_port"), 1883, 1, 65535),
        mqtt_username=str(raw.get("mqtt_username", "")),
        mqtt_password=str(raw.get("mqtt_password", "")),
        router_host=str(raw.get("router_host", "")).strip(),
        internet_host=str(raw.get("internet_host", "")).strip(),
        enable_ping_monitoring=bool(raw.get("enable_ping_monitoring", True)),
    )


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.lock = threading.Lock()
        self.connection = self._connect_with_recovery()

    def _connect_with_recovery(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            connection = self._open_connection()
            self._init_schema(connection)
            return connection
        except sqlite3.DatabaseError as exc:
            logging.warning("SQLite database is not usable; backing it up and starting fresh: %s", exc)
            self._backup_corrupt_database()
            connection = self._open_connection()
            self._init_schema(connection)
            return connection

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _init_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                start_ts TEXT NOT NULL,
                end_ts TEXT,
                duration_seconds INTEGER,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_type_start ON events(type, start_ts)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_type_end ON events(type, end_ts)"
        )
        connection.commit()

    def _backup_corrupt_database(self) -> None:
        if not self.db_path.exists():
            return
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = self.db_path.with_name(f"{self.db_path.name}.corrupt-{timestamp}")
        shutil.move(str(self.db_path), str(backup_path))
        for suffix in ("-wal", "-shm"):
            sidecar = self.db_path.with_name(f"{self.db_path.name}{suffix}")
            if sidecar.exists():
                shutil.move(str(sidecar), str(backup_path.with_name(f"{backup_path.name}{suffix}")))
        logging.warning("Backed up corrupt database to %s", backup_path)

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def insert_event(
        self,
        event_type: str,
        start: datetime,
        end: datetime | None = None,
        duration_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        if end is not None and duration_seconds is None:
            duration_seconds = int(max(0.0, (end - start).total_seconds()))
        metadata_json = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
        with self.lock:
            cursor = self.connection.execute(
                """
                INSERT INTO events(type, start_ts, end_ts, duration_seconds, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    to_iso(start),
                    to_iso(end) if end else None,
                    duration_seconds,
                    metadata_json,
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def update_event_end(self, event_id: int, end: datetime, duration_seconds: int) -> None:
        with self.lock:
            self.connection.execute(
                "UPDATE events SET end_ts = ?, duration_seconds = ? WHERE id = ?",
                (to_iso(end), duration_seconds, event_id),
            )
            self.connection.commit()

    def record_heartbeat(self, timestamp: datetime) -> None:
        self.insert_event("heartbeat", timestamp, timestamp, 0)

    def get_last_heartbeat(self) -> datetime | None:
        with self.lock:
            row = self.connection.execute(
                """
                SELECT start_ts
                FROM events
                WHERE type = 'heartbeat'
                ORDER BY start_ts DESC
                LIMIT 1
                """
            ).fetchone()
        return from_iso(row["start_ts"]) if row else None

    def get_open_down_event(self, event_type: str) -> sqlite3.Row | None:
        with self.lock:
            return self.connection.execute(
                """
                SELECT id, start_ts, metadata_json
                FROM events
                WHERE type = ? AND end_ts IS NULL
                ORDER BY start_ts DESC
                LIMIT 1
                """,
                (event_type,),
            ).fetchone()

    def mark_host_down(self, kind: str, host: str, timestamp: datetime) -> bool:
        down_type = f"{kind}_down"
        if self.get_open_down_event(down_type):
            return False
        self.insert_event(down_type, timestamp, None, None, {"host": host})
        return True

    def mark_host_up(self, kind: str, host: str, timestamp: datetime) -> bool:
        down_type = f"{kind}_down"
        row = self.get_open_down_event(down_type)
        if not row:
            return False
        start = from_iso(row["start_ts"])
        duration_seconds = int(max(0.0, (timestamp - start).total_seconds())) if start else 0
        self.update_event_end(int(row["id"]), timestamp, duration_seconds)
        self.insert_event(f"{kind}_up", timestamp, timestamp, 0, {"host": host})
        return True

    def calculate_metrics(self, now: datetime, process_start: datetime) -> dict[str, Any]:
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        seven_days_start = now - timedelta(days=7)
        thirty_days_start = now - timedelta(days=30)

        last_outage = self._last_event("outage")
        last_duration_seconds = 0
        last_start = "none"
        last_end = "none"
        if last_outage:
            last_start = last_outage["start_ts"]
            last_end = last_outage["end_ts"] or "none"
            if last_outage["duration_seconds"] is not None:
                last_duration_seconds = int(last_outage["duration_seconds"])

        return {
            "downtime_today_minutes": round_minutes(
                self._sum_overlap_seconds("outage", today_start, now)
            ),
            "downtime_7d_minutes": round_minutes(
                self._sum_overlap_seconds("outage", seven_days_start, now)
            ),
            "downtime_30d_minutes": round_minutes(
                self._sum_overlap_seconds("outage", thirty_days_start, now)
            ),
            "outage_count_today": self._count_events_started("outage", today_start, now),
            "outage_count_7d": self._count_events_started("outage", seven_days_start, now),
            "outage_count_30d": self._count_events_started(
                "outage", thirty_days_start, now
            ),
            "last_outage_start": last_start,
            "last_outage_end": last_end,
            "last_outage_duration_minutes": round_minutes(last_duration_seconds),
            "addon_uptime_seconds": int(max(0.0, (now - process_start).total_seconds())),
            "internet_outage_7d_minutes": round_minutes(
                self._sum_overlap_seconds("internet_down", seven_days_start, now)
            ),
            "router_outage_7d_minutes": round_minutes(
                self._sum_overlap_seconds("router_down", seven_days_start, now)
            ),
            "updated_at": to_iso(now),
        }

    def _last_event(self, event_type: str) -> sqlite3.Row | None:
        with self.lock:
            return self.connection.execute(
                """
                SELECT start_ts, end_ts, duration_seconds
                FROM events
                WHERE type = ?
                ORDER BY start_ts DESC
                LIMIT 1
                """,
                (event_type,),
            ).fetchone()

    def _count_events_started(
        self, event_type: str, window_start: datetime, window_end: datetime
    ) -> int:
        with self.lock:
            row = self.connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM events
                WHERE type = ? AND start_ts >= ? AND start_ts <= ?
                """,
                (event_type, to_iso(window_start), to_iso(window_end)),
            ).fetchone()
        return int(row["count"] if row else 0)

    def _sum_overlap_seconds(
        self, event_type: str, window_start: datetime, window_end: datetime
    ) -> float:
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT start_ts, end_ts
                FROM events
                WHERE type = ?
                  AND start_ts <= ?
                  AND (end_ts IS NULL OR end_ts >= ?)
                """,
                (event_type, to_iso(window_end), to_iso(window_start)),
            ).fetchall()

        total = 0.0
        for row in rows:
            start = from_iso(row["start_ts"])
            end = from_iso(row["end_ts"]) or window_end
            if not start:
                continue
            overlap_start = max(start, window_start)
            overlap_end = min(end, window_end)
            if overlap_end > overlap_start:
                total += (overlap_end - overlap_start).total_seconds()
        return total


class NetworkMonitor:
    def __init__(self, store: EventStore, options: Options) -> None:
        self.store = store
        self.options = options
        self.status: dict[str, bool | None] = {"internet": None, "router": None}

    def check_all(self, timestamp: datetime) -> dict[str, bool | None]:
        if not self.options.enable_ping_monitoring:
            return self.status
        self.status["router"] = self._check_host("router", self.options.router_host, timestamp)
        self.status["internet"] = self._check_host(
            "internet", self.options.internet_host, timestamp
        )
        return self.status

    def _check_host(self, kind: str, host: str, timestamp: datetime) -> bool | None:
        if not host:
            return None
        online = ping_host(host)
        if online:
            if self.store.mark_host_up(kind, host, timestamp):
                logging.info("%s is reachable again", kind.capitalize())
        else:
            if self.store.mark_host_down(kind, host, timestamp):
                logging.warning("%s is unreachable", kind.capitalize())
        return online


def ping_host(host: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        logging.warning("Ping command is not available in the container")
    except subprocess.TimeoutExpired:
        logging.warning("Ping timed out for %s", host)
    except OSError as exc:
        logging.warning("Ping failed for %s: %s", host, exc)
    return False


class MqttPublisher:
    def __init__(self, options: Options) -> None:
        self.options = options
        self.client: Any = None
        self.started = False
        self.discovery_published = False

    def start(self) -> bool:
        if self.started:
            return self.client is not None
        self.started = True

        if mqtt is None:
            logging.warning("paho-mqtt is not installed; MQTT publishing is disabled")
            return False
        if not self.options.mqtt_host:
            logging.warning("MQTT host is empty; MQTT publishing is disabled")
            return False

        client = self._create_client()
        client.reconnect_delay_set(min_delay=5, max_delay=60)
        client.max_queued_messages_set(50)
        if self.options.mqtt_username:
            client.username_pw_set(
                self.options.mqtt_username,
                self.options.mqtt_password or None,
            )
        client.will_set(AVAILABILITY_TOPIC, "offline", qos=1, retain=True)
        try:
            client.connect_async(
                self.options.mqtt_host,
                self.options.mqtt_port,
                keepalive=60,
            )
            client.loop_start()
        except OSError as exc:
            logging.warning("Could not start MQTT connection: %s", exc)
            return False

        self.client = client
        logging.info("MQTT publishing configured for %s:%s", self.options.mqtt_host, self.options.mqtt_port)
        return True

    def _create_client(self) -> Any:
        if hasattr(mqtt, "CallbackAPIVersion"):
            return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID)
        return mqtt.Client(client_id=DEVICE_ID)

    def publish_discovery(self, ping_enabled: bool) -> None:
        if not self.start():
            return

        for definition in SENSOR_DEFINITIONS:
            payload: dict[str, Any] = {
                "name": definition["name"],
                "object_id": definition["object_id"],
                "unique_id": f"{DEVICE_ID}_{definition['key']}",
                "state_topic": STATE_TOPIC,
                "value_template": "{{ value_json.%s }}" % definition["field"],
                "availability_topic": AVAILABILITY_TOPIC,
                "icon": definition["icon"],
                "device": device_info(),
            }
            if "unit" in definition:
                payload["unit_of_measurement"] = definition["unit"]
            self._publish_json(
                f"{DISCOVERY_PREFIX}/sensor/{DEVICE_ID}/{definition['key']}/config",
                payload,
                retain=True,
            )

        for definition in BINARY_SENSOR_DEFINITIONS:
            topic = f"{DISCOVERY_PREFIX}/binary_sensor/{DEVICE_ID}/{definition['key']}/config"
            if not ping_enabled:
                self._publish_raw(topic, "", retain=True)
                continue
            payload = {
                "name": definition["name"],
                "object_id": definition["object_id"],
                "unique_id": f"{DEVICE_ID}_{definition['key']}",
                "state_topic": BINARY_STATE_TOPIC,
                "value_template": "{{ value_json.%s }}" % definition["field"],
                "payload_on": "ON",
                "payload_off": "OFF",
                "device_class": "connectivity",
                "availability_topic": AVAILABILITY_TOPIC,
                "device": device_info(),
            }
            self._publish_json(topic, payload, retain=True)

        self.discovery_published = True

    def publish_state(
        self,
        metrics: dict[str, Any],
        connectivity: dict[str, bool | None],
        ping_enabled: bool,
    ) -> None:
        if not self.start():
            return
        if not self.discovery_published:
            self.publish_discovery(ping_enabled)

        state_payload = metrics.copy()
        self._publish_json(STATE_TOPIC, state_payload, retain=True)

        if ping_enabled:
            binary_payload = {
                "internet_online": bool_to_mqtt_state(connectivity.get("internet")),
                "router_online": bool_to_mqtt_state(connectivity.get("router")),
            }
            self._publish_json(BINARY_STATE_TOPIC, binary_payload, retain=True)

        self._publish_raw(AVAILABILITY_TOPIC, "online", retain=True)

    def stop(self) -> None:
        if not self.client:
            return
        try:
            self._publish_raw(AVAILABILITY_TOPIC, "offline", retain=True)
            self.client.disconnect()
            self.client.loop_stop()
        except Exception as exc:  # pragma: no cover - best-effort shutdown path.
            logging.debug("MQTT shutdown failed: %s", exc)

    def _publish_json(self, topic: str, payload: dict[str, Any], retain: bool) -> None:
        self._publish_raw(topic, json.dumps(payload, separators=(",", ":"), sort_keys=True), retain)

    def _publish_raw(self, topic: str, payload: str, retain: bool) -> None:
        if not self.client:
            return
        try:
            self.client.publish(topic, payload, qos=1, retain=retain)
        except Exception as exc:
            logging.debug("MQTT publish failed for %s: %s", topic, exc)


def device_info() -> dict[str, Any]:
    return {
        "identifiers": [DEVICE_ID],
        "name": APP_NAME,
        "manufacturer": "Local Home Assistant Add-on",
        "model": "Downtime monitor",
        "sw_version": APP_VERSION,
    }


def bool_to_mqtt_state(value: bool | None) -> str:
    return "ON" if value is True else "OFF"


def detect_start_event(store: EventStore, options: Options, started_at: datetime) -> None:
    last_heartbeat = store.get_last_heartbeat()
    restart_type = "first_start"
    metadata: dict[str, Any] = {"restart_type": restart_type}

    if last_heartbeat:
        gap_seconds = int(max(0.0, (started_at - last_heartbeat).total_seconds()))
        outage_limit = (
            options.heartbeat_interval_seconds + options.outage_threshold_seconds
        )
        restart_type = "normal_restart"
        metadata = {
            "restart_type": restart_type,
            "last_heartbeat": to_iso(last_heartbeat),
            "gap_seconds": gap_seconds,
        }
        if gap_seconds > outage_limit:
            outage_start = last_heartbeat + timedelta(
                seconds=options.heartbeat_interval_seconds
            )
            duration_seconds = int(max(0.0, (started_at - outage_start).total_seconds()))
            store.insert_event(
                "outage",
                outage_start,
                started_at,
                duration_seconds,
                {
                    "last_heartbeat": to_iso(last_heartbeat),
                    "detected_at": to_iso(started_at),
                    "gap_seconds": gap_seconds,
                },
            )
            restart_type = "outage_restart"
            metadata["restart_type"] = restart_type
            metadata["outage_duration_seconds"] = duration_seconds
            logging.warning(
                "Detected outage: %s seconds since expected heartbeat",
                duration_seconds,
            )
        else:
            logging.info("No outage detected on startup; heartbeat gap was %s seconds", gap_seconds)

    store.insert_event("addon_start", started_at, started_at, 0, metadata)


def run_cycle(
    store: EventStore,
    publisher: MqttPublisher,
    network_monitor: NetworkMonitor,
    options: Options,
    process_start: datetime,
) -> None:
    now = utc_now()
    store.record_heartbeat(now)
    connectivity = network_monitor.check_all(now)
    metrics = store.calculate_metrics(now, process_start)
    publisher.publish_state(metrics, connectivity, options.enable_ping_monitoring)
    logging.info(
        "Heartbeat stored; downtime 7d=%s min, outages 7d=%s",
        metrics["downtime_7d_minutes"],
        metrics["outage_count_7d"],
    )


def main() -> int:
    setup_logging()
    options = load_options()
    logging.info(
        "Starting %s %s with heartbeat interval %ss",
        APP_NAME,
        APP_VERSION,
        options.heartbeat_interval_seconds,
    )

    stop_event = threading.Event()

    def handle_shutdown(signum: int, _frame: Any) -> None:
        logging.info("Received signal %s; shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    store = EventStore(DB_PATH)
    publisher = MqttPublisher(options)
    network_monitor = NetworkMonitor(store, options)
    process_start = utc_now()

    try:
        detect_start_event(store, options, process_start)
        publisher.publish_discovery(options.enable_ping_monitoring)
        run_cycle(store, publisher, network_monitor, options, process_start)

        while not stop_event.wait(options.heartbeat_interval_seconds):
            run_cycle(store, publisher, network_monitor, options, process_start)
    finally:
        shutdown_at = utc_now()
        try:
            store.record_heartbeat(shutdown_at)
            logging.info("Final heartbeat stored")
        finally:
            publisher.stop()
            store.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
