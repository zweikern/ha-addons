# HA Uptime & Outage Monitor

Lokales Home-Assistant-Add-on zur Protokollierung von Home-Assistant-Ausfallzeiten, Add-on-Neustarts und optionaler Router-/Internet-Erreichbarkeit. Die Daten bleiben lokal in `/data/downtime_monitor.sqlite3`; Sensorwerte werden per MQTT Discovery an Home Assistant veröffentlicht.

## Funktionen

- Heartbeat alle `heartbeat_interval_seconds` Sekunden
- Ausfall-Erkennung beim Add-on-Start anhand der letzten Heartbeat-Lücke
- Persistente SQLite-Speicherung unter `/data`
- MQTT Discovery für Home-Assistant-Sensoren
- Optionales Ping-Monitoring für Router und Internet-Host
- Robuster Start bei beschädigter Datenbank: die alte DB wird als `.corrupt-<timestamp>` gesichert
- Graceful shutdown mit finalem Heartbeat

## Installation als lokales Add-on

1. Den Ordner `downtime` in den Home-Assistant-Add-on-Ordner kopieren, typischerweise nach `/addons/downtime`.
2. In Home Assistant `Einstellungen` -> `Add-ons` -> `Add-on Store` öffnen.
3. Rechts oben das Menü öffnen und `Neu laden` wählen.
4. `HA Uptime & Outage Monitor` öffnen, bauen/installieren und starten.
5. `Start beim Booten` aktivieren.

Der Mosquitto Broker muss laufen. Wenn MQTT-Benutzer/Passwort im Broker eingerichtet sind, dieselben Zugangsdaten in der Add-on-Konfiguration hinterlegen.

## Konfiguration

Standardwerte:

```yaml
heartbeat_interval_seconds: 60
outage_threshold_seconds: 120
mqtt_host: core-mosquitto
mqtt_port: 1883
mqtt_username: ""
mqtt_password: ""
router_host: 192.168.178.1
internet_host: 1.1.1.1
enable_ping_monitoring: true
```

Ein Systemausfall wird erkannt, wenn beim Start gilt:

```text
jetzt - letzter_heartbeat > heartbeat_interval_seconds + outage_threshold_seconds
```

Die eigentliche Ausfalldauer wird ab dem erwarteten nächsten Heartbeat berechnet.

## MQTT-Entities

Per MQTT Discovery erscheinen unter anderem diese Entities:

- `sensor.ha_outage_downtime_today`
- `sensor.ha_outage_downtime_7d`
- `sensor.ha_outage_downtime_30d`
- `sensor.ha_outage_count_today`
- `sensor.ha_outage_count_7d`
- `sensor.ha_outage_count_30d`
- `sensor.ha_outage_last_duration`
- `sensor.ha_outage_addon_uptime`
- `binary_sensor.ha_outage_internet_online`
- `binary_sensor.ha_outage_router_online`

Zusätzlich werden `sensor.ha_outage_last_start`, `sensor.ha_outage_last_end`, `sensor.ha_outage_internet_outage_7d` und `sensor.ha_outage_router_outage_7d` veröffentlicht.

Hinweis: Zeitstempel werden in UTC gespeichert. Die Kennzahl `today` wird ebenfalls ab 00:00 UTC berechnet.

## Beispiel-Lovelace-Karte

```yaml
type: entities
title: HA Ausfallmonitor
entities:
  - entity: sensor.ha_outage_downtime_7d
    name: Ausfallzeit 7 Tage
  - entity: sensor.ha_outage_count_7d
    name: Ausfälle 7 Tage
  - entity: sensor.ha_outage_last_duration
    name: Letzter Ausfall
  - entity: sensor.ha_outage_addon_uptime
    name: Add-on Uptime
  - entity: binary_sensor.ha_outage_internet_online
    name: Internet
  - entity: binary_sensor.ha_outage_router_online
    name: Router
```

## Testanleitung

Schneller Funktionstest:

1. Add-on starten und Log prüfen. Es sollte `Heartbeat stored` erscheinen.
2. Prüfen, ob die MQTT-Entities in Home Assistant angelegt werden.
3. Für einen schnellen Ausfalltest temporär setzen:

```yaml
heartbeat_interval_seconds: 10
outage_threshold_seconds: 10
```

4. Add-on starten, mindestens einen Heartbeat abwarten, Add-on stoppen.
5. Mehr als 20 Sekunden warten.
6. Add-on wieder starten.
7. Im Log sollte `Detected outage` erscheinen; `sensor.ha_outage_count_today` und `sensor.ha_outage_last_duration` sollten steigen.

Router-/Internet-Test:

1. `enable_ping_monitoring: true` aktivieren.
2. Einen bewusst unerreichbaren `internet_host` setzen, zum Beispiel eine freie lokale Test-IP.
3. Nach dem nächsten Heartbeat sollte `binary_sensor.ha_outage_internet_online` auf `off` wechseln.
4. Danach wieder einen erreichbaren Host setzen und Add-on neu starten.

## Datenbank

SQLite-Datei:

```text
/data/downtime_monitor.sqlite3
```

Tabelle `events`:

- `type`: `heartbeat`, `addon_start`, `outage`, `internet_down`, `internet_up`, `router_down`, `router_up`
- `start_ts`: UTC-Startzeit
- `end_ts`: UTC-Endzeit, falls abgeschlossen
- `duration_seconds`: Dauer, falls berechnet
- `metadata_json`: zusätzliche lokale Metadaten ohne sensible Zugangsdaten

## Grenzen

Das Add-on misst Add-on-/Host-Lücken anhand eigener Heartbeats. Wenn nur Home Assistant Core neu startet, der Add-on-Container aber weiterläuft, entsteht kein Systemausfall-Event. Internet- und Router-Ausfälle werden separat behandelt und zählen nicht als Home-Assistant-Ausfallzeit.
