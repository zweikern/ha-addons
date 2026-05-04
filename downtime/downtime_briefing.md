Projekt: Home Assistant Add-on “HA Uptime & Outage Monitor”

Ziel:
Erstelle ein schlankes Home-Assistant-Add-on zur lokalen Erfassung und Auswertung von System-Ausfallzeiten. Das Add-on soll ohne InfluxDB/Grafana auskommen und einfache Sensorwerte an Home Assistant liefern.

Kontext:
Home Assistant läuft auf einem Raspberry Pi mit Home Assistant OS. Ziel ist zu prüfen, ob eine USV notwendig ist. Dafür sollen Systemausfälle, Neustarts und optional Internet-Ausfälle über mehrere Wochen protokolliert und ausgewertet werden.

Wichtige Vorgaben:
- Schlank, wartungsarm, lokal.
- Keine Cloud.
- Persistente Speicherung in /data.
- Konfiguration über /data/options.json.
- Add-on-Struktur gemäß Home-Assistant-Add-on-System.
- Home Assistant Add-ons nutzen config.yaml; /data dient als persistenter Speicher. Siehe offizielle Home Assistant Developer Docs. 
- Möglichst wenig externe Dependencies.

Referenz:
Home Assistant Add-ons werden über config.yaml beschrieben und laufen als Container. Persistente Add-on-Daten gehören nach /data; User-Konfiguration liegt in /data/options.json. Siehe Home Assistant Developer Docs:
https://developers.home-assistant.io/docs/apps/
https://developers.home-assistant.io/docs/apps/configuration/
https://developers.home-assistant.io/docs/apps/tutorial/

Funktionale Anforderungen:

1. Heartbeat Logging
- Das Add-on schreibt alle N Sekunden einen Heartbeat-Zeitstempel in eine lokale JSON- oder SQLite-Datei.
- Default Intervall: 60 Sekunden.
- Konfigurierbar: heartbeat_interval_seconds.

2. Ausfall-Erkennung
- Beim Start des Add-ons wird der letzte gespeicherte Heartbeat gelesen.
- Wenn die Differenz zwischen aktuellem Zeitpunkt und letztem Heartbeat größer ist als:
  heartbeat_interval_seconds + outage_threshold_seconds
  dann soll daraus ein Ausfallereignis berechnet werden.
- Default outage_threshold_seconds: 120 Sekunden.
- Beispiel:
  letzter Heartbeat: 10:00:00
  Start: 10:07:00
  Intervall: 60s
  Threshold: 120s
  erkannter Ausfall: ca. 6 Minuten

3. Neustart-Erkennung
- Jeder Add-on-Start soll als Start-/Restart-Event gespeichert werden.
- Optional unterscheiden:
  - normal restart
  - outage restart, falls vorher eine Lücke erkannt wurde.

4. Internet-/Router-Monitoring optional
- Konfigurierbare Liste von Hosts:
  - Router IP, z.B. 192.168.178.1
  - Internet Host, z.B. 1.1.1.1 oder 8.8.8.8
- Periodischer Ping.
- Ausfälle separat speichern:
  - router_unreachable
  - internet_unreachable
- Wichtig: Ein Internet-Ausfall ist nicht gleich HA-Ausfall.

5. Auswertungen
Das Add-on soll mindestens folgende Kennzahlen berechnen:
- downtime_today_minutes
- downtime_7d_minutes
- downtime_30d_minutes
- outage_count_today
- outage_count_7d
- outage_count_30d
- last_outage_start
- last_outage_end
- last_outage_duration_minutes
- addon_uptime_seconds
- internet_outage_7d_minutes, falls Ping aktiviert
- router_outage_7d_minutes, falls Ping aktiviert

6. Home Assistant Integration
Bevorzugte Variante:
- Werte per MQTT Discovery an Home Assistant veröffentlichen.
- Mosquitto Broker ist bereits installiert.
- Add-on soll MQTT Host/User/Passwort über options.json akzeptieren.
- MQTT Discovery Topics nach Home-Assistant-Konvention veröffentlichen.
- Sensoren sollen in Home Assistant automatisch erscheinen.

MQTT Sensoren:
- sensor.ha_outage_downtime_today
- sensor.ha_outage_downtime_7d
- sensor.ha_outage_downtime_30d
- sensor.ha_outage_count_today
- sensor.ha_outage_count_7d
- sensor.ha_outage_count_30d
- sensor.ha_outage_last_duration
- sensor.ha_outage_addon_uptime
- binary_sensor.ha_outage_internet_online
- binary_sensor.ha_outage_router_online

7. Datenformat
Nutze SQLite bevorzugt.
Tabellen:
events:
- id
- type: heartbeat | addon_start | outage | internet_down | internet_up | router_down | router_up
- start_ts
- end_ts
- duration_seconds
- metadata_json

Alternativ JSON Lines, falls einfacher.

8. Add-on Struktur
Erstelle folgende Dateien:
- config.yaml
- Dockerfile
- run.sh
- app/main.py
- README.md

config.yaml:
- name: "HA Uptime & Outage Monitor"
- slug: "ha_uptime_outage_monitor"
- version: "0.1.0"
- arch: ["aarch64", "amd64", "armv7"]
- startup: "services"
- boot: "auto"
- options:
    heartbeat_interval_seconds: 60
    outage_threshold_seconds: 120
    mqtt_host: "core-mosquitto"
    mqtt_port: 1883
    mqtt_username: ""
    mqtt_password: ""
    router_host: "192.168.178.1"
    internet_host: "1.1.1.1"
    enable_ping_monitoring: true
- schema passend definieren.

9. Robustheit
- Zeitstempel immer in UTC speichern.
- Bei beschädigter DB nicht abstürzen; Backup anlegen und neue DB starten.
- Graceful shutdown: letzten Heartbeat schreiben.
- Logs klar und knapp.
- Keine sensiblen Daten loggen.

10. Dashboard-Vorschlag in README
README soll erklären:
- Installation als lokales Add-on
- MQTT-Konfiguration
- welche Sensoren erscheinen
- Beispiel Lovelace-Karte für:
  - Ausfallzeit 7 Tage
  - Anzahl Ausfälle 7 Tage
  - letzter Ausfall
  - Internet online/offline
  - Router online/offline

11. Akzeptanzkriterien
- Add-on startet auf Home Assistant OS.
- Sensoren erscheinen automatisch über MQTT Discovery.
- Heartbeats werden persistent gespeichert.
- Nach simuliertem Neustart mit Zeitlücke wird ein Outage-Event erzeugt.
- Kennzahlen werden alle 60 Sekunden aktualisiert.
- Keine externen Cloud-Abhängigkeiten.
- README enthält Installations- und Testanleitung.

Hinweis:
Dies ist kein sicherheitskritisches Alarm-Modul, sondern ein Monitoring-Tool zur Entscheidungsfindung “USV notwendig ja/nein”.