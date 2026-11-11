# Entwicklung und Betrieb

## Lokal testen

Python 3.13 verwenden. Im Verzeichnis `household_tool`:

```sh
python3 -m venv /tmp/household-venv
/tmp/household-venv/bin/pip install -r app/requirements.txt httpx
/tmp/household-venv/bin/python -m unittest discover -s tests -v
HOUSEHOLD_DATA_DIR=/tmp/household-dev /tmp/household-venv/bin/python app/main.py
```

`HOUSEHOLD_DATA_DIR` ist optional, Default `/data`; fuer lokale Tests immer ein
isoliertes Verzeichnis verwenden. Static/Templates werden relativ zu main.py
gefunden. Das Add-on verwendet weiterhin unveraendert `/data` und Port 8099.
Die Berlin-Zeitzonendaten muessen im Betriebssystem vorhanden sein.

## Tests

`test_projects.py`: Schema-Migration auf bestehender DB, wiederholter Start,
mehr als 25 Historieneintraege, Daten-/Anhangerhalt nach Abschluss und
Wiederoeffnen, fremde Zugriffe, Deadline-Filter und Entfernen der Deadline.
`test_project_http.py`: isolierter Prozess mit TestClient; Login, CSRF,
Projektanlage, Aufgabenanlage, ungueltiges Datum, Anhang, Abschluss,
Historien-Rendering, Wiederoeffnen. Keine produktiven Zugangsdaten.
Die bestehenden Musiktests muessen weiterhin bestehen.

Manueller Abnahmetest im Browser: Desktop und Smartphone, lange Titel,
leere Projekte, Suche, alle Filter, mehrere Mitglieder, Datum entfernen,
Historie mit Anhang, Tastaturbedienung der aufklappbaren Bereiche.

## Release / Home Assistant

Dockerfile basiert auf Home-Assistant Python 3.13 / Alpine 3.22; run.sh startet
die App. Architekturen: amd64 und aarch64. Version steht in config.yaml.
Vor Update Backup des Add-ons inklusive `/data` erstellen. Code pushen,
Repository im HA-Store aktualisieren, angebotene Version installieren und starten.
Das Versionsupdate alleine ist kein Deployment und kein Nachweis eines Live-Tests.
Bei Rollback eine passende Datensicherung verwenden; keine destruktiven
Rueckmigrationen automatisch ausfuehren.

## Bestehende Besonderheiten

Ein gesetztes `admin_password` in HA wird derzeit bei jedem Start in die DB
uebernommen. Das kann ein im Konto geaendertes Admin-Passwort ueberschreiben.
Beim Zuruecksetzen zuerst die bestehende Implementierung und HA-Konfiguration
pruefen. Keine echten Passwoerter in Logs, Tests oder Dokumentation uebernehmen.

Benutzerloeschung weist Projekte und Uploads einem anderen Benutzer zu.
Die Folgen fuer Eigentum und Speicherkontingent vor Aenderungen beachten.
SQLite-Connections werden vielerorts ueber `with connection` benutzt; dies
beendet Transaktionen, schliesst aber die Connection nicht explizit. Neuere
Python-Versionen melden deshalb ResourceWarnings. Eine zentrale Korrektur
sollte alle Module samt Nebenwirkungen testen.
