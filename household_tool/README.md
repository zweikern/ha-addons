# Household Tool (Home Assistant Add-on)

MVP-Add-on für ein kleines internes Haushalts-Intranet auf Home Assistant OS.

## Funktionen (MVP)
- Login/Logout mit Session-Cookies
- Benutzerverwaltung (admin/user, Passwort-Hashing mit bcrypt)
- Projekte anlegen und auflisten
- Aufgaben pro Projekt (offen, in Arbeit, erledigt)
- SQLite persistent unter `/data/app.db`
- Initialer Admin beim ersten Start

## Home Assistant OS Installation (exakt)

### Variante A: Lokales Add-on (ohne Git, direkt auf HA)
1. Auf dem Home-Assistant-Host den Ordner erstellen:
```bash
mkdir -p /addons/local/household_tool
```
2. Den kompletten Inhalt dieses Ordners nach `/addons/local/household_tool` kopieren:
- `config.yaml`
- `Dockerfile`
- `run.sh`
- gesamter Ordner `app/`

3. In Home Assistant öffnen:
- `Einstellungen` -> `Add-ons` -> `Add-on Store`

4. Add-on Store aktualisieren (oben rechts Menu):
- `Neu laden`

5. Unter `Lokale Add-ons` das Add-on **Household Tool** öffnen.

6. `Installieren` klicken.

7. Reiter `Konfiguration` öffnen und Optionen setzen (Beispiel unten), dann `Speichern`.

8. Reiter `Info`:
- `Start beim Booten` aktivieren (optional, empfohlen)
- `Watchdog` aktivieren (optional)
- `Starten` klicken

9. Reiter `Protokoll` prüfen. Erwartete Meldung:
- `[info] Database ready at /data/app.db`

10. Web UI öffnen:
- über Button `Web UI öffnen` im Add-on
- oder `http://<HA-IP>:8099`

### Variante B: Als Add-on-Repository per Git
1. Dieses Projekt in ein Git-Repository pushen (inkl. `repository.yaml` auf Repo-Root-Ebene).

2. In Home Assistant öffnen:
- `Einstellungen` -> `Add-ons` -> `Add-on Store`

3. Oben rechts Menu -> `Repositories`.

4. Repository-URL einfügen und `Hinzufügen`.

5. Danach das Add-on **Household Tool** im Store auswählen, installieren, konfigurieren und starten (wie in Variante A ab Schritt 7).

## Add-on Optionen
Setze die Optionen in Home Assistant im Reiter `Konfiguration`.

Beispiel:
```yaml
admin_username: admin
admin_password: "Bitte-ein-langes-sicheres-Passwort"
```

Wenn `admin_password` leer bleibt, wird beim ersten Start ein temporäres Passwort generiert und im Add-on-Log ausgegeben.

## Optional: `options.json` Beispiel
Für lokalen Docker-Test (oder zur Veranschaulichung der Supervisor-Optionen):

```json
{
  "admin_username": "admin",
  "admin_password": "Bitte-ein-langes-sicheres-Passwort"
}
```

Hinweis: In Home Assistant wird `/data/options.json` vom Supervisor automatisch aus der Add-on-Konfiguration erzeugt.

## Lokaler Docker-Test (optional)
```bash
cd household_tool
docker build -t household-tool-addon .
mkdir -p local-data
cat > local-data/options.json <<'JSON'
{"admin_username":"admin","admin_password":"Bitte-ein-langes-sicheres-Passwort"}
JSON
docker run --rm -p 8099:8099 -v "$(pwd)/local-data:/data" household-tool-addon
```
Dann aufrufen: `http://localhost:8099`
