# Codex-Review der DeepSeek-Ergebnisse

Datum: 2026-11-12
Ergebnis: Nicht zur Veroeffentlichung freigegeben. Kein Commit/Push/Deployment.
Basis: lokale DeepSeek-Aenderungen gegen Release 0.6.0 / Commit 9654bb1.
Der Anwendungscode wurde bei diesem Review nicht veraendert.

## Verifikation

- Isolierte Arbeitskopie in `/private/tmp/household-review-20261112`.
- 36 vorhandene Tests bestanden mit Python 3.13 und
  `python -W error::ResourceWarning -m unittest discover -s tests -q`.
- Der erste Lauf scheiterte ausschliesslich am Sandbox-Verbot fuer den lokalen
  HTTP-Testserver. Mit freigegebenem lokalen Testserver bestanden alle Tests.
- Zusaetzliche DB-, Thread- und FastAPI-TestClient-Gegenproben mit neuen
  temporaeren Datenbanken bestaetigen die unten genannten Fehler.
- Keine produktiven Datenbanken, Tokens oder Benachrichtigungsziele verwendet.
- Keine Browser-/Smartphone-Sichtpruefung, Docker-Builds oder Tests am echten HA.
- Bestandene Tests sind keine vollstaendige Feature-/Migrationsfreigabe.

## Befunde nach Prioritaet

### P1: Benutzer mit persoenlichen Vorlagen nicht loeschbar

`app/db.py:562`, Schema `task_templates.created_by`.
Die Benutzerloeschung behandelt die neue Fremdschluesselreferenz nicht.
Reproduktion: zwei Benutzer anlegen, fuer den zweiten eine Aufgabenvorlage
anlegen, `delete_user_with_reassignment(2, 1)` aufrufen.
Ergebnis: `IntegrityError: FOREIGN KEY constraint failed` statt `ok`.
Dies betrifft sowohl die administrative Loeschung als auch die Selbstloeschung.

Korrektur: Lebenszyklus persoenlicher Vorlagen bei Benutzerloeschung festlegen
und transaktional umsetzen. Keine privaten Vorlagen stillschweigend an andere
Nutzer weitergeben. HTTP-Tests fuer beide Loeschwege und Rollback ergaenzen.

### P1: Erinnerungen haben keine benutzerspezifische Zustellung

`app/reminders.py:204`.
Alle Aufgaben gehen ueber einen globalen Service; der vorhandene Parameter
`target` wird nie befuellt. Der Opt-in-Benutzer bestimmt nicht den Empfaenger.
Nach Aktivierung eines funktionsfaehigen gemeinsamen Notify-Service koennten
private Aufgabentitel bei anderen Haushaltsmitgliedern landen. Standardmaessig
ist der Adapter deaktiviert; es gab keinen realen Versand im Review.

Korrektur: explizite, validierte Empfaengerzuordnung pro Benutzer; ohne passende
Zuordnung kein Versand. Zwei Nutzer mit privaten Projekten getrennt testen.

### P1: Erinnerungsschleife blockiert den Webserver

`app/main.py:505`, insbesondere Zeile 509.
Die async-Schleife ruft synchronen HTTP-Versand direkt im Event-Loop auf.
Bei vielen faelligen Aufgaben und Timeouts kann die gesamte Weboberflaeche
fuer die Summe der HTTP-Wartezeiten blockieren. Dies ist eine Codeanalyse,
kein gemessener Lasttest. Die Schleife wird zudem nicht explizit beendet.

Korrektur: begrenzte asynchrone Verarbeitung oder Thread-Auslagerung mit
kontrolliertem Task-Lebenszyklus und Shutdown. Parallel einen HTTP-Request
waehrend langsamer simulierter Zustellungen testen.

### P2: HA-REST-Endpunkt ist falsch

`app/reminders.py:125`.
Die Standardkonfiguration ergibt `/api/services/notify.notify` statt
`/api/services/notify/notify`. Der bestehende HTTP-Test akzeptiert jeden Pfad
und erkennt den Fehler daher nicht.
Verifiziert mit abgefangenem urllib-Request, ohne Netzwerkversand.

Referenz: https://contributors.home-assistant.io/core/internals/rest-api/
Die HA-REST-API erwartet `POST /api/services/<domain>/<service>`.

Korrektur: Service validieren und Domain/Service korrekt zusammensetzen;
exakten Pfad im Test verlangen. Die benoetigten Reminder-Optionen fehlen zudem
in `config.yaml`; Integration weiterhin als deaktivierten Entwurf behandeln.

### P2: Persistente Deduplizierung ist nicht nebenlaeufigkeitssicher

`app/reminders.py:188` und `app/reminders.py:204`.
Zustellung wird erst nach dem Versand gespeichert. Zwei Laeufe koennen beide
vorher keinen Datensatz finden und dieselbe Nachricht senden.
Reproduktion: zwei Threads, identische Aufgabe/Datum, Barrier im FakeNotifier.
Ergebnis: beide Laeufe melden `sent=1`, der Notifier erhaelt zwei Aufrufe.
Ein Absturz zwischen Versand und Speichern bietet ein weiteres Duplikatfenster.

Korrektur: atomare persistente Claim-/Attempt-Logik vor Netzwerkzugriff;
unklare Zustellung und Retry-Politik explizit dokumentieren. Keine Exactly-once-
Garantie behaupten, die der externe Empfaenger nicht unterstuetzt. Zusaetzlich
das Datum bei der erneuten Kandidatenpruefung vergleichen: aktuell wird eine
zwischenzeitlich verschobene Deadline nicht erneut auf Faelligkeit geprueft.

### P2: Aufgabenlinks und Suche passen nicht zur Pagination

`app/templates/my_tasks.html:35`, `app/templates/projects_app.html:262`,
`app/main.py:720`, `app/static/projects.js:7`.
Die Aufgabenlinks oeffnen immer die erste aktive Projektseite. Erledigte
Aufgaben aus Meine-Aufgaben/Historie sind dort grundsaetzlich nicht vorhanden;
Kalenderaufgaben auf Seite 2 ebenfalls nicht. TestClient bestaetigte in beiden
Faellen einen Link ohne vorhandenes Ziel im resultierenden HTML.
Die Suchfunktion durchsucht nur die maximal 50 gerenderten Zeilen und kann
Aufgaben auf anderen Seiten nicht finden.

Korrektur: stabile, rechtegepruefte Detailroute oder serverseitige Aufloesung
von Aufgabe, Statusansicht und Seite. Suche vor Pagination ausfuehren und
Suchparameter in Seitennavigation erhalten. Mit >50 Aufgaben und erledigten
Aufgaben pruefen; aus allen Ansichten muss Bearbeiten/Wiederoeffnen erreichbar sein.

### P2: Wiederholungen uebernehmen ungueltige Zuweisungen

`app/db.py:1125`.
Beim Erzeugen einer Folgeaufgabe wird die Zuweisung unveraendert kopiert,
auch nach Entzug der Projektmitgliedschaft. Zugriffsrechte werden dadurch nicht
erteilt, aber die neue Aufgabe bleibt einer Person zugewiesen, die sie nicht
bearbeiten kann. Der Meilenstein geht ohne erkennbare Produktregel verloren.
Reproduktion: wiederkehrende Aufgabe mit Mitglied und Meilenstein anlegen,
Mitgliedschaft entfernen, Aufgabe abschliessen.
Ergebnis: Folgeaufgabe `assignee_id=2`, `milestone_id=None`.

Korrektur: Zuweisung erneut validieren und gegebenenfalls leeren;
Uebernahme des Meilensteins und der Abhaengigkeiten explizit festlegen/testen.

### P2: Kalender-Randwerte erzeugen HTTP 500

`app/main.py:737` und `app/main.py:741`.
Akzeptierte Monate am Rand des date-Wertebereichs verursachen Ueberlauf beim
Berechnen des Nachbar-Monats. Reproduktion per TestClient:
`GET /projects?project_id=<berechtigt>&month=9999-12` ergibt HTTP 500,
auch ohne explizite Kalenderansicht.

Korrektur: unterstuetzten Datumsbereich validieren und Nachbarn sicher bilden.

## Weitere offene Abnahmebereiche

- Pagination begrenzt nur die Aufgabenliste; Kommentare, Events, Checklisten
  und Anhangmetadaten werden weiter fuer das ganze Projekt geladen
  (`app/main.py:756`). Abhaengigkeitsoptionen laden alle aktiven Aufgaben.
- Vorlagen- und Wiederholungsanlage erzeugen keinen task_created-Event;
  der neue Aktivitaetsverlauf ist an diesen Einstiegspunkten unvollstaendig.
- Meilensteine/Abhaengigkeiten lassen sich anlegen, aber der vollstaendige
  Bearbeiten-/Entfernen-Lebenszyklus muss noch abgenommen werden.
- Migration einer echten 0.6.0-Datenbank, mobile Layouts, Tastaturbedienung,
  File-Sharing-/Musik-Regressionspruefung und Containerstart stehen noch aus.

## Naechster Freigabeschritt

1. P1/P2-Befunde korrigieren und gezielte Regressionstests hinzufuegen.
2. Erneutes Review, Migrationstest, Oberflaechen- und Containerpruefung.
3. Erst danach Wiki/Changelog/Release-Version aktualisieren und ausschliesslich
   Household-Dateien gezielt committen/pushen. `downtime/` unberuehrt lassen.

Der DeepSeek-Ergebnisbericht bleibt als urspruengliche Uebergabe erhalten;
dieses Review ergaenzt und relativiert seine Fertigstellungs-/Dedup-Aussagen.
