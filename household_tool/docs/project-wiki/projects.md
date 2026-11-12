# Projekte-App

## Bedienung ab 0.6.0

Links stehen eigene und geteilte Projekte mit ihrer Hierarchie und Zahl aktiver
Aufgaben. Das ausgewaehlte Projekt zeigt Beschreibung, Verantwortlichen,
Fortschritt sowie Links fuer Fokus, heute, morgen und ueberfaellige Deadlines.
Die Zaehler gelten fuer dieses Projekt, nicht projektuebergreifend.

Aktive Aufgaben umfassen `open` und `in_progress`. Erledigte Aufgaben (`done`)
erscheinen ausschliesslich unter Historie. Dort sind alle Aufgaben verfuegbar,
nicht nur die bisherigen 25 Eintraege. Details und Bearbeitung lassen sich
oeffnen, Anhaenge weiterhin herunterladen/ergaenzen und der Status aendern.
Wiederoeffnen setzt den Status auf `open` und entfernt die Aufgabe aus der Historie.
Titel, Beschreibung, Fokus, Zustaendigkeit, Deadline und Anhaenge bleiben erhalten.
`completed_at` beschreibt den aktuellen Abschluss und wird beim Wiederoeffnen
geleert. Eine lueckenlose Ereignischronik aller Statuswechsel gibt es noch nicht.

Neue Aufgaben, Projekteinstellungen und Teamverwaltung sind getrennt und
aufklappbar. Die lokale Suche durchsucht Titel, Beschreibung und Zustaendigen
innerhalb des aktuellen Filters. Aufgaben werden als kompakte Karten dargestellt.
Die Formularaktionen funktionieren auch ohne JavaScript; nur die Suche benoetigt JS.

## Deadlines

Optionales Datum, ohne Uhrzeit: `tasks.deadline`, ISO `YYYY-MM-DD` oder NULL.
Datumsvalidierung findet serverseitig statt; ungueltige Daten werden abgewiesen.
Leeres Datum entfernt die Deadline. Bestehende Aufgaben erhalten NULL.
Heute/Morgen basieren auf `Europe/Berlin` inklusive Sommerzeit; die Container-
Zeitzone ist dafuer irrelevant. Zaehler werden beim Seitenaufruf berechnet.
Erledigte Aufgaben werden bei den Deadline-Zaehlern nicht mitgezaehlt.
Sortierung: Historie nach Abschluss absteigend; aktive Aufgaben nach Deadline
(ohne Datum zuletzt), dann Fokus und Erstellungszeit.

## Datenmodell

- `projects`: id, name, description, parent_id, created_by, created_at.
- `tasks`: id, project_id, title, description, status, focus, priority,
  recurrence, milestone_id, assignee_id, deadline, created_at, completed_at.
- `project_members`: project_id, user_id, role (`member`/`manager`), unique Paar.
- `task_attachments`: task_id, filename, mime, size, content (BLOB), created_at.
- `task_comments`: task_id, author_id (nullable), author_name, content, created_at.
- `task_events`: task_id, actor_id (nullable), actor_name, event_type, old/new, created_at.
- `task_checklist_items`: task_id, content, done, position.
- `task_recurrence_links`: source_task_id, followup_task_id (unique Quelle).
- `task_templates` / `task_template_items`: Vorlagen pro Nutzer inkl. Checkliste.
- `milestones`: project_id, name, due_date.
- `task_dependencies`: task_id, depends_on_task_id (same project, azyklisch).
- `reminder_deliveries`: Deduplizierung/Retries fuer HA-Erinnerungen.
- `users`: zentrale Identitaeten, Rollen, Passwort-Hash, E-Mail, Mail- und
  Reminder-Opt-in inkl. `reminder_target` (Empfaenger fuer HA-Erinnerungen).

Migrationen liegen in `app/db.py:init_db()`, werden beim Start ausgefuehrt
und pruefen Spalten vor ALTER TABLE. Version 0.6.0 ergaenzt nur die nullable
Deadline-Spalte. Aufgabenabschluss loescht keine Datensaetze.
Anhaenge sind auf 2 MiB begrenzt. Sie sind anders als File-Sharing-Dateien
direkt in der Datenbank gespeichert und muessen mit ihr gesichert werden.

## Rechte

Projektzugriff: Eigentuemer oder explizite Mitgliedschaft. Hierarchie bedeutet
keine automatische Vererbung der Mitgliedschaft. Projektverwalter duerfen
Metadaten und Mitgliedschaften bearbeiten; Mitglieder duerfen Aufgaben bearbeiten.
Die Admin-Pruefung in `can_manage_project` hebt die vorgeschaltete
Projektzugriffspruefung nicht auf. Aufgaben-/Anhangzugriff erfolgt ueber das Projekt.
Zustaendige Personen muessen Projektmitglieder oder Eigentuemer sein.
Zyklen werden beim Bearbeiten der Projekthierarchie abgefangen.

## Code und Schnittstellen

`app/main.py`: FastAPI-Routen, Sessions, CSRF, Formvalidierung, Template-Kontext.
`app/db.py`: Schema, SQL, Zugriffspruefungen und Lebenszyklus.
`app/templates/projects_app.html`: aktive Projektoberflaeche.
`app/static/projects.js`: lokale Suche. `style.css`: `.pm-workspace`-Styles.
Alte Templates `projects.html`/`project_detail.html` sind nicht die Hauptansicht.

GET `/projects?project_id=ID&view=...`:
`all`, `open`, `in_progress`, `focus`, `today`, `tomorrow`, `overdue`, `history`.
Legacy `done` wird auf `history` normalisiert.
GET `/projects/{id}` leitet auf die aktuelle Ansicht um.
POST `/projects`, `/projects/{id}/edit`: Projektanlage und -bearbeitung.
POST `/projects/{id}/tasks`: Aufgabe mit optionaler Deadline anlegen.
POST `/tasks/{id}/edit`: vollstaendige Aufgabenbearbeitung inklusive Deadline.
POST `/tasks/{id}/status`: Statuswechsel ohne andere Felder zu veraendern.
POST `/tasks/{id}/attachments`, GET `/attachments/{id}/download`: Anhaenge.
POST `/projects/{id}/share` und `/share/{user_id}/remove`: Mitgliedschaften.

Alle Schreibformulare enthalten `csrf`. Nach Schreiben folgt Redirect (303).
`list_project_tasks()` filtert aktive/abgeschlossene Aufgaben;
`list_project_history()` liefert dieselben vollstaendigen Aufgabenfelder.
`normalize_deadline()` validiert Daten; `project_today()` ist die testbare Uhr.

Erweiterungen in 0.7.0:

- `GET /my-tasks`: projektuebergreifende Sicht auf eigene Aufgaben.
- `GET /templates`, `POST /templates`, `POST /templates/{id}/use`: Vorlagen.
- `POST /tasks/{id}/comments`, `/checklist`, `/dependencies`; `POST /checklist/{id}/toggle`.
- `POST /projects/{id}/milestones`.
- `GET /tasks/{id}`: stabile, rechtegepruefte Detailansicht einer Aufgabe.
- `GET /projects` mit `view=kanban|calendar`, `month`, `page` und serverseitiger
  Suche `q` (filtert vor der Pagination, bleibt in der Seitennavigation erhalten).
- `app/reminders.py`: standardmaessig deaktivierter HA-Erinnerungsadapter mit
  adminseitiger Dienstzuordnung pro Nutzer, DB-Leases und begrenztem Best-effort-Versand. Siehe [Release-Abnahme](release-0.7.0.md).
