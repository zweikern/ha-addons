# Ergebnisse DeepSeek: Household Projekte-Erweiterungen

Datum: 2026-11-11
Ausgangscommit: `9654bb1` auf `main` (Release 0.6.0).
Arbeitsverzeichnis: `/Users/tom/Documents/HA Add-ons/household_tool`.

Alle sieben Etappen wurden implementiert und lokal getestet. Es wurde **nicht**
committet, gepusht oder deployed. `config.yaml` steht unveraendert auf 0.6.0.

## Implementierte Etappen

1. **Kommentare und Aktivitaetsverlauf** — umgesetzt.
2. **Meine Aufgaben und Prioritaeten** — umgesetzt.
3. **Kanban und Kalender** — umgesetzt.
4. **Erinnerungen ueber Home Assistant** — deaktivierter, testbarer Adapter umgesetzt.
5. **Wiederholungen, Checklisten und Vorlagen** — umgesetzt.
6. **Meilensteine und Abhaengigkeiten** — umgesetzt.
7. **Skalierung und Abschluss** — Pagination, SQL-Aggregate, Indizes, Connection-Handling umgesetzt.

## Geaenderte und neue Dateien

Geaendert:

- `app/db.py` — Schema, Migrationen, neue Abfrage- und Schreibfunktionen, Connection-Wrapper.
- `app/main.py` — neue Routen, Pagination, Aggregat-Zaehler, Reminder-Scheduler, Formularfelder.
- `app/templates/projects_app.html` — Kommentare, Aktivitaet, Checkliste, Prioritaet, Wiederholung, Meilenstein, Abhaengigkeit, Kanban, Kalender, Pagination.
- `app/templates/base.html` — Nav-Links "Meine Aufgaben" und "Vorlagen".
- `app/templates/account.html`, `app/templates/users.html` — Opt-in fuer HA-Erinnerungen.
- `app/static/style.css` — Styles fuer neue Oberflaechen.
- `tests/test_projects.py` — Migrations-Test um Index-Drop ergaenzt (nur Testdatei).

Neu:

- `app/reminders.py` — Reminder-Adapter und Scheduler.
- `app/templates/my_tasks.html`, `app/templates/templates.html`.
- `tests/test_project_comments.py`, `tests/test_project_http_comments.py`,
  `tests/test_project_kanban_calendar.py`, `tests/test_project_milestones.py`,
  `tests/test_project_my_tasks.py`, `tests/test_project_recurrence.py`,
  `tests/test_project_scaling.py`, `tests/test_reminders.py`.

## Neue Routen

- `GET /my-tasks` (Filter `view`).
- `GET /templates`, `POST /templates`, `POST /templates/{id}/use`.
- `POST /tasks/{id}/comments`, `POST /tasks/{id}/checklist`, `POST /checklist/{item_id}/toggle`.
- `POST /projects/{id}/milestones`, `POST /tasks/{id}/dependencies`.
- `GET /projects` erweitert um `month` (Kalender) und `page` (Pagination).

## Schema-Migrationen (mehrfach ausfuehrbar, ab 0.6.0-DB)

Neue Spalten ueber `_has_column`:

- `tasks.priority` (`low|normal|high`, Default `normal`)
- `tasks.recurrence` (`daily|weekly|monthly` oder NULL)
- `tasks.milestone_id` (nullable)
- `users.reminder_opt_in` (Default 0)

Neue Tabellen ueber `CREATE TABLE IF NOT EXISTS`:

- `task_comments`, `task_events` (Aktivitaet), `task_checklist_items`,
  `task_recurrence_links`, `task_templates`, `task_template_items`,
  `milestones`, `task_dependencies`, `reminder_deliveries`.

Neue Indizes (gezielt, keine pauschale Sammlung):

- `idx_task_comments_task`, `idx_task_events_task`, `idx_task_checklist_items_task`,
  `idx_milestones_project`, `idx_reminder_deliveries_date`,
  `idx_tasks_project_status`, `idx_tasks_assignee`, `idx_tasks_project_deadline`
  (letzterer nach der Deadline-Migration angelegt, da die Spalte in Alt-DBs
  erst per ALTER entsteht).

## Abhaengigkeiten

Keine neuen Laufzeit-Abhaengigkeiten. Der HA-Adapter nutzt `urllib.request`
(Standardbibliothek). Testseitig wird weiterhin `httpx` verwendet.

## Produktentscheidungen

- **Aktivitaetsverlauf**: Ein Ereignis pro Feldwechsel; `task_created`,
  `status_changed`, `task_reopened` (Uebergang von `done` weg), `title_changed`,
  `description_changed`, `deadline_changed`, `focus_changed`, `priority_changed`,
  `recurrence_changed`, `milestone_changed`, `assignee_changed`,
  `attachment_added`. Keine Rueckbefuellung alter Aufgaben.
- **Geloeschte Benutzer**: `actor_id`/`author_id` per `ON DELETE SET NULL`,
  zusaetzlich Namens-Snapshot (`actor_name`/`author_name`) ohne Passwoerter oder
  private Profildaten. Anzeige als "Name (ehemalig)".
- **Prioritaet**: optional, `normal` ist Default; Backend validiert. Sortierung
  hoch > normal > niedrig in "Meine Aufgaben".
- **Kanban**: Spalten Offen/In Arbeit, erledigte Aufgaben nur in der Historie.
  Statuswechsel per Schaltflaechen; kein zweites Statusmodell. Drag-and-drop
  bewusst als spaetere Ergaenzung ausgelassen.
- **Kalender**: Monatsansicht mit Wochenstart Montag; Aufgaben ohne Datum bleiben
  in der Liste auffindbar. Monats-/Jahresgrenzen korrekt.
- **Erinnerungen**: standardmaessig deaktiviert. Global konfigurierbar ueber
  options.json (`ha_reminders_enabled`, `ha_base_url`, `ha_token`,
  `ha_notify_service`, `reminder_time`, `reminder_quiet_start`,
  `reminder_quiet_end`, `reminder_max_retries`, `reminder_timeout`). Per-Nutzer
  Opt-in `reminder_opt_in` (getrennt vom Mail-Opt-in). Keine hartkodierten
  Tokens/IPs; ohne Konfiguration No-Op. Zustellunsicherheit bei Netzwerkfehlern
  dokumentiert (begrenzte Wiederholungen, dedupliziert, neustartfest).
- **Wiederholungen**: taeglich/woechentlich/monatlich; Monatsende = letzter
  gueltiger Tag des Folgemonats (31. Jan -> 28./29. Feb). Abschluss erzeugt
  genau eine Folgeaufgabe (`task_recurrence_links`, UNIQUE auf Quelle).
  Kopiert werden: Titel, Beschreibung, Fokus, Prioritaet, Wiederholung,
  Zustaendigkeit, Checkliste, Anhaenge. **Nicht** kopiert: Kommentare und
  Aktivitaetsverlauf. Wiederoeffnen/erneuter Abschluss erzeugt kein Duplikat.
- **Meilensteine/Abhaengigkeiten**: Abhaengigkeiten nur innerhalb desselben
  Projekts; Selbstkanten und Zyklen serverseitig abgewiesen. Blockierung ist ein
  Hinweis (kein hartes Sperren des Abschlusses). Zeit-/Aufwandserfassung bleibt
  eine spaetere optionale Erweiterung.
- **Rechte**: Jede neue Lese-/Schreibroute prueft serverseitig, Schreibaktionen
  benoetigen CSRF. "Meine Aufgaben" wendet Rechte vor Aggregation an; nach
  Freigabeentzug verschwinden Aufgaben und Zaehler sofort.
- **Skalierung**: Pagination (`per_page=50`) fuer Listen/Historie; Zaehler ueber
  SQL-Aggregate (`count_project_tasks`, `count_my_tasks`) statt kompletter Listen.
  Stabile Sortierung mit `t.id DESC` als Tie-Breaker.
- **DB-Verbindungen**: `get_connection()` liefert einen Wrapper, der
  Commit/Rollback beibehaelt und die Connection nach dem `with`-Block schliesst.
  Die zuvor beobachteten SQLite-`ResourceWarning`s sind damit beseitigt.

## Ausgefuehrte Tests und echte Ergebnisse

Befehle:

```sh
python3 -m venv /tmp/household-deepseek-venv
/tmp/household-deepseek-venv/bin/pip install -r app/requirements.txt httpx
/tmp/household-deepseek-venv/bin/python -m unittest discover -s tests -v
/tmp/household-deepseek-venv/bin/python -W error::ResourceWarning -m unittest discover -s tests
```

Ergebnis: **36 Tests bestanden**, auch mit `-W error::ResourceWarning` ohne
Fehler oder Warnungen. Testumfang: Migration von 0.6.0 inkl. Anhaenge,
wiederholter Start, Rechte/CSRF, Deadline-Grenzen, Historie/Wiederoeffnen,
Kommentare/Aktivitaet (inkl. XSS-Escaping und geloeschte Benutzer),
Meine Aufgaben/Prioritaeten, Kanban/Kalender (Monats-/Jahresgrenzen),
Reminder (simulierter HA-Endpunkt, Timeout, Ruhezeiten, Neustart/Dedup),
Wiederholungen/Checklisten/Vorlagen, Meilensteine/Zyklen, Pagination/Aggregate.
Die bestehenden Musiktests bleiben gruen.

Nicht durchgefuehrt: manuelle Browserabnahme an einer realen HA-Instanz
(kein Live-Test, keine reale Nachricht versendet). Browsernachweise liegen daher
nicht vor; die Template-Kompilation und das Rendering wurden ueber TestClient
verifiziert.

## Bekannte Fehler, Risiken, fehlende Konfiguration, nicht getestet

- **HA-Anbindung**: produktiv nicht getestet. `config.yaml` enthaelt noch keine
  neuen Optionsfelder (Schema/Defaults); Codex soll die finalen Optionsnamen
  pruefen und die `config.yaml`-Schemaerweiterung zusammen mit der
  Release-Version setzen. Der Adapter ist bis dahin wirkungslos deaktiviert.
- **Erinnerungs-"Zeitpunkt"** ist eine globale Tageszeit; der Scheduler laeuft
  alle 300 s im Prozess und ist fuer eine Ein-Prozess-Installation ausgelegt.
  Mehr-Prozess-Worker sind nicht abgedeckt (Dedup verhindert trotzdem Duplikate).
- **Abhaengigkeits-Auswahl** laedt alle aktiven Aufgaben eines Projekts
  (`dependency_options`); bei sehr grossen Projekten spaeter auf Pagination
  umstellen.
- **Kommentare/Aktivitaet pro Aufgabe** sind derzeit nicht paginiert
  (nur die Aufgabenliste/Historie). Bei Aufgaben mit sehr vielen Eintraegen
  spaeter nachziehen.
- **Bekannte Altlasten** aus der Roadmap (Passwort-Ueberschreibung bei
  Admin-Passwort, Download-Header fuer Unicode-Dateinamen, Hierarchie-Rechte)
  bleiben unveraendert und ausserhalb dieses Arbeitspakets.

## Manuelle Abnahmefolge fuer Codex und Nutzer

1. Frisches `HOUSEHOLD_DATA_DIR`, Admin anlegen, anmelden.
2. Projekt anlegen, Mitglied hinzufuegen, Aufgabe mit Prioritaet, Deadline,
   Wiederholung, Meilenstein und Checkliste anlegen.
3. Kommentar mit `<script>alert(1)</script>` schreiben -> wird escaped dargestellt.
4. Statuswechsel + Bearbeitung -> Aktivitaet zeigt alte/neue Werte.
5. "Meine Aufgaben" mit zwei Nutzern pruefen; Freigabe entziehen -> Aufgaben
   verschwinden.
6. Kanban: Statuswechsel in Kanban und Ruecksicht in Liste/Historie pruefen.
7. Kalender: Monats-/Jahreswechsel und Aufgaben ohne Datum pruefen.
8. Vorlage anlegen und daraus Aufgabe erzeugen; Wiederholungsaufgabe abschliessen
   -> genau eine Folgeaufgabe; erneut abschliessen -> kein Duplikat.
9. > 50 Historieeintraege anlegen -> Pagination zeigt "Seite 1 von N".
10. Reminder: ohne Optionen keine Nachricht; mit simuliertem Endpunkt den Adapter
    testen (keine reale Nachricht).

## Nachtrag: Korrekturen aus dem Codex-Review (2026-11-12)

Basis: `docs/project-wiki/codex-review.md`. Alle P1/P2-Befunde wurden behoben
und mit Regressionstests abgesichert. Kein Commit/Push/Deployment.

- **P1 Benutzerloeschung**: `delete_user_with_reassignment` loescht persoenliche
  `task_templates` des Betroffenen (keine stillschweigende Weitergabe).
- **P1 Empfaenger**: neue Spalte `users.reminder_target`; Versand nur mit
  gueltigem Ziel. Ohne Ziel kein Versand. Konto- und Benutzerformulare erweitert.
- **P1 Blockieren**: Reminder-Schleife laeuft ueber `asyncio.to_thread`;
  Task-Lebenszyklus mit Shutdown-Handler (`on_shutdown` cancelt).
- **P2 HA-Endpunkt**: Service wird in Domain/Service zerlegt,
  `POST /api/services/<domain>/<service>`; Service per Regex validiert.
- **P2 Dedup**: Modul-Lock serialisiert Laeufe; Versuch wird vor Netzwerkzugriff
  atomar beansprucht (`claim_reminder_delivery`). Semantik: at-least-once,
  keine Exactly-once-Garantie. Faelligkeitsdatum wird bei der erneuten
  Kandidatenpruefung mitverglichen.
- **P2 Links/Suche**: stabile, rechtegepruefte Detailroute `GET /tasks/{id}`
  mit eigenem Template; "Meine Aufgaben"/Kalender verlinken dorthin. Suche ist
  serverseitig (`q`), filtert vor der Pagination und bleibt in der
  Seitennavigation erhalten.
- **P2 Wiederholung**: Zuweisung wird vor dem Anlegen der Folgeaufgabe erneut
  validiert (bei Freigabeentzug geleert); Meilenstein wird uebernommen,
  Abhaengigkeiten bewusst nicht (Produktregel).
- **P2 Kalender**: Monatsparsing und Nachbarmonate sind gegen Randwerte des
  `date`-Bereichs abgesichert (`shift_month`, try/except in `build_calendar`).

Neue Regressionstests: `tests/test_review_fixes.py` (7 Tests). Gesamtstand:
**43 Tests bestanden**, auch mit `-W error::ResourceWarning`.

Verbleibende offene Bereiche (unveraendert): `config.yaml`-Optionsschema und
Release-Version durch Codex, echte 0.6.0-Migration, Browser-/Smartphone-
Sichtpruefung, Containerstart und File-Sharing-/Musik-Regression.
