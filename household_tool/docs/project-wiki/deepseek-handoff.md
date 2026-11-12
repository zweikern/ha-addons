# Uebergabe an DeepSeek: Household Projekte

Datum: 2026-11-11
Arbeitsverzeichnis: `/Users/tom/Documents/HA Add-ons/household_tool`
Repository: `/Users/tom/Documents/HA Add-ons`
Ausgangsrelease: 0.6.0, Commit `9654bb1` auf `main`.

## Auftrag und Zusammenarbeit

Entwickle die Projekte-App anhand der unten beschriebenen Erweiterungen weiter.
Implementiere, teste und dokumentiere die Ergebnisse lokal. Codex uebernimmt
anschliessend Code-Review, gegebenenfalls Korrekturen, Release-Versionierung,
Commit und Push auf GitHub. Der Nutzer aktualisiert danach selbst das HA-Add-on.

Kein Push, kein Merge, kein Deployment und kein Update der produktiven HA-Instanz
durch DeepSeek. Keine produktiven Zugangsdaten anfordern oder in Dateien ablegen.
Keine Nachrichten oder Testbenachrichtigungen an reale Nutzer senden.
Lasse die Aenderungen lokal reviewbar; keine automatischen Commits.
Bei Unterbrechung dokumentiere den erreichten Stand statt Features als fertig
auszugeben. Scope und verbleibende Arbeiten muessen aus der Ergebnisdatei hervorgehen.

## Zuerst lesen

1. `AGENTS.md`
2. `docs/project-wiki/README.md`
3. `docs/project-wiki/projects.md`
4. `docs/project-wiki/development.md`
5. `docs/project-wiki/review-roadmap.md`
6. Aktuellen Code und `git status --short`; der Code ist massgeblich.

Das Repository enthaelt auch `downtime/`, das in einem separaten Chat entwickelt
wird. Diesen Bereich und fremde Aenderungen nicht anfassen. Insbesondere keine
pauschalen git-add-, reset- oder clean-Befehle verwenden. Bei Konflikten mit
parallel geaenderten Dateien stoppen und den Konflikt dokumentieren.

## Unveraenderliche Produktregeln

- Aufgaben mit Status `done` erscheinen nur in der Historie; alle Informationen
  und Anhaenge bleiben erhalten. Wiederoeffnen muss weiter funktionieren.
- Deadline ist ein optionales Kalenderdatum. Heute/Morgen beziehen sich auf
  Europe/Berlin; erledigte Aufgaben zaehlen nicht in aktive Deadline-Zaehler.
- Zugriff basiert auf Projekteigentuemer oder expliziter Mitgliedschaft.
  Hierarchie vererbt aktuell keine Rechte. Admin ist kein pauschaler Ersatz
  fuer Projektmitgliedschaft bei Abfragen.
- Mitglieder bearbeiten Aufgaben, Owner/Manager verwalten Projekte und Sharing.
- Jede neue Lese-/Schreibroute prueft Rechte serverseitig. Schreibaktionen
  benoetigen CSRF. Versteckte Buttons sind keine Zugriffskontrolle.
- Keine Schema-Neuanlage auf Kosten bestehender Daten. Migrationen muessen
  mit einer 0.6.0-Datenbank funktionieren und mehrfach ausfuehrbar sein.
- File Sharing, Musik und Benutzerverwaltung muessen weiter funktionieren.
- Vorhandenes helles Tuerkis/Blau-CI fortfuehren, mobile Bedienung und
  Tastaturbedienung erhalten. Keine externen CDN-Abhaengigkeiten voraussetzen.

## Umsetzung in reviewbaren Etappen

Die Reihenfolge ist bewusst priorisiert. Etappen einzeln fertigstellen und
testen. Nicht alle Features gleichzeitig als ungetestetes Geruest einfuehren.
Falls die Arbeit in einer Sitzung nicht fertig wird, sauber an einer Etappengrenze
uebergeben. Alle nachfolgenden Etappen bleiben als offen dokumentiert.

### 1. Kommentare und Aktivitaetsverlauf

- Kommentare pro Aufgabe mit Autor und Erstellzeit, sicher als Text gerendert.
- Schreibgeschuetzter Aktivitaetsverlauf fuer Anlage, Status, Wiederoeffnen,
  Titel/Beschreibung, Deadline, Fokus, Zustaendigkeit und neue Anhaenge.
- Akteur, UTC-Zeit, Ereignistyp sowie relevante alte/neue Werte speichern.
- Aufgabenmutation und Ereignis in derselben DB-Transaktion; fehlgeschlagene
  oder unberechtigte Aktionen erzeugen keine Ereignisse.
- Bestehende Aufgaben nicht mit erfundenen historischen Ereignissen auffuellen.
- Geloeschte Benutzer duerfen den Verlauf nicht zerstoeren; eine nachvollziehbare
  Anzeige ehemaliger Autoren vorsehen, ohne Passwoerter oder private Profile
  in Eventdaten zu kopieren.
- Historie abgeschlossener Aufgaben und Aktivitaetsverlauf getrennt benennen.

Abnahme: Kommentar und Ereignisse bleiben nach Abschluss/Wiederoeffnen erhalten;
Fremdnutzer koennen sie weder lesen noch schreiben; XSS-Teststrings werden escaped.

### 2. Meine Aufgaben und Prioritaeten

- Projektuebergreifende Ansicht fuer dem eingeloggten Nutzer zugewiesene Aufgaben.
- Filter: aktiv, Fokus, heute, morgen, ueberfaellig; erledigte Aufgaben nur in
  einer expliziten Historienansicht. Projektname und Link zur Aufgabe anzeigen.
- Prioritaet optional: niedrig, normal (Default), hoch. Validierung im Backend.
- Rechte vor Aggregation und Pagination anwenden. Nach Entzug einer Freigabe
  verschwinden Aufgaben und Zaehler sofort aus der Ansicht.
- Projektbezogene Header-Zaehler weiterhin eindeutig von globalen unterscheiden.

Abnahme: Zwei Nutzer mit unterschiedlichen Mitgliedschaften und Zuweisungen
sehen exakt ihre berechtigten Aufgaben; fehlende Zuweisung ist kein Fehler.

### 3. Kanban und Kalender

- Kanban mit Offen/In Arbeit; erledigte Aufgaben bleiben ausschliesslich in
  Historie. Kein zweites widerspruechliches Statusmodell einfuehren.
- Statuswechsel per Schaltflaechen/Select; Drag-and-drop nur als Ergaenzung.
- Kalender als Monatsansicht mit Terminen und Links zur Aufgabe; Aufgaben ohne
  Datum bleiben in der Liste auffindbar. Monatswechsel und leere Tage behandeln.
- Alle Ansichten benutzen dieselben Daten, Rechte und Deadline-Regeln.

Abnahme: Statuswechsel in Kanban ist in Liste/Historie korrekt sichtbar;
Kalender zeigt Termine an Monats-/Jahresgrenzen korrekt, auch mobil.

### 4. Erinnerungen ueber Home Assistant

- Standardmaessig deaktiviert; eigenes Nutzer-Opt-in fuer Erinnerungen.
  Vorhandenes Mail-Opt-in ist keine HA-Benachrichtigungskonfiguration.
- Konfigurierbares Ziel/Service, Zeitpunkt und Ruhezeiten mit validierten Werten.
- Vor Integration Supervisor-/HA-Zugriff und benoetigte Add-on-Berechtigungen
  anhand aktueller offizieller Dokumentation pruefen und dokumentieren.
- Keine hartcodierten Tokens oder IP-Adressen. Wenn produktive Konfiguration
  fehlt, einen deaktivierten, testbaren Adapter liefern und klar kennzeichnen.
- Persistente Deduplizierung, Neustartverhalten und begrenzte Wiederholungen;
  bekannte Zustellunsicherheit bei Netzwerkfehlern dokumentieren.
- Vor Versand Rechte, Status und Opt-in erneut pruefen. Keine Erinnerungen
  fuer erledigte Aufgaben oder nach Freigabeentzug.

Abnahme: Tests mit simuliertem HA-Endpunkt, inklusive Timeout, Ruhezeiten,
Neustart und doppeltem Scheduler-Lauf. Keine reale Nachricht versenden.

### 5. Wiederholungen, Checklisten und Vorlagen

- Checklistenpunkte mit erledigt/offen; Aufgabestatus nicht stillschweigend aendern.
- Wiederholungen zunaechst taeglich/woechentlich/monatlich, Kalenderdaten nach
  Europe/Berlin. Monatsende explizit definieren (z.B. letzter gueltiger Tag).
- Abschluss erzeugt hoechstens eine Folgeaufgabe; doppelte Requests und
  Wiederoeffnen/erneuter Abschluss duerfen keine Duplikate erzeugen.
- Kopierregeln fuer Zuweisung, Fokus, Checklisten, Anhaenge und Kommentare
  festlegen und im Wiki dokumentieren. Aktivitaetsverlauf nicht kopieren.
- Projekt-/Aufgabenvorlagen als explizite Aktion; keine Daten fremder Projekte
  ungefragt in neue Freigabekontexte kopieren.

Abnahme: Mehrfachabschluss, Monats-/Jahreswechsel, fehlender Zustaendiger und
Freigabeentzug getestet; Vorlage veraendert ihr Ursprungsprojekt nicht.

### 6. Meilensteine und Abhaengigkeiten

- Meilensteine pro Projekt mit optionalem Datum; Aufgaben zuordenbar.
- Abhaengigkeiten zunaechst innerhalb desselben Projekts; keine Selbstkanten
  oder Zyklen. Blockierende Aufgaben und deren Status sichtbar machen.
- Blockierung zunaechst als Hinweis; Abschluss nicht ohne dokumentierte
  Produktentscheidung hart sperren.
- Aufwand-/Zeiterfassung bleibt eine spaetere optionale Erweiterung,
  nicht Voraussetzung fuer diese Etappe.

Abnahme: Zyklusversuche serverseitig abweisen; geloeste Abhaengigkeiten
aktualisieren die Anzeige; keine Datenlecks ueber verknuepfte Aufgaben.

### 7. Skalierung und Abschluss

- Pagination fuer Listen, Historie, Kommentare und Aktivitaeten.
- Zaehler ueber SQL-Aggregate statt Laden aller Aufgaben berechnen.
- Stabile Sortierung mit ID als Tie-Breaker; Suche/Filter/Pagination kombinierbar.
- Passende Indizes anhand realer Abfragen, keine pauschale Indexsammlung.
- DB-Verbindungen verlaesslich schliessen; SQLite-Transaktionen bewusst halten.
- Fehlermeldungen lesbar, Leerzustaende und Suchtrefferzahl klar darstellen.

Abnahme: Mehrere hundert Aufgaben und mehr als eine Seite Historie pruefen;
Zaehler gelten fuer die gesamte berechtigte Ergebnismenge, nicht nur die Seite.

## Technische Leitplanken

FastAPI + Jinja2 + SQLite beibehalten. Keine SPA-Komplettmigration und keinen
neuen Datenbankserver einfuehren. Kleine Module duerfen main.py/db.py entlasten,
aber nur mit nachvollziehbaren Imports, Tests und aktualisierter Dokumentation.
Neue Abhaengigkeiten begruenden. Python 3.13, amd64/aarch64 und Alpine beachten.

Bestehende Security-/Auth-Themen aus der Roadmap nicht nebenbei umbauen.
Gefundene Bugs als Review-Hinweise dokumentieren; notwendige Fixes gezielt
testen. Kein automatischer Passwortreset und keine Datenloeschung.

## Testumgebung

Im Add-on-Verzeichnis:

```sh
python3 -m venv /tmp/household-deepseek-venv
/tmp/household-deepseek-venv/bin/pip install -r app/requirements.txt httpx
/tmp/household-deepseek-venv/bin/python -m unittest discover -s tests -v
HOUSEHOLD_DATA_DIR=/tmp/household-deepseek-data /tmp/household-deepseek-venv/bin/python app/main.py
```

Vor Serverstart Port 8099 auf Belegung pruefen; keine laufende Instanz stoppen.
Nur isolierte Testdaten. Bei Browsertests keine produktiven Sessions verwenden.
Ausgangsstand: 11 Tests bestanden; ein Live-Test in HA war bei der Uebergabe
noch nicht erfolgt. Alte ResourceWarnings sind kein Nachweis eines Testfehlers,
muessen bei Connection-Aenderungen aber gezielt adressiert werden.

Pflichtpruefungen: Migration von 0.6.0 inklusive Anhaengen, wiederholter Start,
Rechte-/CSRF-Tests, Deadline-Grenzen, Historie/Wiederoeffnen, neue Features,
bestehende Musiktests, Template-Kompilation und JS-Syntax.
Browserabnahme bei Desktop- und Smartphonebreite mit Tastaturbedienung.
Nicht durchgefuehrte Pruefungen explizit benennen.

## Ergebnis an Codex

Erstelle `docs/project-wiki/deepseek-results.md` mit:

- Ausgangscommit und implementierten Etappen; offene Punkte getrennt auffuehren.
- Geaenderten Dateien, neuen Routen, Schema-Migrationen und Abhaengigkeiten.
- Produktentscheidungen (Wiederholung, Rechte, Termine, Benachrichtigungen).
- Ausgefuehrten Testbefehlen und echten Ergebnissen, Browsernachweisen soweit vorhanden.
- Bekannten Fehlern, Risiken, fehlender Konfiguration und nicht getesteten Bereichen.
- Kurzer manueller Abnahmefolge fuer Codex und den Nutzer.

Aktualisiere das Wiki passend zum implementierten Stand. Lass `config.yaml`
auf dem Ausgangsrelease, bis Codex das Review abgeschlossen hat; Codex setzt
die finale Release-Version. Keine Behauptung "deployed" oder "in HA getestet"
ohne entsprechenden Nachweis.

## Anschliessender Codex-Review

Codex prueft zuerst Datenverlust, Zugriffsrechte, Transaktionen, Migrationen,
Neustart-/Deduplizierungsverhalten und Regressionen. Danach folgen Bedienung,
mobile Darstellung, Tests und Dokumentation. Notwendige Korrekturen werden
implementiert und erneut getestet. Erst danach folgen Release-Version,
gezielter Commit und GitHub-Push. Der Nutzer fuehrt das HA-Update aus.
