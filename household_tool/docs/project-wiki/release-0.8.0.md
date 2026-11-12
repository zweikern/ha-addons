# Version 0.8.0: Projektoberflaeche und Projektplaene

Stand: 2026-11-12. Keine Aenderungen am separaten downtime-Add-on.

## So wird ein Projektplan erstellt

1. Unter Projekte ein Projekt auswaehlen oder ueber Projekt anlegen erstellen.
2. Neue Aufgabe oeffnen und optional Start- und Enddatum setzen. Bestehende
   Aufgaben ueber den Aufgabennamen oeffnen und unter Projektplanung terminieren.
3. In der Aufgabendetailansicht Vorgaenger auswaehlen und verknuepfen.
   Die aktuelle Aufgabe beginnt fachlich erst nach diesen Vorgaengern.
4. In Projektplan auf Tage, Wochen oder Monate umschalten. Zeitraum vor/zurueck
   bewegen; Heute springt in den aktuellen Zeitraum. Seitliches Scrollen bleibt
   im Zeitstrahl, nicht auf der ganzen Seite. Aufgabennamen bleiben fixiert.
5. Auf einen Balken oder das Kalender-Symbol einer Aufgabe klicken/tippen, um
   ihren Zeitraum zu bearbeiten. Beide Daten leeren, um die Planung aufzuheben.
6. Meilensteine ueber Verwalten bzw. Meilensteine anlegen, bearbeiten oder
   entfernen. Eigentuemer/Projektverwalter verwalten sie, Mitglieder lesen sie.
7. Drucken / PDF oeffnet den Browser-Druckdialog. Als PDF speichern waehlen.
   Vorgabe A3 quer; aktuelle Zeitskala und aktueller Ausschnitt werden gedruckt.
   Die Namen bleiben links lesbar, die Balken skalieren auf die Druckbreite.

Die Listenansicht zeigt kompakte Zeilen statt vieler verschachtelter Formulare.
Aufgaben, Board, Projektplan, Kalender und Historie sind eigene Ansichten.
Fokus und Heute/Morgen/Ueberfaellig sind weiterhin direkt im Header erreichbar.
Vollstaendige Details, Bearbeitung, Checklisten, Kommentare, Anhaenge und Verlauf
stehen in der Aufgabenansicht zur Verfuegung. Formularaktionen kehren dort zur
Aufgabe zurueck. Vorgaenger koennen auch wieder entfernt werden.

## Verbindliche Planungsregeln

- `tasks.start_date` und `tasks.end_date`: nullable ISO-Kalenderdaten.
  Entweder beide gesetzt oder beide NULL. Enddatum darf gleich dem Start sein,
  aber nicht davor liegen. Server und Browser validieren die Eingabe.
- Kalendertage, keine Arbeitskalender. Start und Ende sind inklusive.
- Deadline bleibt ein unabhaengiges Faelligkeitsdatum und steuert weiterhin
  Tageszaehler/Erinnerungen. Sie erzeugt keinen erfundenen Planungszeitraum.
- Eine Ende-Start-Abhaengigkeit erfordert: Start des Nachfolgers spaeter als
  Enddatum des Vorgaengers. Gleicher Kalendertag gilt als Konflikt.
- Bestehende Zyklus-/Projektgrenzen gelten weiter. Selbstbezug, Zyklen und
  Verknuepfungen zwischen Projekten sind unzulaessig.
- Zeitliche Widersprueche bleiben als Warnung sichtbar und werden nicht still
  korrigiert. Ein Planende nach der Deadline ist ebenfalls eine Warnung.
- Keine automatische Terminverschiebung, kein Critical-Path-Algorithmus, keine
  Arbeitszeit-/Ressourcenkalender. Das waeren separate Produkterweiterungen.
- Erledigte Aufgaben bleiben ausschliesslich in Historie; ihre Planungsdaten
  gehen nicht verloren und sind in den Details weiterhin les-/bearbeitbar.
- Wiederkehrende Folgeaufgaben sind zunaechst ungeplant; historische Zeitraeume
  werden nicht blind auf eine neue Aufgabe kopiert.
- Nicht terminierte Aufgaben bleiben als solche sichtbar. Ausserhalb des
  gewaehlten Ausschnitts liegende Aufgaben werden beschriftet, nicht verschwiegen.
- Pfeile erscheinen nur zwischen aktiven, im Ausschnitt sichtbaren Aufgaben.
  Abhaengigkeiten zu erledigten/ungeplanten Aufgaben bleiben in den Details erhalten.
- Loeschen eines Meilensteins entfernt nur dessen Zuordnung, nie die Aufgaben.

## Architektur und Migration

`app/db.py:init_db()` ergaenzt die zwei nullable Spalten idempotent. Bestehende
Aufgaben erhalten keine automatisch erfundenen Termine. Neue Aufgaben speichern
Planungsdaten atomar; spaetere Planungsaktionen protokollieren `schedule_changed`.
Metadatenbearbeitung und Statuswechsel lassen den Zeitraum unveraendert.
Abhaengigkeitsanlage/-entfernung wird im Verlauf protokolliert.

Neue Routen:
- `POST /tasks/{id}/schedule`: Rechte, CSRF, Datumsvalidierung, Audit und Redirect.
- `POST /tasks/{id}/dependencies/{dependency_id}/remove`: Projektmitgliedschaft,
  CSRF und exakte Zuordnung zum Task; keine fremden Verknuepfungen loeschbar.
- `POST /projects/{id}/milestones/{milestone_id}/edit`: explizite
  Projektverwaltung, CSRF, Datum, Projektgrenze; `action=save|delete`.
- `GET /projects?project_id=...&view=timeline&scale=day|week|month&anchor=YYYY-MM-DD`.

`app/planning.py` ist ein reiner, separat testbarer Layout-Builder. Drei Skalen:
28 Tage/42px, 84 Tage/20px, 366 Tage/7px pro Kalendertag. Start der Ansicht am
Montag; Default beim fruehesten terminierten Projekt-Eintrag, sonst heute.
Der Datumsbereich ist unabhaengig von der Dauer einzelner Aufgaben begrenzt;
auch extreme, gueltige Kalenderdaten erzeugen keine riesigen Tagesschleifen.
Balken werden am Ausschnitt abgeschnitten, Dauer wird aus den echten Daten
berechnet. SVG-Pfeile liegen in derselben Geometrie; Zeilenhoehe aktuell 58px.

`project-ui.css` ist ausschliesslich auf `body.project-ui`/`.pm-*` begrenzt;
File Sharing und Musik erhalten keine neue Oberflaeche. Die Projekt-Templates
nutzen `partials/pm_ui.html`, `project_plan.html`, `project_calendar.html` und
Dialog-Partials. Keine externen CDNs, Icon-/Gantt-Bibliotheken oder neuen
Runtime-Abhaengigkeiten. CSS-/JS-Dateien werden mit Release-Query geladen.

Druck: Datumspunkte und Balken haben zusaetzlich Prozentkoordinaten. Die SVG
verwendet viewBox plus preserveAspectRatio=none, damit nur die horizontale
Geometrie skaliert, nicht Schriftgroesse/Zeilenhoehe. Druck ist Browserfunktion,
kein serverseitiger PDF-Generator. Lange Plaene koennen mehrere Seiten erzeugen.
Auf sehr kurzen Balken duerfen Texte abgeschnitten sein; volle Namen stehen links.

Native dialog-Elemente liefern Escape-/Fokusverhalten; Schliessen gibt den Fokus
an den Ausloeser zurueck. JS befuellt Formulare via DOM-Text und gepruefte
numerische IDs. Ohne JS werden Anlage-/Verwaltungsformulare inline sichtbar;
Zeitplanung funktioniert weiter ueber die Aufgabendetails.

Aufgabenlisten laden Anhangmetadaten nur fuer ihre sichtbare Seite und die zwei
neuesten Kommentare pro Aufgabe. Vollstaendige Chroniken werden erst in der
Aufgabenansicht geladen. Keine Datei-BLOBs im Listen-Kontext.

## Abnahme und Testgrenzen

- 67 Tests bestanden, auch mit `-W error::ResourceWarning`.
- Bestand: Login/CSRF, Musik, File Sharing, Historie, Migration aus 0.6.0,
  Erinnerungen und prozessuebergreifende Zustellreservierungen weiterhin getestet.
- Neue Tests: Datumsvalidierung, Dauer, Ein-Tages-Balken, Ausschnitt-Clipping,
  Randdaten, Planungswarnungen, Meilensteine, SVG-Geometrie, Status-/Datenerhalt,
  Rechte, Zyklen, Zuordnung beim Entfernen, sichere Vorschauen und XSS-Escaping.
- Migration aus dem 0.7.0-Taskschema simuliert durch Entfernen der neuen Spalten;
  mehrfacher Start erhaelt Aufgaben und laesst deren Planungsdaten leer.
- Lokale Chromium-Abnahme bei 1600 und 390 Pixeln: alle Projektansichten,
  Details, Meine Aufgaben, Vorlagen. Keine JS-Fehler oder horizontalen Seiten-
  Ueberlaeufe. Der Zeitstrahl selbst ist absichtlich horizontal scrollbar.
- Browserablauf: geplante Aufgabe anlegen, Zeitraum per Balkendialog aendern,
  Vorgaenger hinzufuegen/entfernen, Meilenstein anlegen/aendern/loeschen,
  Aufgabe abschliessen. Native Dialoge, Escape und Fokusrueckgabe geprueft.
- Drei PDF-Druckproben fuer Tage/Wochen/Monate erzeugt und gerendert; Beispiele
  passen auf A3 quer. Lokale Testartefakte, keine privaten Projektinhalte.

Nicht getestet: physisches Smartphone/Safari, echte HA-Installation,
Containerstart oder reale Benachrichtigungen. Docker ist hier nicht installiert.
Keine produktive Datenbank fuer die Entwicklung verwendet.

## Update

Add-on inklusive Daten sichern. Nach GitHub-Push das Repository im HA-Store
aktualisieren und Version 0.8.0 installieren. Danach Projekte > Projektplan
aufrufen. Fuer bestehende Aufgaben Zeitraeume bewusst setzen; keine automatische
Migration von Deadlines in Balken. Bei Rollback passende Datensicherung verwenden.
