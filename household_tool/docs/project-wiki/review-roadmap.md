# Begutachtung und Weiterentwicklung

## Befund und umgesetzte Verbesserungen (0.6.0)

Die bisherige Ansicht wurde von immer offenen Erstell-/Einstellungsformularen
dominiert. Tabellen enthielten viele gleichzeitig sichtbare Upload- und
Editierfelder. Erledigte Aufgaben erschienen sowohl in der normalen Liste als
auch in einer unvollstaendigen Historie. Termine fehlten.

Die neue Arbeitsansicht stellt aktive Aufgaben, Fokus und Termine in den
Vordergrund. Fortschritt und Tageszaehler geben Orientierung. Aufgaben erscheinen
als responsive Karten, Beschreibung/Anhaenge/Bearbeitung sind aufklappbar.
Neue Aufgaben und Projekteinstellungen werden bei Bedarf geoeffnet.
Historie verwendet die vollstaendigen Aufgaben inklusive Wiederoeffnen.
Suche, In-Arbeit-Filter und Ueberfaellig-Filter ergaenzen die Tagesansichten.
Die vorhandenen Funktionen bilden damit einen durchgaengigen Arbeitsablauf:
Projekt strukturieren, teilen, Aufgaben planen, zuweisen, bearbeiten, abschliessen
und spaeter wieder aufnehmen.

## Grenzen und Prioritaeten

Dies ist ein Haushalts-Projektmanagement mit den vorhandenen Funktionen,
kein Ersatz fuer alle Enterprise-PM-Funktionen. Folgende Erweiterungen sind
Vorschlaege und wurden nicht als bereits vorhanden ausgegeben:

1. Kommentare und unveraenderliche Aktivitaetschronik: Autor, Zeit, alte/neue
   Werte; getrennt von der Historie aktuell erledigter Aufgaben.
2. Projektuebergreifendes "Meine Aufgaben" mit Zustaendigkeit, Heute/Morgen
   und Prioritaeten; Rechte immer vor Aggregation anwenden.
3. Kanban-Ansicht und optionale Kalenderansicht auf derselben Aufgabenbasis;
   Statuswechsel auch ohne Drag-and-drop zugaenglich halten.
4. Erinnerungen ueber HA-Notifications; pro Nutzer Opt-in, Ruhezeiten und
   deduplizierte Zustellung. Mail-Opt-in alleine versendet noch nichts.
5. Wiederkehrende Aufgaben, Checklisten und Vorlagen fuer Haushalt/Routinen.
6. Meilensteine und Abhaengigkeiten, danach optional Zeit-/Aufwandserfassung.
7. Pagination und SQL-Aggregate fuer grosse Projekte statt kompletter Listen.

## Technische Folgearbeiten

- Sessions nach Passwortwechsel widerrufbar machen; expliziten Recovery-Prozess
  statt automatischer Passwortueberschreibung bei jedem Start etablieren.
- Deadlines bei Bedarf mit konfigurierbarer Haushaltszeitzone erweitern.
- Projekt-Unterordner vererben derzeit keine Rechte: Produktentscheidung
  dokumentieren, bevor dies geaendert wird.
- Download-Header fuer beliebige Unicode-Namen und sichere Inline-Dateitypen
  pruefen; dies betrifft auch File Sharing und liegt ausserhalb dieses Releases.
- Ressourcenfreigabe fuer DB-Verbindungen zentral korrigieren.
- Vor produktiver Freigabe manuelle Browserabnahme am realen HA durchfuehren.
