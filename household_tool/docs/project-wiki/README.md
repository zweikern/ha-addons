# Home Assistant Add-ons: Projekt-Wiki

Stand: 12. November 2026. Repository: `zweikern/ha-addons`.
Dieses versionierte Wiki ist der Einstieg fuer Menschen und weitere Agenten.
Es lag zuvor kein Wiki im lokalen Repository vor. Ein eventuell separat
gehostetes GitHub-Wiki wurde nicht geprueft.

## Orientierung

- `repository.yaml`: Home-Assistant-Repository-Metadaten.
- `household_tool/`: Household-Plattform, Port 8099, Version 0.8.0.
- `downtime/`: separates Add-on fuer Ausfallprotokollierung. Eigener Entwicklungsbereich.
- [Projekte: Produkt, Architektur und Daten](projects.md)
- [Entwicklung, Tests und Betrieb](development.md)
- [Begutachtung und Erweiterungsvorschlaege](review-roadmap.md)

## Household-Plattform

FastAPI stellt serverseitig gerenderte Jinja-Seiten bereit. SQLite speichert
Benutzer und Anwendungsdaten; JavaScript ergaenzt Uploads, Bildnavigation und
Aufgabensuche. Das vorhandene CI nutzt helle Flaechen, Tuerkis und Blau.

Die Startseite `/apps` verknuepft Projekte, File Sharing und die Musikfunktionen.
`/account` verwaltet eigenes Profil/Passwort, `/users` die Benutzeradministration.
Session-Cookies und CSRF-Tokens schuetzen angemeldete Formularaktionen.
Passwoerter werden mit bcrypt gehasht. Mail-Opt-in ist ein gespeichertes Profilfeld;
ein vollstaendiger Mailversand/Passwort-vergessen-Prozess ist nicht implementiert.

File Sharing umfasst Ordnerfreigaben, Uploads (300 MiB pro Datei), ein
2-GiB-Kontingent pro Benutzer, Bildvorschau mit Navigation und ZIP-Downloads.
Dateibinaerdaten liegen unter `/data/fileshare`, Metadaten in SQLite.
Die Musikfunktionen enthalten einen token-geschuetzten Ingest und eine Sammlung;
Tests dazu befinden sich unter `tests/test_music_*.py`.

## Agenten-Uebergabe

1. Git-Status lesen; fremde Aenderungen und `downtime/` respektieren.
2. Dieses Wiki und die relevanten Routen/Funktionen lesen; alte Chat-Aussagen
   koennen vom aktuellen Code abweichen.
3. Keine produktive Datenbank fuer Tests verwenden. Keine Tokens, options.json
   oder Datenbankinhalte in Commits aufnehmen.
4. Aenderungen an Schema und Produktverhalten hier dokumentieren und testen.
5. Version in `config.yaml` bei Releases erhoehen. Ein lokaler Versionsbump
   allein aktualisiert keine laufende Home-Assistant-Installation.

Die Version 0.6.0 erweitert Aufgaben um Deadlines, vollstaendige Historie,
Wiederoeffnen, anklickbare Tagesfilter und eine aufgeraeumte Projektoberflaeche.

Neu in 0.7.0 (Abschlussbericht: [Release-Abnahme](release-0.7.0.md)): Kommentare und
Aktivitaetsverlauf, "Meine Aufgaben" mit Prioritaeten, Kanban/Kalender,
HA-Erinnerungen (standardmaessig deaktiviert), Wiederholungen/Checklisten/Vorlagen,
Meilensteine/Abhaengigkeiten sowie Pagination und SQL-Aggregate.

Neu in 0.8.0: neue Projektoberflaeche und Gantt-Projektplaene.
[Bedienung, Architektur und Release-Abnahme](release-0.8.0.md).
