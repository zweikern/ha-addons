# Codex-Nachpruefung der Review-Korrekturen

Datum: 2026-11-12. Ergebnis: weiterhin keine Release-Freigabe.
Bezieht sich auf die lokale, nicht committete DeepSeek-Nachbesserung mit 43 Tests.
Keine Aenderung an Anwendungscode, Version oder produktiver Installation.

## Verifiziert

- Alle 43 Tests bestanden, auch mit `-W error::ResourceWarning`.
- Ausfuehrung in isolierter Kopie `/private/tmp/household-review2-20261112`.
- Migration mit dem echten db.py aus Commit 9654bb1 (0.6.0): Datenbank frisch
  erzeugt, Benutzer, Projekt, offene und erledigte Aufgaben eingefuegt, dann
  zweimal mit dem neuen init_db migriert. Bestehende Zeilen/Spaltenwerte blieben
  unveraendert; `PRAGMA foreign_key_check` ohne Befund. Das ist ein Basistest,
  kein Test einer produktiven Datenbank mit vollstaendigem Datenbestand.
- Vorlagenloeschung, Wiederholungszuweisung, Meilenstein-Uebernahme,
  Domain/Service-URL und grundlegende Detailroute sind nachgebessert.
- Keine echten HA-Nachrichten versendet.

## Verbleibende Befunde

### P1: Empfaengerzuordnung noch nicht servicegerecht

Stellen: `app/reminders.py`, HomeAssistantNotifier.send;
`app/templates/account.html:48`.

Die UI empfiehlt `mobile_app_iphone` als Ziel, der Adapter sendet diesen Namen
jedoch als Payload-Feld `target` an den globalen Service `notify.notify`.
Ein Companion-Service-Name ist nicht allgemein eine Empfaenger-ID fuer diesen
Service. notify.notify bezeichnet den ersten verfuegbaren Notify-Service;
target-Unterstuetzung und Bedeutung haengen von dessen Integration ab.
Die Pruefung auf einen nichtleeren String garantiert daher weder korrekte
Zustellung noch Empfaengertrennung. Ungueltige Servicekonfiguration faellt
ausserdem still auf notify.notify zurueck statt den Versand zu unterbinden.
Die derzeitigen FakeNotifier-Tests pruefen nur die Weitergabe des Strings.

Korrektur: genau ein unterstuetztes Routingmodell definieren und validieren,
z.B. benutzerspezifischer `notify.mobile_app_<device>`-Service ohne falsches
target-Feld. Keine automatische Rueckfallzustellung ueber einen anderen Service.
Adminseitige Empfaengerzuordnung und Benutzer-Opt-in getrennt behandeln.
Tests fuer zwei Benutzer mit unterschiedlichen Endpunkten und ungueltige Ziele.

Offizielle Quellen (2026-11-12 geprueft):
- https://www.home-assistant.io/actions/notify.notify
- https://companion.home-assistant.io/docs/notifications/notifications-basic/
- https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/mobile_app/notify.py

### P2: Claim ist weiterhin keine prozessuebergreifende Reservierung

Stelle: `app/db.py:1040`, claim_reminder_delivery.

Das UPSERT erhoeht nur attempts; es verweigert keinen bereits laufenden Claim.
Das Python-Modul-Lock schuetzt nur Threads desselben Prozesses.
Gegenprobe mit zwei unabhaengigen Python-Prozessen, gemeinsamer SQLite-Datei
und simuliertem Notifier: beide Ergebnisse `sent=1`, insgesamt zwei Send-Aufrufe
fuer dieselbe Aufgabe und denselben Tag. Kein Absturz/Neustart war erforderlich.
Der neue Regressionstest prueft nur Threads und verdeckt diesen Fehler.

Korrektur: atomare DB-Reservierung mit eindeutiger Besitzkennung und definierter
Lease/Recovery-Politik; Statusabschluss nur fuer den Besitzer. Claim muss
bereits gesendete und aktive reservierte Zustellungen ablehnen. Prozesse separat
testen, inklusive abgelaufener Reservierung, Crash und Retry-Limit.
At-least-once ist bei begrenzten Wiederholungen zudem keine Zustellgarantie;
besser als begrenzten Best-effort-Versand mit moeglichen Duplikaten beschreiben.

### P2: Suchbegriff wird in Pagination nicht URL-kodiert

Stellen: `app/templates/projects_app.html:551` und `:553`.

Reproduktion: 51 aktive Aufgaben mit `A&B` im Titel, Suche nach `A&B`, Weiter.
Gerenderter Link: `/projects?project_id=1&view=all&q=A&B&page=2`.
Der Server erhaelt danach `q=A` statt `q=A&B`; Filter und Trefferzahl aendern
sich beim Seitenwechsel. HTML-Escaping ersetzt kein URL-Encoding.

Korrektur: Query-Parameter ueber URL-Builder oder URL-Encoding zusammensetzen;
Tests mit &, +, # und Unicode. Der bisherige Suchtest erzeugt 60 erledigte
Aufgaben ausserhalb des aktiven Filters, prueft also keine echte aktive
Mehrseiten-Suche.

### P2: Initialer Erinnerungslauf blockiert weiterhin den Start

Stelle: `app/main.py:554`.

Nur periodische Laeufe verwenden to_thread. on_startup ruft den kompletten
synchronen Versand vor Abschluss des Starts auf. Viele faellige Aufgaben plus
langsame HA-Antworten verzögern die Bereitschaft um die aufsummierten Timeouts.
Der Shutdown cancelt den asyncio-Task, beendet aber keinen bereits laufenden
to_thread-Worker; dessen Lebenszyklus muss ebenfalls kontrolliert werden.

Korrektur: Initiallauf in kontrollierten Hintergrund-Lebenszyklus uebernehmen,
Timeouts/Batchgroesse begrenzen und Shutdown-Verhalten testen.

## Noch ausstehend

Konfigurationsschema und Version bleiben bis zur Klaerung des Routingmodells
unveraendert. Browser-/Smartphone-Abnahme, Containerstart und umfassende
File-Sharing-Regression wurden in dieser Nachpruefung nicht ausgefuehrt.
Musiktests sind Teil der erfolgreichen vorhandenen 43 Tests.
Kein Commit, Push oder Deployment. `downtime/` blieb unberuehrt.
