# Release 0.7.0: Abschluss und Betrieb

Stand: 2026-11-12. Die urspruenglichen DeepSeek-Berichte und beiden Reviews
bleiben als historische Nachweise erhalten. Dieses Dokument beschreibt den
abschliessenden Stand und ersetzt deren offene P1/P2-Listen.

## Funktionsumfang

- Erledigte Aufgaben nur in Historie, mit vollstaendigen Details und Wiederoeffnen.
- Deadlines, Fokus, Heute/Morgen/Ueberfaellig-Zaehler, Prioritaeten, Meine Aufgaben.
- Kommentare, Aktivitaetsverlauf, Checklisten, wiederkehrende Aufgaben, Vorlagen.
- Meilensteine und gerichtete Abhaengigkeiten mit Zykluspruefung.
- Kanban, Desktop-Monatskalender und kompakte Smartphone-Terminagenda.
- Rechtegepruefte direkte Aufgabenlinks aus Liste, Kalender und Meine Aufgaben.
- Serverseitige Suche vor Pagination; URL-kodierte Filter und begrenzte Seitenzahl.
- Private Vorlagen werden bei Benutzerloeschung geloescht, nicht weitergegeben.
- Wiederholungen validieren Zuweisungen erneut, kopieren den Meilenstein, aber
  keine Abhaengigkeiten. Vorlagen/Folgeaufgaben erhalten Anlageereignisse.
- Unicode-sichere Downloads und geschlossene temporaere ZIP-Dateideskriptoren.

## Erinnerungen einrichten (optional)

Standard bleibt deaktiviert. Kein Supervisor-Token, kein host_network, keine
zusaetzlichen Add-on-Berechtigungen: der Adapter nutzt die HA-REST-API direkt.

1. HA-URL (HTTPS bevorzugt) und einen geeigneten HA-Zugriffstoken ausschliesslich
   in der Add-on-Konfiguration hinterlegen. Nie in Git, Tickets oder Logs.
2. Unter Household > Benutzer ordnet ein Admin jedem Empfaenger dessen konkreten
   vorhandenen Dienst `notify.mobile_app_<geraet>` zu. Keine Gruppen, kein
   `notify.notify`, keine automatische Rueckfallzustellung. Ein vorhandener
   Entwurfswert `mobile_app_...` muss bewusst neu zugeordnet werden.
3. Der Nutzer aktiviert unter Konto sein eigenes Erinnerungs-Opt-in. Das Ziel
   ist dort nur lesbar; gefaelschte Profilfelder koennen es nicht aendern.
4. `ha_reminders_enabled` erst nach Kontrolle der Zuordnung einschalten.
   Der globale Entwurfsparameter `ha_notify_service` ist absichtlich entfallen.

```yaml
ha_reminders_enabled: false
ha_base_url: ""
ha_token: ""
reminder_time: "09:00"
reminder_quiet_start: "22:00"
reminder_quiet_end: "07:00"
reminder_max_retries: 3
reminder_timeout: 5
```

Die API wird unter `/api/services/notify/mobile_app_<geraet>` mit Titel und
Nachricht aufgerufen, ohne falsches target-Payload. Ungueltige Konfiguration
verhindert den Versand. Weiterleitungen werden nicht verfolgt, damit kein
Bearer-Token an einen anderen Host gelangt. Fehlermeldungen speichern keine
rohen Netzwerk-Exceptions.

Zeitbasis Europe/Berlin; Erinnerung nur fuer heute faellige, aktive, zugewiesene
Aufgaben mit weiterhin vorhandener Projektberechtigung und Opt-in. Alle fuenf
Minuten maximal 25 Versuche; 0 bis 5 Versuche je Aufgabe/Benutzer/Tag, Timeout
1 bis 10 Sekunden. Gleiche Ruhezeitgrenzen bedeuten keine Ruhezeit.

SQLite reserviert vor dem Versand atomar einen Versuch mit Besitzer-Token und
120-Sekunden-Lease. Parallele Prozesse koennen keine aktive Lease uebernehmen;
veraltete Besitzer koennen keinen neuen Status ueberschreiben. Nach abgelaufener
Lease kann erneut versucht werden, bis zum Limit. Best effort: Ein Crash nach
extern akzeptierter Nachricht kann einen spaeteren Doppelversand verursachen;
keine Exactly-once- oder garantierte Zustellung. Ein extremer Netzwerkstillstand
ueber die Lease hinaus ist ebenfalls keine Exactly-once-Situation.

Initiallauf und Folgeintervalle laufen in einem eigenen Worker, nicht im
Webserver-Event-Loop. Shutdown signalisiert Stop, verhindert weitere Versuche
und wartet auf den laufenden Worker. Der Netzwerkzugriff besitzt einen Socket-
Timeout; bei unnormal langsam tröpfelnden Serverantworten ist dies keine harte
Gesamtzeitgarantie. Der Adapter liest keinen Response-Body.

Referenzen:
- https://companion.home-assistant.io/docs/notifications/notifications-basic/
- https://contributors.home-assistant.io/core/internals/rest-api/
- https://contributors.home-assistant.io/apps/guides/options/

## Abnahme

- 52 Tests mit Python 3.13, auch mit `-W error::ResourceWarning`.
- Separater Prozesskonkurrenztest, Lease-Recovery, Besitzerpruefung und Retry-Limit.
- Zwei getrennte Empfaenger-Endpunkte, ungueltige Ziele und Konfiguration.
- TestClient: Suche mit &, +, #, Unicode ueber 51 aktive Aufgaben; Rechte und CSRF;
  Manipulation der Profil-Zielzuordnung; Unicode-Upload/Download und Ordner-ZIP.
- Echte 0.6.0-Schemafixture aus Commit 9654bb1, doppelte Migration, Erhalt von
  Benutzerhash, erledigter Aufgabe, Deadline und Anhangbytes; foreign_key_check.
- Bestehende Musiktests weiterhin erfolgreich.
- Lokale Chromium-Pruefung bei 1440 und 390 Pixeln: Liste, Kanban, Kalender,
  Historie, Aufgabendetails, Meine Aufgaben, Vorlagen, Files, Musik, Konto, Benutzer.
  Keine JS-Fehler oder horizontalen Ueberlaeufe; Kalenderansicht visuell korrigiert.

Nicht durchgefuehrt: echter HA-Versand, physisches Smartphone, produktive DB-
Migration und Containerstart. Docker ist auf dieser Maschine nicht installiert.
Die lokale Uvicorn-Instanz startete erfolgreich; dies ersetzt keinen Docker-Test.

## Update und verbleibende Grenzen

Vor dem Update HA-Backup inklusive Add-on-Daten erstellen. Nach Push Repository
im Add-on-Store aktualisieren und Version 0.7.0 installieren. Danach Login,
Aufgaben/Historie, Files und Musik pruefen. Erinnerungen bleiben ausgeschaltet,
bis bewusst eingerichtet. Bei Rollback passende Datensicherung verwenden.

Grosse Projekte laden Kommentare, Aktivitaeten und Abhaengigkeitsoptionen noch
projektweit. Vollstaendige CRUD-Oberflaechen fuer Meilensteine/Vorlagen und eine
entfernbare Abhaengigkeitsverwaltung sind Weiterentwicklung, nicht Enterprise-PM.
Mail-Passwort-Recovery und Session-Widerruf bleiben eigene Themen. Ein in HA
konfiguriertes admin_password wird weiterhin beim Start uebernommen; leeren,
wenn der etablierte Admin sein Passwort ausschliesslich im Konto verwalten soll.
