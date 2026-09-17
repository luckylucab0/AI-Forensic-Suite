# AI Agent Forensic Suite

[English](README.md) | Deutsch

Eine lokal arbeitende, vollständig offline nutzbare Forensik-Suite für die Spuren, die
KI-Coding-Agenten auf Endgeräten hinterlassen. Sie sammelt, verifiziert, parst und
analysiert, was Werkzeuge wie Claude Code, OpenAI Codex CLI, GitHub Copilot, Gemini CLI,
Cursor, Kiro oder Cline auf macOS, Windows und Linux auf der Platte zurücklassen.

> **Stand: früh.** Der Transkript-Viewer ist fertig und schon heute eigenständig
> nutzbar. Artefaktkatalog, Kollektoren, Bundle-Format, Analyzer, Regel-Engine und die
> lokale Web-UI sind drin. Was noch entsteht, sind weitere Parser pro Agent. Siehe
> [Fahrplan](#fahrplan).

## Zuerst die Befugnis, dann das Werkzeug

Dieses Werkzeug rekonstruiert, was eine Person getippt hat, welche Dateien auf ihrem
Rechner gelesen und geschrieben wurden und wohin Daten gegangen sind. Das sind
Personendaten, und auf einem Arbeitsgerät sind es in der Regel Personendaten von
Mitarbeitenden und nebenbei auch von allen, die in deren Code und Nachrichten erwähnt
werden.

Der Einsatz setzt eine ordentliche Befugnis voraus. Je nach Rechtsraum bedeutet das ein
dokumentiertes Untersuchungsmandat, die Einbindung der Arbeitnehmervertretung, eine
Datenschutz-Folgenabschätzung, oder alles davon. Sammle nur das Minimum, das die
Fragestellung wirklich braucht, behalte es nicht länger als notwendig, und halte dich an
das anwendbare Recht und die eigenen internen Vorgaben. Nichts in diesem Repository ist
eine Rechtsberatung, und keine Voreinstellung dieses Werkzeugs nimmt dir diese Abwägung
ab. Zur Dual-Use-Problematik siehe [SECURITY.md](SECURITY.md).

## Welche Fragen es beantwortet

Für ein Gerät und eine Benutzerin oder einen Benutzer:

- Welche KI-Agenten waren installiert, wurden genutzt, und wann
- Was wurde gefragt, vollständig, auch Eingaben, die in der Oberfläche später
  verschwunden sind
- Was hat der Agent getan: gelesene und geschriebene Dateien, ausgeführte Befehle,
  Netzwerkziele, genutzte MCP-Server und Werkzeuge, gestartete Subagenten
- Welche Daten haben das Gerät in Richtung eines Modellanbieters oder eines Dritten
  verlassen
- Wurden Schutzmechanismen umgangen: Berechtigungsmodi, automatisch zustimmende Hooks,
  überschriebene verwaltete Einstellungen
- Wurden anti-forensische Schritte unternommen: verkürzte Aufbewahrung, unterdrückte
  Historie, gelöschter Projektzustand
- Wurde der Agent durch eingeschleuste Anweisungen manipuliert

Jede Antwort ist auf eine Quelldatei, einen Hash und eine Zeilen- oder Byte-Position
zurückführbar und hält damit auch stand, wenn sie im Bericht angezweifelt wird.

## Warum Zeit eine Rolle spielt

Mehrere Agenten löschen ihre Historie selbst und nach Zeitplan. Claude Code entfernt
Transkripte, die älter sind als die Einstellung `cleanupPeriodDays`, standardmässig 30
Tage, und Gemini CLI verwendet ebenfalls 30 Tage als Vorgabe. Eine Untersuchung, die in
Woche sechs beginnt, hat Woche eins bereits verloren. Der Artefaktkatalog hält diese
Flüchtigkeit pro Artefakt fest, damit klar ist, was zuerst gesichert werden muss, und
die Kollektoren sind genau deshalb einzelne Dateien ohne Abhängigkeiten: so lassen sie
sich in Minuten über Live-Response-Werkzeuge ausrollen und nicht erst nächste Woche
einplanen.

## Entwurfsvorgaben

Das sind keine Vorlieben, sondern der Grund, weshalb das Werkzeug so aussieht, wie es
aussieht.

| Vorgabe | Was das praktisch bedeutet |
| --- | --- |
| Offline | Kein Netzzugriff zur Laufzeit, keine Telemetrie, keine Update-Prüfung, und nirgends im Ablauf ein LLM- oder API-Aufruf. Die Analyse ist deterministisch und erklärbar. Die Web-UI bindet ausschliesslich an `127.0.0.1`. |
| Beweismittel nur lesend | Kollektor und Analyzer verändern, verschieben, umbenennen oder löschen niemals ein Quellartefakt und führen auf dem Zielsystem nie eine Agenten-Binary aus. Versionsangaben werden aus Dateien gelesen. |
| Überprüfbar | Jede gesammelte Datei wird mit SHA-256 gehasht und trägt ihre originalen Zeitstempel. Bundles lassen sich offline verifizieren. Die Chain of Custody ist eine Hash-Kette und damit manipulationssichtbar. |
| Deterministisch | Gleiche Eingabe, gleiche Ausgabe. Stabile Sortierung überall, Zeitstempel in UTC nach ISO 8601, die Zeitzone des Endgeräts einmal im Manifest festgehalten. |
| Plattformübergreifend | Kollektoren und Analyzer laufen auf macOS, Windows und Linux. Windows-Laufwerksbuchstaben, lange Pfade, Junctions und Gross-Klein-Unempfindlichkeit werden ausdrücklich behandelt, nicht hoffnungsvoll ignoriert. |
| Wenige Abhängigkeiten | Eine Analyse-Workstation kann vom Netz getrennt sein. Die Kollektoren haben gar keine Abhängigkeiten, der Analyzer hält sie minimal und permissiv lizenziert. |
| Nichts Organisationsspezifisches | Nichts in diesem Repository nennt eine Firma, eine Domain, einen Host, einen Projektnamen oder eine Person. Scope-Regeln kommen aus der eigenen, per gitignore ausgeschlossenen Konfiguration. |

## Der Transkript-Viewer

`viewer/index.html` ist eine einzelne HTML-Datei ohne Abhängigkeiten, die
Agenten-Sitzungsprotokolle nur lesend darstellt, in einer Oberfläche, die der
Terminalausgabe von Claude Code nachempfunden ist. Sie funktioniert vollständig
eigenständig, ohne Installation und ohne Backend. Das ist Absicht: so lässt sie sich auf
einem USB-Stick mitnehmen und auf einem Rechner öffnen, auf dem nichts installiert
werden darf.

### Unterstützte Protokoll-Layouts

| Agent | Standardort | Layout | Format |
| --- | --- | --- | --- |
| Claude Code | `~/.claude/projects/` | `projects/<dir>/<uuid>.jsonl` | ein JSON-Ereignis pro Zeile |
| OpenAI Codex CLI | `~/.codex/sessions/` | `sessions/YYYY/MM/DD/rollout-*-<uuid>.jsonl` | `{timestamp,type,payload}` pro Zeile |
| GitHub Copilot CLI | `~/.copilot/session-state/` | `session-state/<id>/events.jsonl` | `{type,id,timestamp,data}` pro Zeile |
| Beliebiger Agent, über ein vereinheitlichtes Log | eine Datei, irgendwo | ein Datensatz pro Zeile | [das vendorneutrale Format](docs/UNIFIED_FORMAT.de.md) |

Die Erkennung prüft jedes Layout direkt und zusätzlich unter `.claude/`, `.codex/` und
`.copilot/`. Zeigt man den Viewer also auf eines dieser Verzeichnisse oder auf ein
übergeordnetes Verzeichnis, das mehrere davon enthält, erscheinen die Sitzungen aller
Agenten gemeinsam.

Die letzte Zeile ist der allgemeine Fall. Ein vereinheitlichtes Agenten-Log ist eine
Datei mit normalisierten Datensätzen beliebiger Agenten, erzeugt entweder durch
`afx normalize <quelle>` oder durch das Velociraptor-Artefakt
`Custom.Forensics.AIAgents.UnifiedLog`, das auf dem Endpunkt parst und Zeilen statt
Dateien zurückgibt. Der Viewer gruppiert ein solches Log nach Agent, Arbeitsverzeichnis
und Sitzung, sodass eine Sammlung über viele Hosts und mehrere Agenten als ein Satz von
Sitzungen aufgeht. Datensätze, die zu keiner Sitzung gehören, etwa ein Prompt aus einer
Verlaufsdatei oder ein Speicher, den niemand geparst hat, erhalten eine eigene Gruppe
statt weggelassen zu werden.

### Starten

**A. Ein Agentenverzeichnis lokal ausliefern.**

```bash
cd ~/.claude   # oder ~/.codex, ~/.copilot, oder ein übergeordnetes Verzeichnis
python3 -m http.server 8000
# dann http://localhost:8000/index.html öffnen
```

Dazu `viewer/index.html` vorher in dieses Verzeichnis kopieren, oder das Repository
ausliefern und im Browser `viewer/index.html` öffnen.

**B. Die einzelne Datei hosten und einen Ordner auswählen.** Auf **Open local folder**
in der Seitenleiste klicken und das eigene `.claude`-, `.codex`- oder
`.copilot`-Verzeichnis wählen. Das nutzt die
[File System Access API](https://caniuse.com/native-filesystem-api) des Browsers und
braucht einen Chromium-basierten Browser (Chrome, Edge, Brave, Arc, Opera) in einem
sicheren Kontext, also `https://` oder `http://localhost`. Eine `file://`-Seite erfüllt
das nicht, dort blendet sich die Schaltfläche selbst aus. Firefox und Safari
implementieren die API nicht.

**C. Ein vereinheitlichtes Agenten-Log öffnen.** In der Seitenleiste unten auf
**Open unified log** klicken und eine `.jsonl`-Datei auswählen. Das ist die Variante, die
überhaupt nichts braucht: keinen Server, keinen Verzeichniszugriff, und sie funktioniert
von einer `file://`-Seite. Wer ein Log aus einer Flottensammlung hat, öffnet also diese
Seite und diese Datei und liest. Es ist außerdem der einzige Weg, einen Agenten zu sehen,
für den der Viewer kein Layout kennt, denn das Normalisieren ist passiert, bevor die Datei
geschrieben wurde.

**D. Auf eine Falldatenbank zeigen.** `afx serve --case case.db` legt einen Fall hinter
dieselbe Seite, auf 127.0.0.1 und nur lesend, und ergänzt vier Ansichten für die Fragen, die
einen Fall statt ein Transkript betreffen. Siehe [die lokale Web-UI](#die-lokale-web-ui).

Kein Build-Schritt, kein `npm install`, kein Backend. Alles läuft im Browser. Das
Einzige, was der Viewer irgendwo schreibt, ist die Themenwahl in `localStorage`.

### Was der Viewer zeigt

- **Sitzungen**, nach Projekt gruppiert, neueste zuerst, mit dem echten Sitzungstitel und
  einem farbigen Punkt für den ursprünglichen Client
- **Ein getreues Transkript**: Benutzereingaben, gruppierte Assistenten-Züge,
  ausklappbare Denkblöcke, Markdown, und `Tool(summary)`-Einzeiler mit Ergebnisvorschau
- **Volle Werkzeugdetails** auf Abruf: vollständige JSON-Eingabe und ungekürzte
  Ausgabe, pro Zug oder für das ganze Transkript
- **Zwei Suchfelder mit klarem Geltungsbereich**, eines nur über Nachrichtentext, eines
  über alles einschliesslich Werkzeugeingaben, -ausgaben und Denkblöcke, mit
  Hervorhebung im Text, Trefferzähler, Tastaturnavigation und automatischem Aufklappen
  jedes eingeklappten Blocks, der einen Treffer enthält
- **Werkzeugnutzung über alle Sitzungen**: jeder Werkzeugaufruf aus jeder Sitzung in
  einer filterbaren Liste
- **Ein heuristischer Secret-Scan** über Werkzeugeingaben, Werkzeugausgaben und
  Assistententext, der wahrscheinliche Schlüssel, Tokens und Zugangsdaten markiert
- **Jeder Datensatz, immer.** Eine Zeile, die sich nicht parsen lässt, ein Datensatztyp,
  den der Parser nicht kennt, ein Assistenten-Zug ohne Kennung: alles davon wird als
  eigene, sichtbare Zeile dargestellt statt verworfen, und der Sitzungskopf zählt die
  nicht parsbaren Zeilen mit. In einem Forensikwerkzeug ist stilles Nichts schlimmer als
  eine Fehlermeldung, weil daraus geschlossen wird, es sei nichts da gewesen.

### Bekannte Grenzen

- Der Verzeichnislisten-Modus versteht den HTML-Index, den Pythons `http.server`
  ausgibt. Autoindex-Formate anderer Server werden nicht geparst. Dort Modus B, C oder D
  verwenden.
- Das Parsen passiert im Browser, eine sehr grosse Sitzung wird also komplett in den
  Speicher geladen.
- Der Secret-Scan besteht aus Heuristiken auf Basis regulärer Ausdrücke, nicht aus
  einem vollwertigen Scanner. Fehlalarme und übersehene Funde sind zu erwarten, jeder
  Fund gehört geprüft.
- Die Parser für Codex und Copilot entstanden aus öffentlichen Formatbeschreibungen.
  Sie erhalten alles, was sie nicht erkennen, brauchen aber möglicherweise Anpassungen
  an neue Agentenversionen.

## Die lokale Web-UI

```bash
uv run afx ingest /evidence/bundle-2026-09-17 --case case.db   # eine Sammlung einlesen
uv run afx scan --case case.db                                 # die Regelpakete laufen lassen
uv run afx serve --case case.db                                # im Browser öffnen
```

`serve` bindet ausschliesslich an `127.0.0.1`, öffnet den Fall nur lesend, sodass SQLite
selbst das Schreiben verweigert, und legt jede URL unter ein Token, das für diesen Lauf
erzeugt und auf der Konsole ausgegeben wird. Keine Telemetrie, kein Update-Check, und eine
Content-Security-Policy, die der Seite verbietet, irgendetwas ausserhalb dieses Servers zu
laden oder zu kontaktieren.

Ausgeliefert wird derselbe Einzeldatei-Viewer, ergänzt um vier Ansichten: den Fall samt den
Zahlen, die ihn relativieren, die geräteweite Timeline über alle Agenten, die Regel-Funde,
und jede Datei, die die Sammlung mitgebracht hat, gelesen oder nicht.

![Die Fall-Ansicht mit den relativierenden Zahlen](docs/images/webui-case.png)

Der ausführliche Durchgang, die API und die übrigen Screenshots stehen in
[docs/WEBUI.de.md](docs/WEBUI.de.md). Alle Bilder dort zeigen einen synthetischen Fall:
echte Agentendaten kommen in diesem Repository nirgends vor.

## Fahrplan

| Phase | Inhalt | Stand |
| --- | --- | --- |
| 0 | Repository-Hygiene, bereinigter Viewer, Werkzeugkette, CI, OpSec-Wächter | fertig |
| 1 | Artefaktkatalog, beide Kollektoren, Bundle-Format, `verify`, synthetische Testdaten | fertig |
| 2 | Generierte Sammelregeln für Velociraptor, KAPE, Defender Live Response, KQL, osquery | fertig |
| 3 | Analyzer-Kern: Ingest-Adapter, Parser pro Agent, einheitliches Ereignismodell, SQLite-Falldatenbank, vereinheitlichtes Logformat, Timeline-Exporte | laufend |
| 4 | Deklarative YAML-Regel-Engine und die ersten Regelpakete | fertig |
| 5 | Lokale Web-UI: nur lesende API, API-Quelle im Viewer, Ansichten für Fall, Timeline, Funde und Artefakte | fertig |

Vorerst nicht geplant: Fallverwaltung mit Triage-Status, Berichte als HTML und PDF,
Pseudonymisierung, und ein Shell-Kollektor als Rückfallebene.

## Dokumentation

- [docs/ARCHITECTURE.de.md](docs/ARCHITECTURE.de.md), wie die Teile zusammenspielen
- [docs/COLLECTION.de.md](docs/COLLECTION.de.md), was zuerst zu sichern ist und warum,
  und wie eine Sicherung läuft
- [docs/ARTIFACTS.de.md](docs/ARTIFACTS.de.md), die generierte Artefaktreferenz,
  gruppiert danach, wie schnell ein Artefakt verschwindet
- [docs/BUNDLE_FORMAT.de.md](docs/BUNDLE_FORMAT.de.md), das Format des Beweismittel-Bundles
- [docs/RULES.de.md](docs/RULES.de.md), die generierte Erkennungsreferenz: jede Regel
  mit ihrer Bedingung, warum sie für die Analyse zählt, und den harmlosen Fällen, auf
  die sie bekanntermaßen feuert
- [docs/UNIFIED_FORMAT.de.md](docs/UNIFIED_FORMAT.de.md), das vendorneutrale Agenten-Log:
  ein JSON-Lines-Datensatz pro Ereignis, egal welcher Agent die Spuren hinterlassen hat
  und egal welches Werkzeug sie liest
- [docs/WEBUI.de.md](docs/WEBUI.de.md), die lokale Web-UI: was `afx serve` bereitstellt,
  was es ausdrücklich nicht tut, und Screenshots jeder Ansicht
- [docs/adr/](docs/adr/), je ein kurzer Eintrag pro Architekturentscheidung, mit der
  Begründung und dem Preis, den sie in Kauf nimmt (englisch)
- [CONTRIBUTING.de.md](CONTRIBUTING.de.md), wie in diesem Repository gearbeitet wird,
  einschliesslich des OpSec-Wächters, den jede mitarbeitende Person verstehen muss
- [SECURITY.de.md](SECURITY.de.md), wie eine Schwachstelle gemeldet wird, und die
  Haltung zur Dual-Use-Problematik

## Lizenz

MIT, siehe [LICENSE](LICENSE).
