# Das vereinheitlichte Agenten-Log

Ein Format für die Spuren beliebiger KI-Coding-Agenten auf der Platte, damit die Frage
"was hat der Agent getan" eine Antwort derselben Form hat, egal welcher Agent die Spuren
hinterlassen hat und egal welches Werkzeug sie liest.

Das Schema liegt unter `src/agentforensics/unified/agentlog.v1.schema.json`. Absichtlich als
Datei und nicht als Definition im Python-Paket: eine Velociraptor-Abfrage, ein CI-Schritt
oder ein fremdes Skript kann dagegen prüfen, indem es einen Pfad liest, ohne irgendetwas zu
installieren.

## Wozu es da ist

Die Suite führt bereits zwölf Agenten mit zwölf Transkriptformaten auf ein Event-Modell
zusammen und legt es in einer SQLite-Falldatenbank ab. Das ist die richtige Form für einen
Gutachter, der eine Woche an einem Gerät arbeitet. Für drei andere Situationen ist es die
falsche Form, und diese drei sind die häufigen:

- Ein Flotten-Hunt kommt mit tausend Hosts zurück, und jemand will die Konversationen, nicht
  tausend Datenbanken.
- Die Normalisierung soll auf dem Endpunkt passieren, im Sammelwerkzeug, das dort schon
  läuft, damit nichts auf den Endpunkt gebracht werden muss und nur das geparste Ergebnis
  zurückkommt.
- Der Viewer soll das Zurückgekommene im Browser öffnen, ohne Server.

Alle drei wollen einen Strom von Datensätzen statt einer Datenbank, und alle drei wollen
denselben Strom. Das ist er.

## Form

JSON Lines. Ein Datensatz pro Zeile, ein Ereignis pro Datensatz. Es gibt keinen Dateikopf
und keine verlangte Reihenfolge, deshalb gilt:

- Zwei Logs lassen sich zu einem gültigen dritten aneinanderhängen, und genau das ist das
  Zusammenführen einer Flottensammlung.
- Ein Produzent, der Zeilen statt Dateien ausgibt, und das ist eine Velociraptor-Abfrage,
  kann das Format direkt erzeugen, weil jeder Datensatz seine eigene Version trägt.
- Ein Leser kann bei Zeile eins beginnen, ohne zu springen, und überall aufhören.

Ein knapper Datensatz, die langen Felder zum Lesen gekürzt:

```json
{
  "v": 1,
  "agent": "claude_code",
  "kind": "tool.call",
  "event_id": "9a445f697549b88dafa699957a7a3f66",
  "ts_utc": "2026-09-06T09:00:03.000Z",
  "ts_precision": "exact",
  "ts_source": "timestamp",
  "actor": "assistant",
  "client": "cli",
  "user": "alice",
  "session_id": "4f8c1e2a-0000-4000-8000-000000000001",
  "project_path": "/src/app",
  "git_branch": "main",
  "payload": {
    "tool": "Bash",
    "tool_use_id": "t1",
    "input": { "command": "npm ci" },
    "commands": [{ "command": "npm ci", "executable": "npm", "cwd": "/src/app" }]
  },
  "parse_problem": null,
  "provenance": {
    "bundle_uuid": "tree-2a8021959fa27c7f6df59aaa",
    "original_path": "/Users/alice/.claude/projects/-src-app/4f8c1e2a.jsonl",
    "sha256": "b10f318452866...",
    "artifact_id": "claude_code.transcripts",
    "locator": "line:12"
  },
  "raw": { "type": "assistant", "message": { "content": [{ "type": "tool_use" }] } },
  "producer": "agentforensics/0.1.0"
}
```

## Die Zusagen

Das sind die Gründe, dieses Format und nicht irgendeine CSV zu nehmen, und jede Zusage ist
ein Test in `tests/unit/test_unified_format.py`.

**Der Agent ist immer genannt.** `agent` ist Pflicht und hat keinen Standardwert. Ein
Ereignis, das keinem Agenten zugeordnet werden kann, ist weniger wert als kein Ereignis,
weil es trotzdem mitgezählt wird.

**Nichts geht verloren.** `raw` ist Pflicht und enthält den Originaldatensatz wörtlich. Ein
Abbildungsfehler kostet damit Interpretation und keine Beweise: was ein Produzent falsch
gemacht hat, steht im Original derselben Zeile noch zum Nachlesen. Ein Ereignis übersteht
den Rundlauf durch das Format Feld für Feld, und dieser Test hält die Zusage ehrlich.

**Nichts wird versteckt.** Ein Datensatz, den ein Produzent nicht lesen konnte, wird mit
`kind: "unparsed.record"` geschrieben, dem Original in `raw` und dem Grund in
`parse_problem`. Das Lesen ist genauso vollständig: eine Zeile eines Unified-Logs, die kein
gültiges JSON ist, kommt als Ereignis zurück, das die ganze Zeile enthält. Ein Leser, der
eine kaputte Zeile überspringt, lässt ein manipuliertes Log sauber aussehen, und in einem
forensischen Werkzeug führt "nichts anzeigen" dazu, dass ein Analyst auf "da war nichts"
schließt.

**Zeit ist qualifiziert oder nicht vorhanden.** `ts_utc` ist null, wenn der Datensatz keine
eigene Zeit trug, und `ts_precision` sagt, wie viel vom Zeitstempel echt ist. Weder die
Einlesezeit noch die Änderungszeit der Datei wird je als eigene Zeit des Ereignisses
ausgegeben. `ts_source` nennt die Herkunft der Zeit, damit ein Analyst die Uhr des Agenten
von der des Dateisystems unterscheiden kann.

**Jeder Datensatz ist nachverfolgbar.** `provenance` trägt die Sammlung, den absoluten Pfad
auf dem Endpunkt, den Hash der Quelldatei und die Position darin. Genau daran wird ein
Bericht angegriffen.

**Die Kennung ist prüfbar, nicht vertrauenswürdig.** `event_id` wird aus Provenienz und Art
abgeleitet, ein Leser rechnet sie also nach. Findet er eine Abweichung, hält er die
Uneinigkeit fest statt sie zu korrigieren: welcher Produzent eine Datei gelesen hat und ob
er mit uns übereinstimmt, ist selbst ein Befund. `producer` nennt, was den Datensatz
normalisiert hat.

## Ereignisarten

Das Vokabular ist geschlossen und agentenneutral: eine Art benennt, was passiert ist, nicht
in welchem Agenten es passiert ist, damit eine Abfrage für alle funktioniert.

| Art | Was sie ist |
| --- | --- |
| `session.start`, `session.end` | Anfang und Ende einer Konversation. Eine Verdichtung beendet eine Sitzung auch und sagt das im Payload. |
| `user.prompt` | Was der Nutzer gefragt hat. |
| `assistant.text`, `assistant.thinking` | Was der Agent geantwortet hat, und seine Überlegungen, wo der Agent sie festhält. |
| `tool.call`, `tool.result` | Ein Werkzeugaufruf mit seinen Argumenten, und seine Ausgabe. Verbunden über `payload.tool_use_id`. |
| `file.read`, `file.write`, `file.snapshot` | Was der Agent angefasst hat, abgeleitet aus dem Werkzeugaufruf. |
| `command.exec` | Ein Shell-Befehl, den der Agent ausgeführt hat. |
| `network.request` | Ein Ziel, das der Agent erreicht hat. |
| `mcp.call` | Ein Aufruf in einen MCP-Server, wobei der Server getrennt vom Werkzeug benannt ist. |
| `permission.decision` | Eine Anfrage, entschieden nach den geltenden Regeln. |
| `permission.change` | Eine Änderung der Regeln selbst. Getrennt, weil sie die andere Hälfte der Umgehungsfrage beantwortet: wer hat die Torpfosten verschoben, und wann. |
| `safety.refusal` | Das Modell lehnt ab. Verschieden von einer verweigerten Berechtigung: dort sagt die Umgebung nein, hier das Modell. |
| `config.snapshot` | Konfiguration, wie sie war, einschließlich Modellwechsel mitten in einer Sitzung. |
| `instruction.source` | Eine Anweisung, die auf dem Endpunkt in Kraft war: eine CLAUDE.md, ein Skill, ein Output Style, eine Regeldatei, ein Hook-Skript. Getrennt von `config.snapshot`, weil eine Einstellung und ein Text, dem das Modell folgen sollte, zwei verschiedene Aussagen sind und nur die zweite die Frage nach eingeschleusten Anweisungen beantwortet. Source, nicht prompt: der Basisprompt des Herstellers liegt nicht auf dem Endpunkt, das hier ist also der Teil eines Systemprompts, der Beweis sein kann, und nie das Ganze. |
| `memory.write`, `plan.write` | Der Agent schreibt in seinen eigenen dauerhaften Zustand. |
| `prompt.history` | Ein Prompt aus einer Verlaufsdatei statt aus einem Transkript. Diese überleben Transkripte, weshalb ein Prompt ohne passende Sitzung zu den interessanteren Dingen gehört, die eine Sammlung enthalten kann. |
| `artifact.fs` | Die Dateisystem-Zeitstempel einer Artefaktdatei selbst. Bei einem Artefakt ohne interne Zeitstempel ist das der einzige zeitliche Beweis, und es ist auch das, was eine gesammelte Datei ohne Parser auf die Zeitachse bringt. |
| `unparsed.record` | Ein Datensatz, den nichts lesen konnte, behalten mit seinem Originaltext. |

## Payload-Vokabular

`payload` trägt das Geschehen in Feldern, die eine Abfrage erreicht. Zusätzliche Schlüssel
sind bewusst erlaubt: ein agentenspezifisches Feld, das noch niemand abgebildet hat, gehört
dorthin und nicht ins Nichts. Die gemeinsamen Schlüssel sind `text`, `tool`, `tool_use_id`,
`input`, `output`, `is_error` sowie die Listenfelder `files`, `commands`, `network`, `mcp`,
`models`, `permissions` und `instructions`. Das Schema dokumentiert jedes einzeln.

Zwei Anmerkungen zur Ehrlichkeit im Payload. `text` wird nie gekürzt, denn ein
abgeschnittener Prompt liest sich wie ein kurzer Prompt. Und `permissions[].decision` ist
absichtlich keine geschlossene Liste: das gemeinsame Vokabular ist `allow`, `deny`,
`always_allow`, `ask` und `unknown`, aber ein Agent, dessen Datensätze ein anderes Wort
verwenden, behält dieses Wort, statt in eines unserer gepresst zu werden. Ein solches
Pressen würde genau die Unterscheidung zerstören, nach der ein Analyst sucht.

## Erzeugen

```bash
# Aus einem Bundle, einem gesammelten Baum, einer KAPE-Ausgabe oder einem gemounteten Profil
afx normalize <quelle> --out agents.jsonl

# Direkt vom Endpunkt, innerhalb einer Velociraptor-Sammlung
# (siehe docs/COLLECTION.de.md)
```

`afx normalize` liest über dieselben Quelladapter und dieselben Parser wie `afx ingest`. Das
ist Absicht: zwei Codepfade, die beide behaupten, das Log eines Agenten zu normalisieren,
wären irgendwann bei einem uneinig, und es gäbe keine Möglichkeit festzustellen, welcher
recht hat. Ein Test prüft, dass das Log und ein aus derselben Quelle gebauter Fall genau
dieselben Ereignisse enthalten.

Die Zusammenfassung geht immer nach stderr, damit ein nach stdout geschriebenes Log ein
sauberer Strom bleibt und die Zahlen, die es einschränken, den Bediener trotzdem erreichen.
Diese Zahlen sind der Punkt:

```
normalize: unified agent log, format version 1
normalize: directory source /evidence/host-1
normalize:   39 file(s): 9 parsed, 30 with no parser, 0 that failed
normalize:   112 record(s) written
normalize:   by agent: claude_code 81, cline 2, codex 14, copilot 11
normalize:   15 record(s) no parser could read, written to the log as unparsed.record
normalize:   30 file(s) were collected and have no parser. They are in the log as one
normalize:   artifact.fs record each, which says the file was there and when it was
normalize:   written, and nothing about its content.
normalize:   3 path(s) no catalogue entry claims, which is a lead rather than a non-event
```

Die Rückgabewerte folgen dem Rest des Werkzeugs: 0 für einen sauberen Lauf, 1 wenn die
Sammlung Pfade trug, die kein Katalogeintrag beansprucht, 3 wenn überhaupt nichts gefunden
wurde. Ein Host ohne Agenten-Artefakte ist eine gültige und nützliche Antwort und darf nicht
wie ein Absturz aussehen.

## Lesen

Drei Konsumenten, und keiner braucht einen Server.

**Der Viewer.** `viewer/index.html` öffnen und in der Seitenleiste unten auf
**Open unified log** klicken. Der Viewer gruppiert ein Log nach Agent, Arbeitsverzeichnis
und Sitzung, sodass eine Sammlung über viele Hosts und mehrere Agenten als ein Satz von
Sitzungen aufgeht, und alles, was er schon kann, die Transkriptdarstellung, die
Werkzeugübersicht und die Suche nach Zugangsdaten, funktioniert unverändert. Eine
`file://`-Seite genügt: kein Server, kein Verzeichniszugriff.

Datensätze ohne eigene Sitzung werden nicht weggelassen. Ein Prompt aus einer Verlaufsdatei,
eine Datei, die niemand geparst hat, eine Zeile des Logs, die selbst nicht geparst hat:
jedes bekommt eine eigene Gruppe, denn ein Leser muss einen Agenten, der nichts
hinterlassen hat, von Beweisen unterscheiden können, die niemand gelesen hat.

Zwei Dinge, nach denen es sich zu suchen lohnt. Eine Ablehnung des Modells ist eine eigene
Zeile, damit die Frage "wurde etwas abgelehnt" beantwortbar ist, ohne jeden
Assistenten-Zug zu lesen. Und eine Änderung des Berechtigungsmodus ist eine eigene Zeile,
denn das ist die Hälfte der Umgehungsfrage, die sagt, wer die Torpfosten verschoben hat und
wann.

**Der Analyzer.** `afx` liest ein vereinheitlichtes Log zurück in Ereignisse und rechnet
`event_id` aus der Provenienz jedes Datensatzes neu. Eine Abweichung zur Kennung des
Produzenten wird festgehalten statt korrigiert, was der Produzent als unlesbar gemeldet hat
bleibt erhalten, und was er grob gelassen hat wird verfeinert: die Endpunkt-Abfrage gibt
eine Zeile pro Datensatz zurück, und aus dem `raw` dieser Zeile entsteht die vollständige
Deutung pro Zug. Genau das macht die Grobheit des Endpunkt-Produzenten zu einer Frage der
Deutung und nicht der Beweise.

**Alles andere.** Es ist JSON Lines mit einem veröffentlichten Schema, also lesen es `jq`,
ein SIEM oder das Skript einer Kollegin ohne diese Suite. Prüfen gegen
`src/agentforensics/unified/agentlog.v1.schema.json`.

## Versionierung

`v` ist eine ganze Zahl und steht auf jedem Datensatz. Version 1 ist das, was dieses
Dokument beschreibt. Eine künftige Version, die ein Feld hinzufügt, ist weiterhin Version 1,
denn ein Konsument, der einen unbekannten Schlüssel ignoriert, funktioniert weiter, und das
Schema erlaubt zusätzliche Payload-Schlüssel von Anfang an. Die Zahl ändert sich nur, wenn
ein bestehendes Feld seine Bedeutung ändert, und das ist der einzige Fall, in dem ein
Konsument es wissen muss.
