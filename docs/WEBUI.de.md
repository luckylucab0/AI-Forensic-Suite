# Die lokale Web-UI

`afx serve` legt einen Fall hinter den Transcript-Viewer, auf 127.0.0.1, nur lesend. Das ist
die Ansicht für die Phase einer Untersuchung, in der die Frage nicht mehr "was steht in
diesem Transcript" lautet, sondern "was ist auf diesem Gerät passiert, über alle Agenten
hinweg, und was haben die Regeln gefunden".

Der Viewer selbst bleibt unverändert. Er ist weiter die einzelne HTML-Datei, die eine
Analystin auf einem USB-Stick mitnehmen und auf einem Rechner öffnen kann, auf dem nichts
installiert werden darf, und er liest weiter ein Verzeichnis voller Transcripts oder ein
einzelnes vereinheitlichtes Log ganz ohne Server. Von `afx serve` ausgeliefert bekommt er
eine dritte Datenquelle und sechs zusätzliche Ansichten, und sonst verschiebt sich nichts.

## Der Weg dorthin

```bash
# 1. eine Sammlung in einen Fall einlesen
uv run afx ingest /evidence/bundle-2026-09-17 --case case.db

# 2. die Regelpakete darüber laufen lassen, damit die Fundansicht etwas zu sagen hat
uv run afx scan --case case.db

# 3. ausliefern
uv run afx serve --case case.db
```

Der dritte Befehl gibt etwa das aus:

```
serve: case case.db, opened read-only
serve: viewer sha256 4f2c...e91b
serve: open http://127.0.0.1:8765/Xq3nK9vP2sM7wL4tR8yB6aZc/
serve: the path holds a one-time access token for this run. Nothing is served without it,
       and it changes when this command is restarted.
serve: bound to 127.0.0.1 only. No network access, no telemetry. Ctrl-C to stop.
```

Die ausgegebene URL öffnen, samt Token. Unter `http://127.0.0.1:8765/` liegt nichts.

`--port 0` lässt das System einen freien Port wählen, der genauso ausgegeben wird.
`--access-log` protokolliert jede Anfrage auf stderr; standardmäßig aus, weil eine
Anfragezeile das Zugangstoken enthält und ein Terminal-Scrollback ein Ort ist, an dem ein
Token zurückbleibt.

## Was sie nicht tut

Die Sicherheitshaltung ist kein Nebenprodukt, deshalb hier ausdrücklich. Ein Fall enthält
die Prompts anderer Leute, den Inhalt von Dateien, die ein Agent gelesen hat, und manchmal
Zugangsdaten, die in eine Konversation kopiert wurden. Ein lokaler HTTP-Server ist von
jedem Prozess auf der Workstation erreichbar und über den Browser von jeder Seite, die die
Analystin offen hat.

- Der Socket bindet an `127.0.0.1`, und es gibt keine Option, das zu ändern.
- Jede URL liegt unter einem Token, das für diesen Lauf erzeugt wird. Eine Seite, die im
  Browser der Analystin schon offen ist, kann den Fall nicht durch Erraten des Ports lesen.
- Eine Anfrage, deren `Host`-Header nicht Loopback nennt, wird abgewiesen. Genau das
  verhindert DNS-Rebinding: eine feindliche Seite kann ihren eigenen Namen auf 127.0.0.1
  auflösen, sendet in diesem Header aber weiter ihren eigenen Namen.
- Eine Cross-Origin-Anfrage wird abgewiesen.
- Es gibt nur `GET` und `HEAD`. Eine Anfrage, die einen Body ankündigt, wird abgewiesen,
  ohne gelesen zu werden.
- Es gibt eine explizite Tabelle aus Methode und Pfad und keinen Fallback-Handler. Ein
  unbekannter Pfad ist ein 404, nie eine Datei.
- Nichts wird über einen Pfad aus dem Dateisystem ausgeliefert. Der Viewer ist eine
  Byte-Kette, die beim Start einmal gelesen wird, also gibt es keinen Pfad zum Traversieren
  und kein Verzeichnis zum Auflisten.
- Eine Content-Security-Policy mit `default-src 'none'` und `connect-src 'self'` verbietet
  der Seite, irgendetwas außerhalb dieses Servers zu laden oder zu kontaktieren.
- Der Fall wird über eine `mode=ro`-Verbindung geöffnet, also verweigert SQLite selbst das
  Schreiben, statt dass dieser Code verspricht, es nicht zu versuchen.

Jeder Punkt dieser Liste ist durch einen Test in `tests/unit/test_webui.py` festgenagelt,
denn [ADR 0006](adr/0006-standard-library-web-server.md) sagt ausdrücklich, dass eine
handgepflegte Härtungsliste der Teil ist, der am ehesten verrottet.

## Die Ansichten

Die drei Ansichten des eigenständigen Viewers bleiben unverändert: **Sessions** zeigt eine
Konversation, **Tools** listet jeden Tool-Aufruf über alle hinweg, und **Security** ist der
eingebaute Regex-Scan nach Zugangsdaten im Transcript-Text.

Ein ausgelieferter Fall ergänzt sechs weitere, und das sind Fragen an einen Fall, nicht an
ein Transcript:

**Case** zeigt, was der Fall enthält und was ihm fehlt. Zuerst die Zahlen, die eine
Analystin zuerst liest, dann die, die sie relativieren: gesammelte Dateien, die kein Parser
gelesen hat, Datensätze, die niemand parsen konnte, Ereignisse ohne Zeitstempel und Lücken,
die die Sammlung selbst gemeldet hat. Danach ein Block pro Sammlung mit Endpunkt, Sammler,
Zeiten, der eigenen Zeitzone des Endpunkts und dem Manifest-Hash, und zuletzt die Herkunft
der Seite selbst, samt Hash des ausgelieferten Viewer-HTML.

**Timeline** ist jedes Ereignis des Falls in einer Folge, über alle Agenten hinweg.
Ereignisse ohne Zeitstempel stehen vorn statt zu fehlen: ihre Position ist unbekannt, nicht
früh. Filter nach Agent, oder die Dateisystem-Ereignisse beiseitelegen, von denen es eines
pro Datei gibt und die in einer großen Sammlung die Konversation überzählen. Ein Klick auf
eine Zeile öffnet das Ereignis in seiner Session.

**Findings** zeigt, was die Regelpakete gefunden haben. Wenn kein Scan gelaufen ist, sagt
die Ansicht das ausdrücklich, denn sonst sehen ein ungescannter und ein sauberer Fall gleich
aus, und das sind entgegengesetzte Schlüsse. Jeder Fund nennt seine Regel, sein Paket, was
gematcht hat und die Ereignisse, auf denen er beruht; ein Klick darauf öffnet das Ereignis.

**Instructions** ist der Anweisungsbestand: alles, dem die Agenten folgen sollten, so wie es
auf dem Endpunkt stand. Eine Zeile pro Datei, mit dem Scope, in dem sie galt, den Werkzeugen,
die ein Skill sich selbst zuspricht, der Angabe, ob sie ausgeführt statt gelesen wird, und
einer Zählung der Zeichen, die ein Prüfer nicht sehen konnte. Ein Klick zeigt den Text, und
bei einer Datei mit unsichtbaren Zeichen wird er mit jedem davon markiert angezeigt, denn
genau darum geht es: ein Mensch hat einen Text genehmigt und das Modell hat einen anderen
gelesen. Eine Aussage lässt die Ansicht niemanden übersehen: das ist kein Systemprompt. Jeder
Agent hier baut seinen Prompt zur Laufzeit aus einem Basisprompt, der ins Produkt kompiliert
ist oder vom Hersteller geholt wird, und dieser Teil berührt den Endpunkt nie, liegt also
nicht im Fall. Im Fall liegt alles, was hineininjiziert wird.

Die Scope-Spalte liest man zuerst. `managed` ist die Datei einer Administration und gilt für
jeden Benutzer. `project` kam mit einem Checkout, was heisst: wer einen Pull Request öffnen
kann, konnte sie dort ablegen. `local` ist die dokumentierte persönliche Übersteuerung
innerhalb einer Arbeitskopie. `user` ist die des Profils selbst. `unknown` heisst, dass die
Sammlung keine Arbeitskopien festgehalten hat, eine Projektdatei also nicht von einer
Profildatei zu unterscheiden ist, und die Zeile sagt das, statt zu raten: das sind
entgegengesetzte Befunde darüber, wer den Agenten angewiesen hat.

**Conversations** stellt die Speicher eines Agenten einander gegenüber. Mehrere Agenten
halten eine Konversation an mehr als einer Stelle: einen Transcript-Speicher und einen
Seitenleisten-Index, eine Rollout-Datei und die Datenbank, die sie projiziert, eine
Prompt-Historie und die Sitzung, zu der sie gehört. Die Ansicht listet je Agent, welche
seiner Speicher überhaupt Konversationen benennen und worüber jedes Paar von ihnen einig
ist, und danach die Konversationen, an die sich nur ein Speicher erinnert. Sie ist die eine
Ansicht über etwas, das nicht da ist, und genau deshalb gibt es sie: Ein Parser sieht einen
Datensatz und eine Regel ein Ereignis oder deren Anzahl, und keiner von beiden kann eine
Konversation sehen, die den einen Speicher erreicht hat und den anderen nicht.

Drei Einschränkungen reisen mit, und die Ansicht nennt alle drei, statt sie als bekannt
vorauszusetzen. Schweigen ist eine Spur und kein Befund: Ein Speicher hat eine Konversation
womöglich nie gehalten, weil er nur indexiert, was geöffnet wurde, oder weil die beiden von
verschiedenen Generationen desselben Produkts geschrieben wurden. Verglichen wird über die
Sitzungs-Id, so wie jeder Speicher sie schreibt, und ein Paar ohne eine einzige gemeinsame
Konversation benutzt weit eher zwei Id-Räume, als dass jede einzelne verloren wäre; die
Zeile zum Paar sagt, wonach es aussieht. Und verglichen werden nur Speicher, die im Fall
sind: Ein Speicher, den niemand gesammelt hat, kann nicht schweigen, er fehlt, und dafür
ist die Artifacts-Ansicht da.

**Artifacts** ist jede Datei, die die Sammlung mitgebracht hat, gelesen oder nicht. Das ist
die Ansicht, die alle anderen relativiert, und der Unterschied, für den sie existiert, ist
der zwischen einer Datei, die niemand gesammelt hat, und einer, die gesammelt und nie
gelesen wurde. Das sind verschiedene Lücken mit verschiedenen Gegenmitteln, und ein Fall,
dessen Ereignisse aus einem dieser Gründe dünn sind, sagt nichts über die Nutzung des
Agenten aus.

## Filter

Sechs der Ansichten filtern, und alle folgen einer Regel: ein Filter darf Zeilen vom
Schirm nehmen, weil jemand danach gefragt hat, und er darf sie niemals abwesend aussehen
lassen. Jede gefilterte Ansicht sagt deshalb, wie viele Zeilen ausserhalb des Blickfelds
sind, und der Filter innerhalb eines Chats hält Zahl und Rücknahme sichtbar, solange er
gesetzt ist.

**Innerhalb eines Chats** zeigt eine Reihe von Chips über dem Transkript nur die Prompts,
nur die Antworten, nur die Züge mit Werkzeugaufruf, nur die festgehaltenen Überlegungen oder
nur die Zeilen, die sich nicht parsen liessen. Jeder Chip trägt die Zahl der Zeilen, die er
zeigen würde, sodass die Form einer Konversation lesbar ist, bevor man klickt. Der Filter
behält ganze Züge: ein Assistentenzug, der überlegt, geantwortet und ein Werkzeug gerufen
hat, ist eine Zeile und bleibt bei allen drei Chips erhalten. Deshalb heisst der Chip
"tool use" und nicht "tool calls".

**Ein Zeitfenster** liegt in der Chip-Reihe über dem Transkript und in der Timeline, und
beide Grenzen bedeuten an beiden Orten dasselbe. Ein blosses Datum meint den ganzen Tag, denn
`2026-09-06` als obere Grenze hiesse sonst Mitternacht und nähme den Tag aus seinem eigenen
Fenster. Eine Grenze, die der Viewer nicht lesen kann, wird neben dem Feld gemeldet und nicht
angewendet: ein unlesbares Fenster, das stillschweigend alles zeigt, wäre ein Filter, der über
seinen eigenen Inhalt täuscht.

Ein Ereignis ohne Zeitstempel bleibt in jedem Fenster. Seine Position ist unbekannt, nicht
ausserhalb, und es wegzulassen würde aus "was an jenem Tag geschah" ein "was an jenem Tag
geschah, abzüglich dessen, was keine Uhr hatte" machen. Die Zahl sagt, wie viele Zeilen aus
diesem Grund erhalten blieben, und genau das erklärt ein Fenster, das scheinbar nichts tut.
Die Timeline wendet das Fenster in der Falldatenbank an und nicht im Browser, sodass eine
lange Timeline vor dem Blättern eingegrenzt wird und der Bildschirm mit
`afx timeline --since --until` übereinstimmt.

**Die Sessionliste** filtert auf die Sitzungen, in denen eine Regel etwas gefunden hat, und
auf die Sitzungen mit einem Datensatz, den kein Parser lesen konnte. Beides sind Fragen an
die Verlässlichkeit des Falls und nicht an seinen Inhalt, und das Zweite ist der Grund für
den Filter: in einem grossen Fall verschwindet eine Handvoll unlesbarer Datensätze in einer
Gesamtzahl, und genau die muss eine Analystin ansehen, bevor sie den Rest zitiert. Jede
Sessionzeile trägt dieselben zwei Markierungen, sodass die Behauptung des Chips ohne Klick
überprüfbar ist. Die Chips erscheinen nur, wenn ein Fall ausgeliefert wird, denn ein
Verzeichnis voller Transcripts weiss nichts über Funde.

**Über Sitzungen hinweg** beginnen die Werkzeug- und die Sicherheitsansicht mit einem
Bereichsschalter: alle Sitzungen oder die geöffnete. "This session" erscheint nur, wenn eine
Sitzung offen ist, denn ein Bereich, der stillschweigend "alle" bedeutet, wäre ein Filter,
der über seinen eigenen Inhalt täuscht. Die Werkzeugansicht filtert danach nach Werkzeug,
nach nur Fehlschlägen und nach freiem Text über Werkzeugname, Zusammenfassung und Sitzung.
Die Sicherheitsansicht filtert nach Schweregrad und Regel. Die Anweisungsansicht filtert nach
Scope und nach "worth a look", also nach jeder Datei, die Werkzeuge zuspricht, Zeichen
verbirgt, ausgeführt statt gelesen wird oder ihren Prompt in einem JSON-Feld hält.

![Ein Chat, gefiltert auf die Züge mit Werkzeugaufruf, mit der Zahl der ausgeblendeten Zeilen](images/webui-filter.png)

## Die API

Elf Routen, alle `GET`, alle unter dem Token des Laufs. Sie stehen hier, weil eine
Analystin, die gegen einen bereits offenen Fall skriptet, nicht den Quellcode lesen sollte.

| Pfad | Antwortet mit |
| --- | --- |
| `/` und `/index.html` | dem Viewer, aus dem Speicher |
| `/api/case` | Zahlen, Sammlungen, Agenten, Ereignisarten, Lücken, Scan-Läufe |
| `/api/projects` | den abgeleiteten Sessions, gruppiert wie die Seitenleiste sie zeigt |
| `/api/sessions/<key>/events` | einer Seite einer Session, als vereinheitlichtes Log |
| `/api/events/<event_id>` | einem Ereignis, als vereinheitlichtem Datensatz |
| `/api/timeline` | einer Seite der geräteweiten Timeline, in der Zeilenform des Exports |
| `/api/findings` | den Funden, und der Tatsache, dass ein Scan gelaufen ist |
| `/api/instructions` | dem Anweisungsbestand, mit seinen Scopes und dem, was einen Blick wert ist |
| `/api/corroboration` | welcher Speicher eines Agenten welche Konversation benennt und welcher dazu schweigt |
| `/api/artifacts` | jeder Datei, die die Sammlung mitgebracht hat, und den Lücken |
| `/api/health` | dass dies ein `afx serve` ist |

Eine Session- oder Timeline-Seite nimmt `offset` und `limit`. Eine Session-Seite kündigt den
nächsten Offset im Header `X-Afx-Next-Offset` an, statt die Datensätze in einen Umschlag zu
packen; so bleibt ihr Body ein vereinheitlichtes Log, das eine Analystin direkt in eine
Datei speichern und mit `afx scan` wieder einlesen kann. Die Timeline nimmt `agent`, `kind`,
`since`, `until`, `session` und `no_fs`, dieselben Filter wie `afx timeline`.

Jede JSON-Antwort trägt `afx_api`, die API-Version. Der Viewer prüft darauf, um überhaupt zu
erkennen, ob hinter der Seite ein Fall liegt, und verweigert eine Version, für die er nicht
geschrieben wurde, statt die Felder anzuzeigen, die er zufällig erkennt.

## Was ein Session-Key ist

Ein Fall enthält Ereignisse, keine Sessions. Was die Seitenleiste eine Session nennt, ist
eine Gruppe von Ereignissen mit sechs gemeinsamen Werten: Agent, Host, Benutzer, ob es
Dateisystem-Zeitstempel statt einer Konversation sind, Arbeitsverzeichnis und Session-ID.
Der Key in der URL ist ein Hash genau dieser sechs, also erzeugt derselbe Fall immer
dieselben Keys, und ein in einen Bericht kopierter Link öffnet dieselbe Session auch, wenn
der Fall aus demselben Bundle neu gebaut wurde.

Zwei Folgen sind wissenswert. Eine Gruppe ohne Session-ID ist eine echte Gruppe und kein
Fehler: ein Prompt aus einer History-Datei gehört irgendwohin, und ihn weglassen würde ihn
unsichtbar machen. Und die Dateisystem-Ereignisse bekommen eine eigene Gruppe, weil sie für
eine Datei ohne interne Zeitstempel die einzige zeitliche Evidenz sind und eine Konversation
begraben würden, wenn sie darin auftauchten.

Zu der Frage, warum das Wire-Format das vereinheitlichte Log ist und der Key abgeleitet
statt gespeichert wird, siehe
[ADR 0020](adr/0020-the-case-is-read-as-a-unified-log.md).

## Screenshots

Alle Bilder zeigen denselben synthetischen Fall, erzeugt von `tests/fixtures/generate.py`
und in eine Falldatenbank eingelesen. Echte Agentendaten kommen in diesem Repository
nirgends vor, auch nicht in diesen Bildern.

Das Transcript, die ursprüngliche Ansicht des Viewers, jetzt mit einer Session aus einem
Fall:

![Die Session-Ansicht, mit einer Session aus einem Fall](images/webui-sessions.png)

Der Fall selbst: was er enthält, und darunter die Zahlen, die sagen, was er nicht weiß.

![Die Fall-Ansicht mit den relativierenden Zahlen](images/webui-case.png)

Die Timeline, alle Agenten in einer Folge. Die Zeilen mit hervorgehobener Zeitspalte haben
überhaupt keinen Zeitstempel und stehen deshalb vorn.

![Die geräteweite Timeline](images/webui-timeline.png)

Die Funde, jeder mit seiner Regel und den Ereignissen, auf denen er beruht.

![Die Regel-Funde](images/webui-findings.png)

Die Artefakte, gefiltert auf die Dateien, die ein Parser nicht verstanden hat. Diese Liste
entscheidet, wie viel die anderen Ansichten wert sind.

![Die Artefaktliste](images/webui-artifacts.png)

Der Anweisungsbestand, gefiltert auf die Dateien, die einen Blick wert sind:

![Der Anweisungsbestand](images/webui-instructions.png)

Die Konversationen, mit den Speichern jedes Agenten einander gegenübergestellt. In diesem
Fall ist jeder Speicher mit seinem Geschwister einig, und so sieht ein Fall aus, in dem
nichts fehlt:

![Konversationen über Speicher hinweg](images/webui-corroboration.png)
