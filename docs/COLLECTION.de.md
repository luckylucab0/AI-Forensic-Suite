# Agentenartefakte sichern

[English](COLLECTION.md) | Deutsch

Das hier vor einer Sicherung lesen, nicht danach. Die Reihenfolge ist wichtiger als die
Vollständigkeit: mehrere dieser Artefakte werden durch die normale Benutzung des Rechners
zerstört, und einige sind weg, sobald er sauber herunterfährt.

Der Einsatz setzt eine ordentliche Befugnis voraus. Siehe die README.

## Das Eine, worauf es ankommt

Agenten löschen ihre Historie selbst. Claude Code entfernt Transkripte, die älter sind als
`cleanupPeriodDays`, standardmässig 30 Tage, und dieser Aufräumlauf startet **beim
Programmstart**. Das heisst: das nächste Öffnen des Agenten zerstört die ältesten Spuren.
Gemini CLI verwendet ebenfalls 30 Tage als Vorgabe. Manche Artefakte sind schlimmer: der
Bildcache von Claude Code entfernt bei **jedem** Aufräumlauf die Verzeichnisse aller
Sitzungen ausser der aktuellen, unabhängig vom Alter. Eine neue Sitzung zu starten kann
also alle angehängten Bilder im Baum sofort vernichten.

Der Katalog hält deshalb nicht nur fest, wo etwas liegt. Jedes Artefakt trägt eine
`collect_priority`, und die Kollektoren arbeiten in dieser Reihenfolge statt alphabetisch.
Die generierte Referenz [ARTIFACTS.de.md](ARTIFACTS.de.md) ist genauso gruppiert.

| Priorität | Was sie bedeutet | Was zu tun ist |
| --- | --- | --- |
| `live_only` | Existiert nur, solange Agent oder Sitzung laufen, oder wird beim saubern Herunterfahren gelöscht | Am laufenden Rechner sichern. Ein abgeschaltetes Abbild hat es nicht, und keine Datenträgerforensik holt es zurück |
| `first` | Rotiert oder verfällt aggressiv, nach Anzahl oder bei jedem Aufräumlauf statt nach einer bequemen Frist | Vor allem sichern, was länger überlebt. Einiges davon zerstört die Benutzerin schon, indem sie eine weitere Sitzung startet |
| `normal` | Unterliegt der üblichen Aufbewahrungsfrist des Agenten | Im normalen Ablauf sichern |
| `durable` | Vom Aufräumlauf nicht erfasst | Trotzdem sichern. Diese Gruppe überlebt regelmässig die Transkripte, die sie beschreibt, und wenn die Transkripte schon weg sind, genügt sie oft, um zu belegen, dass ein Agent lief, was er durfte und was gefragt wurde |

Zwei Folgerungen, die man aussprechen sollte. Erstens: läuft das Endgerät noch, ist eine
Live-Sicherung keine Bequemlichkeit, sondern der einzige Weg zur `live_only`-Gruppe.
Zweitens: eine Sicherung, die nur `durable`-Artefakte zurückbringt, ist keine gescheiterte
Sicherung. Sie bedeutet, dass die flüchtigen Spuren schon verfallen waren, und das ist
selbst ein Befund darüber, wie lange die Untersuchung gebraucht hat, um anzulaufen.

## Was die Kollektoren nicht tun

- Sie verändern, verschieben, benennen oder löschen auf dem Zielsystem nie etwas und
  führen nie eine Agenten-Binary aus. Versionsangaben werden aus Dateien gelesen.
- Sie schreiben ausschliesslich in `--out`. Keine temporären Dateien anderswo, keine
  Protokolle, keine Konfiguration.
- Sie kopieren den Inhalt von Zugangsdaten-Artefakten nicht. Die werden als Metadaten samt
  SHA-256 erfasst, ihr Vorhandensein und ihre Identität stehen also im Manifest, ohne dass
  das Bundle zu einer Sammlung lebender Tokens wird. `--include-secrets` hebt das auf, und
  diese Entscheidung wird im Manifest festgehalten.
- Sie folgen keinem Symlink aus dem gesicherten Profil hinaus. Ein solcher Link wird mit
  seinem Ziel festgehalten und übersprungen.

## Eine Sicherung ausführen

macOS und Linux, Python 3.8 oder neuer, nur Standardbibliothek:

```bash
# Die aktuelle Benutzerin, auf diesem Rechner
python3 collect.py --out /tmp/case-001

# Alle Profile, braucht erhöhte Rechte. Ob der Lauf erhöht war, wird in jedem Fall
# festgehalten, ein unerhöhtes --all-users ergibt also eine ehrlich unvollständige
# Sicherung statt einer stillschweigenden.
sudo python3 collect.py --out /tmp/case-001 --all-users --zip

# Ein eingebundenes Abbild oder ein exportiertes Profil, auf der Analyse-Workstation
python3 collect.py --out ./bundle --root /mnt/evidence --os macos

# Anzeigen, was gesichert würde, ohne zu lesen oder zu schreiben
python3 collect.py --dry-run --json
```

Windows, PowerShell 5.1 oder neuer, ohne Module: `collect.ps1` bietet dieselben Optionen
als PowerShell-Parameter, aus `--out` wird also `-Out`, aus `--all-users` `-AllUsers`, aus
`--dry-run` `-DryRun` und aus `--os` `-TargetOs`.

```powershell
# Der Normalfall: das Profil der angemeldeten Person
powershell -ExecutionPolicy Bypass -File collect.ps1 -Out C:\case-001

# Alle Profile der Maschine. Braucht eine erhöhte Sitzung, was das Manifest festhält
powershell -ExecutionPolicy Bypass -File collect.ps1 -Out C:\case-001 -AllUsers -Zip

# Ein eingebundenes Abbild, auf einer Analyse-Workstation gesammelt
powershell -ExecutionPolicy Bypass -File collect.ps1 -Out .\bundle -Root E:\ -TargetOs windows

# Anzeigen, was gesammelt würde, ohne zu lesen und ohne zu schreiben
powershell -ExecutionPolicy Bypass -File collect.ps1 -DryRun -Json
```

Beide Collectors erzeugen dasselbe Bundle-Format, und die CI weist das nach statt es zu
behaupten: beide laufen über ein synthetisches Profil, und ihre Manifeste werden Feld für
Feld verglichen, wobei nur die Felder unter "Felder, die zwischen den beiden Collectors
abweichen dürfen" in `docs/BUNDLE_FORMAT.de.md` normalisiert werden. `collect.ps1
-SelfTest` gibt einen festen Satz Strukturen durch den eigenen JSON-Serialisierer aus, und
die CI vergleicht die auf echtem Windows PowerShell 5.1 Byte für Byte mit dem Ergebnis von
Pythons `json.dumps`.

Die Rückgabewerte sind Teil der Schnittstelle, denn das wird aus Skripten und aus
Live-Response-Sitzungen aufgerufen, wo der Rückgabewert das einzige Signal ist:

| Wert | Bedeutung |
| --- | --- |
| 0 | Mindestens ein Artefakt gesichert |
| 1 | Gelaufen, aber mindestens ein Fehler steht im Manifest |
| 2 | Konnte nicht laufen: falsche Argumente, Ausgabeverzeichnis unbenutzbar |
| 3 | Erfolgreich gelaufen und nichts gefunden |

Wert 3 zählt für eine flottenweite Erhebung. „Dieses System hat keine Agentenartefakte" ist
eine nützliche Antwort, und eine Erhebung, die das nicht von einem Abbruch unterscheiden
kann, zeichnet ein falsches Bild davon, wo Agenten im Einsatz sind.

## Den Baum finden, wenn er verschoben wurde

Mehrere Agenten lassen sich über eine Umgebungsvariable verlegen. `CLAUDE_CONFIG_DIR`
verschiebt das gesamte Claude-Code-Verzeichnis samt Transkripten, Eingabehistorie und
Plugins. Eine Sicherung, die auf den Standardort schaut, findet dann nichts, und nichts
unterscheidet das davon, dass der Agent nie installiert war.

Die Kollektoren lösen solche Variablen aus ihrer eigenen Umgebung auf. Das ist auf einem
laufenden Rechner richtig und auf einem eingebundenen Abbild falsch, denn dort stand die
Variable in einem Shell-Profil, das jetzt nur eine Datei ist. Auf einem Abbild also die
Shell-Profile und etwaige Prozessumgebungs-Spuren prüfen, bevor man auf die Abwesenheit
eines Agenten schliesst. [ARTIFACTS.de.md](ARTIFACTS.de.md) listet die verschiebenden
Variablen je Agent.

## Projektdateien müssen erst gefunden werden

Instruktionsdateien (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`,
`.kiro/steering/` und weitere) liegen in den Repositories der Benutzerin und nicht unter
dem Profil. Sie sind ausserdem die Oberfläche, über die eingeschleuste Anweisungen einen
Agenten erreichen, was sie zu den interessantesten Dateien einer Sicherung macht.

Der Kollektor kann sie nicht durch Auflösen eines Profils finden, also liest er den Zustand
des Agenten selbst nach einer Liste von Arbeitskopien: für Claude Code ist der
`projects`-Schlüssel in `~/.claude.json` die verbindliche Quelle, und die kodierten
Verzeichnisnamen unter `projects/` sind ein Rückfallhinweis. Diese Kodierung ersetzt jedes
nicht alphanumerische Zeichen durch einen Bindestrich und ist nicht umkehrbar, ein
dekodierter Name wird also nur verwendet, wenn er zufällig ein existierendes Verzeichnis
benennt.

Die Folge: ein Repository, das geklont und nie mit einem Agenten geöffnet wurde, wird nicht
gefunden, und von einem gelöschten Repository bleibt nur der kodierte Verzeichnisname. Beides
gehört in den Bericht, statt die Liste als vollständig zu behandeln.

## Ein entferntes Produkt ist keine saubere Maschine

Zwei der Produkte in diesem Katalog wurden auf einem sauberen Windows-Rechner und einem
sauberen macOS-Rechner installiert, einmal benutzt und dann so entfernt, wie ein Mensch
Software entfernt: unter Windows über den eigenen Deinstallationsweg des Produkts, unter
macOS durch Löschen der Anwendung. Unter macOS bringt keines der beiden überhaupt einen
Deinstallationsweg mit.

Übrig blieben danach 376 Megabyte auf dem Windows-Rechner und rund 700 auf dem macOS-Rechner.
Keine Fragmente: sämtliche Transkripte, der Volltextindex über die Unterhaltungen, beide
Zustandsdatenbanken samt ihren Kontoschlüsseln, die Geräte-Kennungen, die
Telemetrie-Zeitstempel für erste und letzte Nutzung, die Liste zuletzt geöffneter Pfade und
die Verzeichnisnamen, die Projektpfade im Klartext tragen. Eine Deinstallation dieser
Produkte entfernt das Programm und vom Inhalt nichts.

Für eine Untersuchung ist das der Normalfall und nicht die Ausnahme. Grenzen Sie eine
Sicherung nicht auf Rechner ein, auf denen das Produkt gerade installiert ist, und lesen Sie
das Fehlen eines Programmverzeichnisses nicht als Fehlen von Spuren. Genau deshalb sucht die
Anwesenheitsprüfung unter `exporters/generated/` nach Daten und nicht nach einer
Installation.

Wo jemand bewusst aufgeräumt hat, überleben drei Dinge das Aufräumen:

- Unter Windows der URL-Protokoll-Handler, den jedes Produkt unter den Klassenschlüsseln des
  Benutzers registriert. Der Deinstallationsweg entfernt den Uninstall-Schlüssel und lässt
  den Handler auf eine ausführbare Datei zeigen, die es nicht mehr gibt. Ein einziger
  Schlüssel belegt damit sowohl die Installation unter diesem Konto als auch die spätere
  Entfernung. Die Benutzer-Pfadvariable verhält sich genauso.
- Unter macOS die Registrierungsdatenbank der Startdienste, die noch einundzwanzig Einträge
  zu zwei Produkten enthielt, deren Anwendungsbündel, Zwischenspeicher, Einstellungsdomänen
  und Schlüsselbundeinträge sämtlich entfernt waren. Ihre Einträge verschwinden erst beim
  Neuaufbau der Datenbank.
- Unter macOS der generische Schlüsselbundeintrag, den jedes Produkt für seinen sicheren
  Speicher anlegt. Er hängt nicht am Anwendungsbündel, also entfernt das Löschen der
  Anwendung ihn nicht.

## Eine Suche nach dem Namen findet das meiste nicht

Aus denselben Messungen kamen drei Namensfallen, und jede davon kostet einen Auswerter ein
ganzes Produkt.

Eine Bundle-Kennung ist kein Produktname. Einer der Editoren in diesem Katalog wird über eine
Verpackungsplattform ausgeliefert, seine Kennung enthält daher weder den Namen des
Herstellers noch den des Produkts, und sie ist das Einzige, worüber sich seine
Zwischenspeicher, sein Netzwerkspeicher und seine Einstellungsdomäne ansprechen lassen. Eine
Suche nach dem Produktnamen findet das Benutzerverzeichnis und unterhalb von `~/Library`
nichts.

Eine Umbenennung benennt die Daten nicht um. Der zweite Editor wurde umbenannt, und seine
Bundle-Kennung, sein Konfigurationsverzeichnis, seine Anmeldeschlüssel, seine
Auslieferungsdomäne und eines seiner drei URL-Schemata tragen weiterhin den früheren
Firmen- und Produktnamen. Eine Suche nach dem aktuellen Namen verfehlt die größere Hälfte der
Spuren, und der alte Name auf einem Rechner ist kein Beleg dafür, dass das alte Produkt dort
je installiert war.

Ein Produktname kann Teil von etwas Harmlosem sein. Sucht man in einer Dateiliste nach einem
dieser Produktnamen, trifft man ein Verzeichnis für Inhaltsentschlüsselung, das mehrere
Browser mitbringen und das mit keinem Agenten zu tun hat. Verankern Sie das Muster an einer
Pfadkomponente, statt irgendwo in der Zeichenkette zu suchen, sonst enthält schon die
Grundaufnahme eines sauberen Rechners Treffer.

## Ein Bundle verifizieren

```bash
agentforensics verify /tmp/case-001
agentforensics verify /tmp/case-001 --json
```

Die Verifikation leitet jeden Hash neu aus den Bytes auf der Platte ab und meldet drei
verschiedene Dinge, weil sie Verschiedenes bedeuten: eine Datei, die das Manifest führt und
das Bundle nicht hat; eine Datei, deren Bytes nicht mehr passen; und eine Datei im Bundle,
die kein Manifesteintrag beansprucht. Zusätzlich prüft sie die Custody-Kette.

Die Custody-Kette ist **manipulationssichtbar, nicht manipulationssicher**. Sie liegt in
einem beschreibbaren Verzeichnis, und wer sie schreiben kann, kann die ganze Kette neu
schreiben. Was sie bringt, ist, dass ein einzelner Datensatz nicht unbemerkt entfernt oder
verändert werden kann. Siehe [BUNDLE_FORMAT.de.md](BUNDLE_FORMAT.de.md).

## Ausrollen über andere Werkzeuge

Der Katalog wird auch in die Formate übersetzt, die andere Werkzeuge schon sprechen, damit
man ihn nutzen kann, ohne den Collector dieser Suite einzuführen. Die Ausgabe ist unter
`exporters/generated/` eingecheckt, und CI schlägt fehl, wenn sie vom Katalog abweicht, aus
demselben Grund wie beim eingebetteten Katalog in den Collectors: eine Regel, die dem
Katalog nachläuft, sucht an den Orten des letzten Monats und meldet einen sauberen Host.

```bash
uv run agentforensics export-collection            # alle Formate, nach exporters/generated
uv run agentforensics export-collection --format kape --out /tmp/rules
```

| Format | Was dabei herauskommt | Wofür |
| --- | --- | --- |
| `velociraptor` | Drei Artefakte: ein Sammelartefakt, das die Katalogpfade globt und Fundstellen hochlädt, ein Präsenzartefakt nur mit Metadaten, und ein Unified-Log-Artefakt, das auf dem Endpunkt parst und die Konversation als Zeilen zurückgibt | Alles plattformübergreifende. Seine Glob-Sprache liegt dem Katalog am nächsten, also hat es die wenigsten Lücken |
| `kape` | Ein `.tkape` pro Agent plus ein Sammelziel | Eine Windows-Auswertung, die ohnehin in KAPE stattfindet |
| `mde` | Ein Präsenz-Skript und ein Runbook | Eine Defender-Live-Response-Sitzung, Host für Host |
| `kql` | Advanced-Hunting-Abfragen über Datei- und Prozessereignisse | Eine Flotte aus der Konsole eingrenzen, bevor ein Host angefasst wird |
| `osquery` | Ein Pack mit Dateiabfragen pro Agent und Plattform | Eine Flotte, die osquery schon betreibt. Nur Metadaten, also Triage statt Sicherung |

### Velociraptor: die Dateien holen, oder die Konversation zurückgeben

Die drei Velociraptor-Artefakte beantworten drei verschiedene Fragen, und ein Hunt, der die
falsche stellt, holt entweder Gigabytes von jedem Endpunkt oder kommt mit nichts zurück.

`Custom.Forensics.AIAgents.Presence` meldet, welche Agenten eine Spur hinterlassen haben, und
lädt nichts hoch. Damit fängt man in einer Flotte an: die Frage "wer hat einen KI-Coding-Agenten
benutzt" ist aus der Existenz von Verzeichnissen beantwortbar, und sie durch das Hochladen
jedes Transkripts im Bestand zu beantworten ist langsam und schafft ein Datenschutzproblem,
das es vorher nicht gab.

`Custom.Forensics.AIAgents.Collect` lädt die Dateien hoch. Das ist für einen Host, an dem man
arbeiten wird; das Ergebnis liest `afx ingest`, und daraus kommen die Falldatenbank, die
Zeitachse und die vollständige Deutung pro Zug.

`Custom.Forensics.AIAgents.UnifiedLog` liest die Agenten-Logs dort, wo sie liegen, und gibt sie
als Zeilen im vendorneutralen Format aus, das in
[docs/UNIFIED_FORMAT.de.md](UNIFIED_FORMAT.de.md) beschrieben ist. Es wird nichts hochgeladen
und nichts auf den Endpunkt gebracht. Das nimmt man, wenn man die Konversationen vieler Hosts
auf einmal will, oder wenn das Hochladen von Transkripten nicht in Frage kommt.

Alle drei fragen zuerst nach einem `Ticket`: das Ticket, für das gesammelt wird, und ein
allfälliger Kommentar, als ein Freitextfeld. Velociraptor speichert es mit den Parametern der
Sammlung, also wird es mit der Sammlung angezeigt und mit ihr exportiert. In die Ergebnisse
wird es nicht geschrieben, damit das vereinheitlichte Format unverändert bleibt.

Was das Unified-Log-Artefakt bewusst weniger tut, hier genannt, weil ein Sammelwerkzeug, das
stillschweigend weniger tut als es scheint, schlimmer ist als eines, das scheitert:

- **Eine Zeile pro Datensatz, nie pro Inhaltsblock.** Ein Assistenten-Zug mit drei
  Werkzeugaufrufen ist eine Zeile. Der vollständige Datensatz reist in `raw` mit, es geht also
  nichts verloren; ein erneutes Lesen des Logs mit dem Analyzer dieser Suite zerlegt ihn
  weiter. Grob ist die Deutung, nicht der Beweis.
- **Es deutet die fünf Formate, die gegen ihren Hersteller gelesen wurden**: Transkript und
  Prompt-Verlauf von Claude Code, Rollout und Prompt-Verlauf von Codex, und das Ereignis-Log
  der Copilot CLI. Jedes andere zeilenweise Agenten-Log kommt Datensatz für Datensatz mit der
  Art `unparsed.record` zurück, denn eine für ein unverifiziertes Format erfundene Abbildung
  erzeugt Ausgaben, die wie eine Antwort aussehen.
- **Es liest keine SQLite-Speicher, JSON-Dokumente oder binären Sitzungsdateien.** Die kommen
  als je eine `artifact.fs`-Zeile zurück, mit Pfad, Hash und Zeitstempeln, damit ein Speicher,
  den niemand gelesen hat, als genau das sichtbar ist und nicht als ein Agent, der nichts
  hinterlassen hat.
- **Es prüft sein eigenes Lesen.** Velociraptors Zeilenleser arbeitet mit einem Puffer, und
  eine Zeile, die länger ist als der Puffer, beendet den Durchlauf und nimmt den Rest der
  Datei mit. Agenten-Transkripte enthalten Zeilen von mehreren Megabyte, sobald eine
  Werkzeugausgabe groß war, deshalb vergleicht das Artefakt die gelesenen Bytes mit der
  Dateigröße und gibt einen Datensatz zurück, wenn das nicht aufgeht. Dann `MaxLineSize`
  erhöhen und erneut sammeln.
- **Es benutzt `parse_jsonl` nicht.** Dieses Plugin überspringt eine Zeile, die es nicht
  dekodieren kann. Eine übersprungene Zeile liest sich wie eine Zeile, die es nie gab, und
  genau dahinter würde sich ein abgeschnittener oder absichtlich beschädigter Datensatz
  verstecken. Das Artefakt dekodiert die Zeilen deshalb selbst und gibt die zurück, die es
  nicht lesen konnte.

Zum Prüfen braucht es eine Velociraptor-Binärdatei, die dieses Repository nicht mitliefert.
`scripts/check_velociraptor_vql.py --velociraptor <binärdatei>` führt das Artefakt gegen ein
synthetisches Profil in einer Sandbox aus, validiert jede Zeile gegen das Schema des Formats
und vergleicht die zurückgegebenen Datensätze mit denen, die `afx normalize` aus demselben
Profil liest. Die CI hat dafür einen eigenen Job, der eine Release-Binärdatei herunterlädt
und alle drei plattformspezifischen Quellen des Artefakts ausführt. `--runner <programm>`
nimmt alles andere, das eine VQL-Datei und einen Ausgabepfad annimmt, etwa einen lokalen Bau
der VQL-Bibliothek. Ohne beides tut es nichts und sagt das, sodass das Skript in einer
Pipeline ohne Engine stehen kann.

Derselbe Lauf führt auch das Präsenz- und das Sammelartefakt gegen dieselbe Sandbox aus. Ihre
Datensätze vergleicht er nicht, denn nur das vereinheitlichte Log hat Datensätze zum
Vergleichen, aber er lässt jedes der beiden scheitern, das keine Zeilen zurückgibt, eine Zeile
ohne Agent liefert oder einen Pfad von ausserhalb der Sandbox. Früher wurde überhaupt nur das
vereinheitlichte Log ausgeführt, und beide anderen wurden mit einer Abfrage ausgeliefert, deren
Schleife nie lief: Sie gaben auf jedem Host nichts zurück, was genau so aussieht wie ein Host
ohne Agent.

Die Sandbox ist der Teil dieses Skripts, den man kennen sollte. Die ganze Aufgabe eines
Sammelartefakts ist es, Agentendaten zu finden, wo sie liegen; unverändert ausgeführt würde
es also die Maschine lesen, auf der es läuft. Jeder Glob des Artefakts wird in ein
Verzeichnis umgeschrieben, das nichts als ein synthetisches Profil enthält, und ein Pfad von
aussen bringt den Lauf zum Scheitern, statt hinterher herausgefiltert zu werden. Ein Test
prüft das Umschreiben in beide Richtungen: eine Profilwurzel, die ausserhalb der Sandbox
geblieben ist, und eine Wurzel, die in ihre eigene Ausgabe hinein umgeschrieben wurde, was
ein Pfad ist, der in der Sandbox liegt und ins Nichts zeigt.

Die statischen Prüfungen in `tests/unit/test_velociraptor_unified.py` laufen überall und bei
jedem Commit.

### Was eine generierte Regel nicht kann, und warum sie es sagt

Jedes dieser Werkzeuge hat eine engere Pfadsprache als der Katalog. KAPE adressiert ein
Laufwerk und eine Dateimaske. osquery hat eine Wildcard-Tiefe pro Segment. Advanced Hunting
sieht Ereignisse statt des Dateisystems und hat überhaupt keinen Platzhalter für das
Benutzerprofil. Live Response holt eine Datei nur über ihren exakten Namen.

Deshalb trägt jede generierte Datei im eigenen Kopf die Artefakte, die sie nicht ausdrücken
konnte, samt Grund. Lesen Sie diesen Abschnitt, bevor Sie die Ergebnisse lesen. Die
wiederkehrenden Gründe:

- **An einer Arbeitskopie verankert.** Eine Projekt-Instruktionsdatei liegt in einem
  Repository, dessen Ort in der Zustandsdatei des Agenten steht. Nichts Statisches findet
  sie. Das ist die größte Gruppe, und sie umfasst genau die Dateien, um die es bei einer
  Injection-Frage geht.
- **Nur über eine Verschiebungsvariable erreichbar.** Der Baum des Agenten wurde per
  Umgebungsvariable verschoben, sein Ort ist also, was die Variable sagt. Ein Agent
  schreibt ein komplettes zweites Transkript an einen Pfad, den der Betreiber wählt.
- **Ein Registry-Schlüssel**, den jedes dieser Werkzeuge ansprechen kann und keine dieser
  generierten Regeln anspricht.
- **Plattformumfang.** KAPE und das Live-Response-Paket sind nur Windows, und sie sagen,
  wie viel des Katalogs damit außer Reichweite liegt.

Der Collector liest alle vier, den vierten nur zum Teil. Eine Arbeitskopie, eine
Verlagerungsvariable und ein nur unter Windows existierender Pfad sind Dateisystemfragen,
die er ganz beantwortet. Ein Registry-Schlüssel ist kein Pfad, und er wird von einem
eigenen Durchgang beantwortet: auf einem laufenden Windows-Host lesen beide Collectors vier
der sechs Registry-Einträge des Katalogs und schreiben jeden Schlüssel als JSON-Dokument
ins Bundle (ADR 0033). Das sind die vier, nach denen kein allgemeines Registry-Werkzeug zu
suchen weiss, darunter die verwaltete Richtlinie, die sagt, was ein Agent durfte, und die
unter Windows allein in der Registry stehen kann, ganz ohne Datei. Die anderen beiden sind
die Ausführungsspuren der Plattform selbst und die Persistenzschlüssel eines Installers:
sie werden namentlich abgelehnt, erscheinen in `refused_patterns` als `registry_key` und
bleiben Beweismaterial, das jemand mit der Registry-Fähigkeit des ohnehin laufenden
Werkzeugs holt, das diese Arbeit besser macht als dieses hier.

Aus einem gemounteten Abbild wird nichts davon gelesen, denn ein Hive braucht einen Parser,
den diese Suite nicht hat, und die Einträge sagen `registry_needs_a_live_host`, statt wie
fehlende Schlüssel auszusehen. Keine generierte Sammelregel deckt einen Registry-Schlüssel
ab, was jede von ihnen im eigenen Kopf sagt.

Für die anderen drei ist das die ehrliche Arbeitsteilung: eine generierte Regel findet die
Hosts, die man ansehen muss, der Collector holt die Beweise.

Ein leeres Ergebnis aus einer dieser Regeln bedeutet, dass an den durchsuchten Pfaden nichts
lag. Es bedeutet nicht, dass der Host sauber ist, und jede generierte Datei widerspricht
diesem Schluss in ihrem Kopf, weil die Person, die die Regel ausführt, oft nicht die Person
ist, die sie generiert hat.
