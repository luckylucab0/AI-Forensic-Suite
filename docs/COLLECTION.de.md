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
| `velociraptor` | Ein Sammelartefakt, das die Katalogpfade globt und Fundstellen hochlädt, plus ein Präsenzartefakt nur mit Metadaten | Alles plattformübergreifende. Seine Glob-Sprache liegt dem Katalog am nächsten, also hat es die wenigsten Lücken |
| `kape` | Ein `.tkape` pro Agent plus ein Sammelziel | Eine Windows-Auswertung, die ohnehin in KAPE stattfindet |
| `mde` | Ein Präsenz-Skript und ein Runbook | Eine Defender-Live-Response-Sitzung, Host für Host |
| `kql` | Advanced-Hunting-Abfragen über Datei- und Prozessereignisse | Eine Flotte aus der Konsole eingrenzen, bevor ein Host angefasst wird |
| `osquery` | Ein Pack mit Dateiabfragen pro Agent und Plattform | Eine Flotte, die osquery schon betreibt. Nur Metadaten, also Triage statt Sicherung |

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
- **Ein Registry-Schlüssel**, der in jedem Werkzeug eine andere Tabelle oder ein anderer
  Zieltyp ist.
- **Plattformumfang.** KAPE und das Live-Response-Paket sind nur Windows, und sie sagen,
  wie viel des Katalogs damit außer Reichweite liegt.

Der Collector liest alle vier. Das ist die ehrliche Arbeitsteilung: eine generierte Regel
findet die Hosts, die man ansehen muss, der Collector holt die Beweise.

Ein leeres Ergebnis aus einer dieser Regeln bedeutet, dass an den durchsuchten Pfaden nichts
lag. Es bedeutet nicht, dass der Host sauber ist, und jede generierte Datei widerspricht
diesem Schluss in ihrem Kopf, weil die Person, die die Regel ausführt, oft nicht die Person
ist, die sie generiert hat.
