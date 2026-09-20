# Architektur

[English](ARCHITECTURE.md) | Deutsch

Dieses Dokument beschreibt, wie die Teile zusammenspielen und warum. Die einzelnen
Entscheidungen, jeweils mit dem Preis, den sie in Kauf nehmen, stehen in [adr/](adr/)
(englisch).

## Die Verarbeitungskette

```
   Endgerät                     Analyse-Workstation
   ────────                     ───────────────────

  catalog/*.yaml  ──eingebettet──▶ collect.py / collect.ps1
        │                              │
        │                              ▼
        │                       Beweismittel-Bundle ──▶ verify ──▶ ingest ──▶ case.sqlite
        │                       manifest.json                                 │
        │                       chain_of_custody.jsonl              ┌─────────┼─────────┐
        │                       files/<Originalpfade>               ▼         ▼         ▼
        │                                                        timeline   rules     serve
        └──generiert──▶ Velociraptor / KAPE / MDE / KQL / osquery            scan    viewer
```

Zwei Dinge daran sind wichtig.

Der Katalog steht vor allem anderen. Er ist die einzige Stelle, die festhält, wo ein Agent
seine Daten ablegt, und aus ihm entstehen beide Kollektoren, alle fünf Generatoren für
Sammelregeln und die generierte Dokumentation. Nichts weiter unten in der Kette enthält
einen fest verdrahteten Pfad. Die CI erzeugt jedes abgeleitete Artefakt neu und schlägt bei
jeder Abweichung fehl, damit ein Pfad nicht an einer Stelle richtig und an einer anderen
veraltet sein kann.

Das Bundle ist die Grenze. Alles links davon passiert auf einem Rechner, der untersucht
wird, der möglicherweise kompromittiert ist, unter Zeitdruck, und auf dem keine
Abhängigkeiten verfügbar sind. Alles rechts davon passiert offline auf einer
Analyse-Workstation und darf gründlich sein. Das Bundle ist der Vertrag zwischen beiden
Seiten, und darum ist es in [BUNDLE_FORMAT.de.md](BUNDLE_FORMAT.de.md) eigenständig
spezifiziert und nicht einfach das, was der Kollektor zufällig schreibt.

## Bestandteile

### `catalog/`

Eine YAML-Datei pro Agent, geprüft gegen `catalog/schema/catalog.schema.json`. Das Schema
liegt neben den Daten und nicht im Python-Paket, damit die CI und ein Kollektor validieren
können, ohne irgendetwas zu importieren.

Jeder Artefakteintrag beantwortet: was es ist (`id`, `agent`, `category`), wo es liegt
(`os`, `paths` als Globs mit den Platzhaltern `~`, `%APPDATA%`, `%LOCALAPPDATA%` und
`$XDG_DATA_HOME`, die die Kollektoren auflösen), welches Format es hat (`format`), wer es
lesen darf (`sensitivity`), wie lange es überlebt (`volatility`), wie sehr wir dem Eintrag
trauen (`status`, `source`) und was eine Analystin oder ein Analyst wissen sollte (`notes`).

`status` ist das Feld, das den Katalog ehrlich hält. `verified` bedeutet, dass eine
Quell-URL diesen Pfad tatsächlich nennt und jemand sie abgerufen hat. Alles andere bleibt
`unverified`, wird trotzdem per Glob gesammelt, und wird in der Ausgabe des Analyzers als
unbestätigt markiert. Diese Markierung trägt Gewicht: sie ist der Unterschied zwischen
„der Agent wurde nicht genutzt" und „wir wussten nie sicher, wo wir suchen müssen".

`volatility` ist das, was den Katalog unter Zeitdruck nützlich macht. Mehrere Agenten
löschen ihre Historie selbst und nach Zeitplan, also hält der Katalog fest, was verfällt
und wie schnell, und die Sammeldokumentation ordnet die Artefakte danach und nicht
alphabetisch.

### `collector/`

Zwei Umsetzungen einer Spezifikation: `collect.py` für POSIX-Systeme, nur Standardbibliothek,
Python 3.8 oder neuer, und `collect.ps1` für Windows, PowerShell 5.1 oder neuer, ohne
Module. Jede ist eine einzelne Datei mit dem Katalog als JSON-Block zwischen
Markierungskommentaren, geschrieben von `scripts/build_collectors.py`.

Die Vorgabe „eine Datei, keine Abhängigkeiten" ist kein Minimalismus um seiner selbst
willen. Sie ist der Grund, weshalb sich ein Kollektor über EDR-Live-Response, eine
Remote-Shell oder einen USB-Stick ausrollen und auf einem Rechner ausführen lässt, auf dem
nichts installiert und nichts heruntergeladen werden darf. Python 3.8 und PowerShell 5.1
sind die Untergrenzen, weil das ist, was ein Unternehmensbestand tatsächlich hat.

Zwei unabhängige Umsetzungen desselben Formats driften auseinander, wenn nichts das
verhindert, also verhindern es drei Dinge: eine Bundle-Konformitätssuite, die einmal
geschrieben ist und gegen ein Bundle aus einem der beiden Kollektoren läuft, ein
Differenztest in der CI, der die beiden Manifeste gegeneinander vergleicht, abzüglich einer
dokumentierten Liste plattformspezifischer Felder, und die gemeinsame Spezifikation selbst.
Diese Liste der erlaubten Unterschiede ist der interessante Teil, denn dort sind sich die
Betriebssysteme wirklich uneinig: `birthtime` gibt es unter Linux nicht, `atime` ist auf
einem mit `noatime` eingebundenen Datenträger bedeutungslos, und `ctime` bedeutet unter
Unix den Zeitpunkt der letzten Inode-Änderung, unter Windows dagegen den Erstellzeitpunkt.

### Das Beweismittel-Bundle

Ein Verzeichnis, optional gezippt: `manifest.json`, `chain_of_custody.jsonl` und ein
`files/`-Baum, der die Originalpfade nachbildet. Die Feldliste und die Regeln der
Pfadkodierung stehen in [BUNDLE_FORMAT.de.md](BUNDLE_FORMAT.de.md).

Die Nachbildung der Originalpfade ist der Grund, weshalb das Einlesen einheitlich sein
kann. Ein eigenes Bundle, ein KAPE-Ausgabebaum und eine Velociraptor-Sammlung sind alle
nur eine Wurzel plus Originalpfade, also deckt eine Adapterform alle drei ab, dazu ein
eingebundenes Abbild und ein exportiertes Benutzerprofil.

Das Custody-Protokoll ist eine Hash-Kette: jeder Datensatz trägt den Hash des
vorhergehenden und den des Manifests. Das macht es manipulationssichtbar, nicht
manipulationssicher, und die Dokumentation sagt das auch so. Eine Datei in einem
beschreibbaren Verzeichnis kann immer überschrieben werden. Was eine Hash-Kette bringt,
ist, dass das nicht *unbemerkt* geht.

### `src/agentforensics/`

- `catalog/` lädt und validiert den Katalog
- `bundle/` schreibt, liest, hasht und verifiziert Bundles und die Custody-Kette
- `ingest/` Adapter für ein eigenes Bundle, einen KAPE-Baum, eine Velociraptor-Sammlung
  sowie ein einfaches Verzeichnis oder eingebundenes Abbild
- `parsers/` ein Modul pro Agent oder pro Formatfamilie, das Rohdatensätze in einheitliche
  Ereignisse verwandelt. Ein Parser wird über den Katalogeintrag gewählt, der die Datei
  beansprucht hat, also kann er dem Katalog nie widersprechen, was eine Datei ist. Eine
  Datei ohne Parser wird als nicht unterstützt vermerkt statt übersprungen, und der Fall
  zählt diese Dateien und sagt, welche es sind. 37 Module lesen 392 der 484
  Katalogartefakte, und was der Rest ist, wird behauptet und nicht angenommen: jeder Eintrag
  in einem Format, das diese Suite liest, wird entweder gelesen oder trägt einen
  aufgeschriebenen Grund, warum nicht, und die Anmeldedatenspeicher sind als Klasse
  ausgenommen, weil der Collector ihren Inhalt zurückhält, was ein Test darauf festnagelt,
  nur für Anmeldedatenspeicher zu gelten. Was bleibt, braucht Formatarbeit, und dafür ist
  das Dateisystem-Ereignis die ehrliche Antwort, bis sie jemand macht. Die drei Zahlen in
  diesem Absatz werden von einem Test gegen den Katalog und die Parser-Registry gehalten,
  denn eine in Prosa geschriebene Zahl stimmt an dem Tag, an dem sie geschrieben wird.

  **Die Agenten-Parser** sind die, die gegen eine Herstellerquelle geschrieben wurden:
  Claude Code, Codex CLI und dessen Projektion in Zeilen, Copilot CLI, Gemini CLI und Qwen
  Code (ein Modul, weil Qwen ein Fork ist und beide die Gemini-Inhaltsform schreiben), Pi,
  Cline mit seinen Forks Roo Code und Kilo Code und dem separaten SDK-Sitzungsspeicher,
  Continue, Zed und seine Seitenleiste, Aider, Amazon Q, opencode, Hermes und die
  VS-Code-Zustandsspeicher. Jeder übernimmt seine Artefakte von den Böden darunter, ein
  verifiziertes Schema nach dem anderen.

  **Die Böden** gehen über Formate statt über Agenten und existieren, damit eine Datei, die
  niemand gemappt hat, im Fall als Datensätze sichtbar ist, die sich jemand ansehen muss,
  statt als Dateiname ohne Inhalt dahinter. Jeder von ihnen schreibt auf jedes Ereignis,
  dass die Lesung uninterpretiert ist, und der Fall zählt diese Datensätze getrennt von
  denen, die nichts lesen konnte: das eine ist intakte Evidenz ohne Lesung, das andere ein
  Defekt in der Evidenz.

  - **SQLite-Speicher.** Nur lesend aus einer Kopie geöffnet und Tabelle für Tabelle, Zeile
    für Zeile zurückgegeben, ohne aus einer Zeile mehr zu lesen, als sie wörtlich sagt. Ein
    zstd-Frame in einem BLOB wird vorher entpackt, denn so legt ein Editor ganze Threads ab,
    und deshalb ist der Python-Boden 3.14 (ADR 0024). Die Kopie nimmt die Geschwister `-wal`
    und `-shm` mit, denn eine Datenbank im Write-Ahead-Log-Modus hält ihre neuesten
    Transaktionen im Log und sonst nirgends. Jede katalogisierte Datenbank beansprucht diese
    Geschwister inzwischen, und wo eine das nicht tut, vermerkt der Fall eine Lücke, statt
    zu schweigen: ein solcher Speicher öffnet sich, alle Tabellen sind da, und das Gespräch
    hört vor seinen letzten Nachrichten auf, ohne dass SQLite irgendeinen Fehler meldet.
    Das ist der einzige Fehlschlag in dieser Kette, der genau wie Erfolg aussieht
    (ADR 0032). Eine Sammlung trägt ein Log auch als eigene Datei, also erreicht eines den
    Parser, der Datenbanken öffnet, und ist keine: es wird als das benannt, was es ist, und
    sagt, ob die Datenbank, zu der es gehört, mitgekommen ist. Denn ein Log, dessen
    Datenbank hier ist, enthält Datensätze, die der Fall schon hat, und ein Log ohne seine
    Datenbank enthält Datensätze, die niemand erreicht. Es als Speicher zu melden, der
    nicht gelesen werden konnte, was es vorher bekam, behauptet einen Verlust, den es nicht
    gab, auf zwei Dutzend Einträgen gleichzeitig.
  - **Zeilenbegrenzte Logs.** Jedes JSON-Lines-Artefakt, das kein verifizierter Parser
    beansprucht, Datensatz für Datensatz. Dieser Boden existiert, weil die beiden Erzeuger
    des einheitlichen Formats auseinandergelaufen waren und der Analyzer die Seite war, die
    weniger las; ein Test schlägt jetzt fehl, wenn sich die Lücke in eine der beiden
    Richtungen wieder öffnet.
  - **Ganze Dokumente.** JSON, YAML, TOML und Property Lists über eine gemeinsame Lesung
    (ADR 0027 für die Regel, ADR 0028 für die anderen drei Formate). Ein Dokument hat keine
    eigenen Datensätze, also wird es allein nach Struktur aufgeteilt, eine Ebene tief, nie
    nach einer Vermutung über seine Bedeutung. Was ein Datensatz *ist*, kommt aus dem
    Katalog und nicht aus dem Dokument: ein als Konfiguration geführter Eintrag erzeugt
    `config.snapshot`, alles andere `unparsed.record`. Genau diese Unterscheidung lässt eine
    Regel über eine Einstellung sie auch finden, und sie war vier ausgelieferte Regeln wert,
    die auf einer echten Sammlung überhaupt nicht feuern konnten.
  - **Textlogs.** Eine Zeile ist ein Datensatz, datiert nur dort, wo die Zeile mit ihrem
    eigenen Zeitstempel beginnt, denn eine Zeile, die ein Datum erwähnt, ist keine Zeile,
    die damals passiert ist. Die Lesung stoppt nach einer festen Zeilenzahl und sagt das in
    einem eigenen Ereignis.
  - **Prosa.** Ein Chat-Export, eine ausgelagerte Werkzeugausgabe, die Ausgabe eines
    Hintergrund-Subagenten, ein geschriebener Plan und der Text hinter einem Platzhalter
    für eingefügten Inhalt: am Stück gelesen, ein Ereignis pro Datei, denn ein halber
    Prompt liest sich in einem Bericht wie das, was jemand gefragt hat.
  - **Datei-Momentaufnahmen.** Die Kopie, die drei Agenten von einer Datei anlegen, bevor
    sie sie ändern, und damit bei einer nie eingecheckten Änderung der einzige Ort, an dem
    der ursprüngliche Text noch steht. Gelesen wird der Inhalt, denn danach muss eine Regel
    über ein Credential oder eine eingeschleuste Anweisung suchen, und ausgesprochen wird,
    dass eine Momentaufnahme meist nicht sagt, von welcher Datei sie stammt: ein Produkt
    benennt seine Sicherungen nach einem Einweg-Digest des ursprünglichen Pfades, ein
    zweites dokumentiert das Verzeichnis und nicht die Benennung darin, ein drittes hält
    beide Seiten einer Änderung, ohne zu sagen, welche welche ist. Was der Pfad aussagt,
    wird gelesen; was er nicht aussagt, wird gesagt statt erschlossen.
  - **Registry-Schlüssel.** Vier Katalogeinträge werden auf einem laufenden Windows-Host
    aus der Registry gelesen und als JSON-Dokumente ins Bundle geschrieben, mit dem
    Schlüssel als Originalpfad des Eintrags (ADR 0033). Zwei davon sind die verwaltete
    Richtlinie, die sagt, was ein Agent durfte, und die unter Windows allein in der
    Registry stehen kann, ganz ohne Datei: ein Fall, der schwiege, läse sich als Host ohne
    Richtlinie statt als Host, auf dem niemand nachgesehen hat. Ein Ereignis pro Wert; ein
    Schlüssel, den es gibt und der leer ist, bekommt ein eigenes, denn bei einem
    Richtlinienschlüssel heisst das, die Richtlinie war nicht gesetzt, und das ist etwas
    anderes als ein nie angelegter Schlüssel. Die Zeit gehört dem Schlüssel und nie dem
    Wert, denn die Registry führt keine pro Wert. Der Hive ist ein Feld und kein Teil des
    Pfades, denn eine Richtlinie unter dem eigenen Hive der Nutzenden ist eine, die auch
    jemand ohne Administratorrechte dort hingelegt haben kann.
  - **Textkonfiguration.** Die kleinen Dateien, die sagen, wie ein Agent eingerichtet war,
    am Stück gelesen, und zwei, die Zeile für Zeile gelesen werden, weil eine Zeile das
    ist, was eine Untersuchende gegen einen Pfad hält. Eine Ignore-Datei ist die Umkehrung
    jedes anderen Artefakts hier: sie hält fest, was der Agent nie lesen, schreiben oder
    indizieren sollte. So erklärt sich eine Datei, die jemand für angefasst hielt und die
    es nicht war, und ein kurz vor dem Untersuchungszeitraum hinzugefügtes Muster hält
    Material aus jedem Transkript heraus, das der Agent je geschrieben hat. Eine
    Worktree-Include-Liste ist ein Verzeichnis der gitignorierten Dateien, die der Agent in
    jeden von ihm angelegten Worktree kopiert, und der Hersteller dokumentiert sie mit
    Umgebungsdateien und Secrets-Konfiguration als Beispielen: ein Name darin sagt also,
    wo Kopien dieser Datei liegen. Zwei weitere Listen kommen aus demselben Grund dazu. Die
    globalen git-Excludes der Nutzenden, wo ein Agent ein Muster für seine eigene Datei mit
    gespeicherten Berechtigungen anhängt, sobald er die erste schreibt, womit diese Zeile
    der einzige Marker ist, der jedes Verzeichnis des Agenten überlebt. Und die Indexliste
    eines Editors, die ein Dateinamens-Verzeichnis ist und kein Inhalt: sie sagt, welche
    Dateien in einem Arbeitsbereich existierten und für den Upload zum Indexdienst des
    Herstellers in Frage kamen, und das ist noch eine Antwort, wenn die Dateien weg sind.
  - **Shell-History.** Vier Shells und die Recall-Datei des Agenten selbst, jede so gelesen,
    wie ihr eigener Schreiber sie schreibt. Hier steht die Startzeile eines Agenten, also
    die erste Frage des Briefings über einen Agenten, und sie steht fast nie im Agenten.
  - **Shell-Skripte, die über eine Umgebung entscheiden.** Zwei Artefakte, ein Format,
    entgegengesetzte Aussagen. Ein Agent kopiert die Shell der Nutzenden in ein Skript,
    bevor er irgendetwas ausführt, und diese Datei ist die Umgebung, in der seine Befehle
    tatsächlich liefen, statt einer Aufzeichnung, dass jemand einmal eine Zeile getippt
    hat. Das andere ist das Shell-Profil selbst, von dem jede künftige Sitzung ausgeht, und
    dort kann eine Sammlung entwertet werden, bevor sie beginnt: eine exportierte Variable,
    die das Zuhause eines Agenten verlagert, heisst, dass der vom Standardpfad genommene
    Baum der falsche sein kann oder gar nicht existiert, und eine exportierte Basis-URL
    heisst, dass der Verkehr woanders hinging als zum Hersteller, ohne dass irgendeine
    Einstellungsdatei das zeigt. Beide Schreibweisen eines Exports werden gelesen, auch die
    von fish, das kein export kennt und wo ein verlagertes Agenten-Zuhause am wenigsten
    nach einem Export aussieht. Nur die drei Deklarationen, die eine Shell eindeutig ausspricht, werden
    als solche gelesen: ein Export, ein Alias und eine Funktion samt Rumpf. Jede andere
    Zeile bleibt mit der Uninterpretiert-Marke stehen, denn ein Leser, der entschiede, was
    eine beliebige Shell-Zeile bedeutet, würde eine Shell schreiben. Das Lesen lohnt
    doppelt: was eine Wrapper-Funktion einer Anfrage hinzufügt, ist im Befehl, den ein
    Transkript aufzeichnet, unsichtbar, denn dort steht nur der Name des Wrappers, und der
    Purge-Befehl des Herstellers lässt dieses Verzeichnis in Ruhe.
  - **Verschlüsselte Speicher.** Ein Produkt legt seine Gespräche in einem AES-GCM-Container
    um ein Protobuf ab. Der Container wird nur mit einem Schlüssel geöffnet, den die
    Untersuchende mitgibt, unter der Rahmung, die sich authentifiziert, und der Klartext
    wird über das Wire-Format gelaufen, also sind seine Felder Nummern statt Namen, und
    jeder Datensatz sagt das (ADR 0029).
  - **Schlüssel-Wert-Speicher.** Die beiden Electron-Desktop-Produkte legen den Zustand
    ihres Fensters, und bei einem von beiden die Prompts, dort ab, wo eine Browser-Engine
    ihn ablegt: in einer LevelDB aus unveränderlichen Tabellendateien und einem
    Write-Ahead-Log. Beides wird gelesen, und das Log zählt am meisten, denn dort steht,
    was eine laufende Anwendung zuletzt geschrieben und noch nicht in eine Tabelle
    gefaltet hat. Das Lesen hört bei den Datensätzen auf: was die Bytes in einem Wert
    bedeuten, ist die eigene Serialisierung der Engine, dafür hat hier niemand eine
    Quelle, und der Text neben einem Datensatz sagt, dass er extrahiert und nicht
    dekodiert wurde. Das Format ist in diesem Paket implementiert statt aus einer
    Abhängigkeit genommen, zusammen mit dem Snappy, mit dem seine Blöcke komprimiert
    sind (ADR 0031).
  - **Die Prompt-Bibliothek.** Ein Editor legt die Prompts, die eine Person für den Agenten
    geschrieben hat, in einem speichergemappten B-Baum-Speicher ab statt in Dateien. Damit
    ist es das eine Instruktionsartefakt in diesem Katalog, dessen Text ein Fall nicht
    zeigen konnte. Das Seitenformat ist hier umgesetzt, aus demselben Grund wie das
    darüber: zwei benannte Unterdatenbanken, eine bildet eine Prompt-Id auf Titel und
    letzte Speicherzeit ab, die andere dieselbe Id auf den Text, und ein Prompt ist die
    Verbindung der beiden. Der Speicher überschreibt nie eine Seite, also halten die
    Seiten, auf die der Baum nicht mehr zeigt, frühere Fassungen von Prompts und die
    gelöschten. Auch die werden gelesen, und jede sagt, was sie ist: ein Prompt, den jemand
    letzte Woche entfernt hat, gehört zur Antwort darauf, was dem Agenten aufgetragen war,
    und steht in keinem anderen Artefakt auf dem Endpunkt (ADR 0035). Ein weiterer Eintrag
    ist ein Speicher desselben Formats, für den niemand eine Quelle hat: dort soll ein
    älterer Build desselben Editors seine Gespräche abgelegt haben. Er geht an den
    uninterpretierten Boden für dieses Format, der jeden Datensatz mit Schlüssel und Wert
    zurückgibt und auf jedem sagt, dass darüber nichts entschieden wurde.

  **Die Schatten-Repositories** sind ein eigener Teil der Antwort auf die Frage nach
  Datei-Momentaufnahmen. Zwei Agenten sichern, was sie ändern wollen, indem sie es in ein
  Repository committen, und wo dieses Repository dem Agenten gehört, sammelt der Katalog es
  ganz. Also wird der git-Objektspeicher hier gelesen: ein loses Objekt ist zlib um einen
  Typ, eine Länge und einen Rumpf, und die Commits, die Bäume und die Dateiinhalte hinter
  jedem Checkpoint liegen im Bundle. Ein Commit trägt seine eigene Uhr, die den Zeitpunkt
  der Aufnahme datiert, wo das Referenzlog nur den Schreibvorgang datiert. Ein gepacktes
  Repository wird entpackt: das Pack-Format und seine beiden Delta-Kodierungen sind hier
  umgesetzt, jedes Objekt kommt als eigenes Ereignis heraus, verortet über seinen
  Byte-Offset im Pack, und die Objekt-Ids kommen so heraus, wie git sie schreibt, was ein
  gepacktes Objekt an die Referenz bindet, die es nennt. Ein Objekt, das sich nicht
  entpacken lässt, ein Delta gegen eine Basis, die das Pack nicht mitbringt, ist ebenfalls
  ein Ereignis, denn der Unterschied zwischen einem Repository, das nichts enthielt, und
  einem, das diese Suite nicht lesen konnte, ist der ganze Punkt. Solche Repositories
  werden normalerweise nie aufgeräumt, also ist ein Pack darin selbst einen Blick wert.
  Ein Hook,
  der keine von gits abgeschalteten Vorlagen ist, wird als Instruktion abgelegt und nicht
  als Konfiguration, denn er ist ein Skript, das der Endpunkt von sich aus ausführt.
  Derselbe Leser nimmt den git-Index, den ein Agent neben jeden Checkpoint legt, in einem
  Kratzverzeichnis, das er absichtlich aus dem System-Temporärverzeichnis heraushält: seine
  eigene Quelle sagt als Grund, dass der Index und die Pfadliste daneben Arbeitsbereichs-
  pfade aufzählen. Diese Datei ist also eine Auflistung der Arbeitskopie im Moment eines
  Checkpoints, unverfolgte Dateien eingeschlossen, mit Grösse, Modus und der Uhr des
  Dateisystems auf jeder Zeile, und nichts anderes in diesem Katalog ist das.

  **Die Instruktionsfläche** hat ihr eigenes formatförmiges Modul für die Artefakte, die
  Skills, Commands, Output Styles, Rules, Steering-Dateien, Subagent-Definitionen und
  Hook-Skripte enthalten. Es liest jede Datei ganz, unterscheidet den Geltungsbereich anhand
  der Arbeitskopien, die die Sammlung aufgezeichnet hat, statt anhand der Pfadform, hebt das
  Frontmatter eines Skills samt der Werkzeuge heraus, die es sich selbst gewährt, und zählt
  die Zeichen, die eine Prüferin nicht sehen kann. Es behauptet nicht, einen System-Prompt
  zu zeigen: der Basis-Prompt des Herstellers liegt nicht auf dem Endpunkt, und etwas
  anderes zu sagen hiesse, eine Frage zu beantworten, die die Evidenz nicht beantworten
  kann. Die Notizen, die ein Agent sich selbst geschrieben hat, werden genauso gelesen und
  als Erinnerungen statt als Instruktionen geführt, denn die Instruktionsfläche beantwortet,
  was dem Agenten aufgetragen wurde, und eine Notiz, die er sich selbst schrieb, ist eine
  andere Frage.

  **Eine Datei, die kein Text ist**, wird mit Grösse und Hash vermerkt statt als Seite voller
  Ersatzzeichen, und zwar in jedem dieser Leser. Ein NUL-Byte in den ersten Kilobytes und ein
  hoher Anteil nicht dekodierter Zeichen entscheiden darüber, und die Schwelle liegt hoch
  genug, dass ein Dokument von einer Maschine mit anderer Codepage weiterhin als das
  Dokument gelesen wird, das es ist.

- `model/` das einheitliche Ereignismodell und das SQLite-Fallschema
- `unified/` das Ereignismodell als Datenstrom: das JSON-Lines-Format und sein Schema,
  dazu der Normalisierer, der eine Sammlung ohne Falldatenbank in ein Log überführt
- `timeline/` Aufbau der Zeitachse und Exporte (CSV, JSONL, Timesketch-JSONL)
- `rules/` die deklarative YAML-Regel-Engine
- `exporters/` die Generatoren für Sammelregeln, ein Modul pro Zielformat
- `webui/` die lokale, nur lesende API, die auch den Viewer ausliefert
- `cli.py` der Befehl `agentforensics`, kurz `afx`

### Das einheitliche Ereignismodell

Jeder Parser erzeugt dieselbe Ereignisform, unabhängig davon, welcher Agent den Datensatz
geschrieben hat: eine deterministische `event_id`, abgeleitet aus der Herkunft, ein
optionales `ts_utc` mit ausdrücklicher `ts_precision`, dazu `agent`, `client`, `host`,
`user`, `session_id`, `project_path`, `git_branch`, `actor`, `kind`, ein artspezifisches
`payload`, die `provenance` (Bundle-Kennung, Originalpfad, Datei-Hash, Zeilennummer oder
Byte-Position) und `raw`, der Originaldatensatz, wortgetreu erhalten.

`raw` ist keine Redundanz. Es ist die Garantie, dass ein Zuordnungsfehler in einem Parser
nur Interpretation kostet und nicht Beweismittel: der Originaldatensatz ist immer noch da
und kann neu gelesen werden.

Dass die `event_id` aus der Herkunft und nicht aus einem Zähler entsteht, macht das
erneute Einlesen idempotent. Dieselben Beweismittel ergeben dieselben Kennungen, ein Bundle
zweimal einzulesen verdoppelt also keinen Fall, und ein Fund von letzter Woche zeigt
weiterhin auf dasselbe Ereignis.

Die Ereignisarten sind absichtlich agentenneutral: `session.start`, `session.end`,
`user.prompt`, `assistant.text`, `assistant.thinking`, `tool.call`, `tool.result`,
`file.read`, `file.write`, `file.snapshot`, `command.exec`, `network.request`, `mcp.call`,
`permission.decision`, `permission.change`, `safety.refusal`, `config.snapshot`,
`instruction.source`, `memory.write`, `plan.write`, `prompt.history` und `artifact.fs`.

Vier davon verdienen einen Satz. `permission.decision` ist eine Anfrage, entschieden nach
den geltenden Regeln, und `permission.change` ist eine Änderung der Regeln selbst: die
Umgehungsfrage braucht beide, denn das eine sagt, was mit einer Anfrage passiert ist, und
das andere, wer die Torpfosten verschoben hat und wann. `safety.refusal` ist das Modell, das
ablehnt, und das ist nicht dasselbe wie eine von der Umgebung verweigerte Berechtigung. Nur
manche Agenten halten es fest, sein Fehlen ist also nie ein Beweis, dass nichts abgelehnt
wurde.

`instruction.source` ist eine Anweisung, die auf dem Endpunkt in Kraft war: eine CLAUDE.md,
ein Skill, ein Output Style, eine Regel- oder Steering-Datei, ein Hook-Skript. Sie gehört
nicht zu `config.snapshot`, weil die beiden verschiedene Fragen beantworten und eine
Zeitachse sie auseinanderhalten muss. Eine Einstellung sagt, wie der Agent konfiguriert war;
eine Anweisung ist Text, dem das Modell folgen sollte, und ob der Agent durch eingeschleuste
Anweisungen manipuliert wurde, betrifft nur das Zweite. Der Name sagt absichtlich source und
nicht prompt: der Basisprompt des Herstellers ist in den Agenten kompiliert oder kommt von
dessen Server, liegt also gar nicht auf dem Endpunkt. Diese Art trägt den Teil eines
Systemprompts, der Beweis sein kann, und nie das Ganze.

`artifact.fs` braucht eine Erklärung: diese Art trägt die Dateisystem-Zeitstempel der
Artefaktdatei selbst. Manche Artefakte enthalten überhaupt keine eigenen Zeitstempel, und
für die ist der einzige zeitliche Beweis, wann die Datei angelegt, geändert oder zuletzt
gelesen wurde. Ohne diese Art wären sie auf einer Zeitachse unsichtbar.

Facetten werden einmal beim Einlesen abgeleitet und in eigenen, indexierten Tabellen
abgelegt: berührte Dateien, ausgeführte Befehle, kontaktierte Hosts und URLs, genutzte
MCP-Server und Werkzeuge, verwendete Modelle, Token- und Kostenangaben, soweit ein Agent
sie protokolliert, genutzte Clients, gesehene Berechtigungsmodi und die wirksamen
Instruktionsdateien. Sie existieren, damit die Fragen, die in der Praxis gestellt werden,
etwa jede Datei, die ein Agent über alle Sitzungen geschrieben hat, oder jeder externe
Host nach Häufigkeit sortiert, eine indexierte Abfrage sind und kein Durchsuchen von
JSON-Feldern.

Die Identitätsspalten zeigen auf Tabellen `users` und `hosts` statt Namen direkt zu halten.
Diese Indirektion ist jetzt schon da, damit Pseudonymisierung später eine Funktion ist und
kein Neubau.

### Das vereinheitlichte Log

Dasselbe Ereignismodell, serialisiert als JSON Lines, ein Ereignis pro Datensatz, definiert
durch `src/agentforensics/unified/agentlog.v1.schema.json`. `docs/UNIFIED_FORMAT.de.md` ist
die Referenz; ADR 0018 hält fest, warum es das Ereignismodell als Datenstrom ist und kein
zweites Modell.

Es existiert, weil drei Konsumenten die Agentenhistorie in einer Form brauchen, die keine
Falldatenbank ist: eine Flottensammlung, die viele Hosts auf einmal zurückgibt, ein
Sammelwerkzeug, das auf dem Endpunkt normalisiert und nur das geparste Ergebnis
zurückliefert, und der Viewer, der im Browser ohne Server läuft. Jeder Datensatz steht für
sich und trägt seine eigene Version, deshalb lassen sich zwei Logs zu einem gültigen dritten
aneinanderhängen, und ein Produzent, der Zeilen statt Dateien ausgibt, kann das Format
direkt schreiben.

`afx normalize <quelle>` erzeugt es über dieselben Adapter und Parser wie `afx ingest`, und
genau das verhindert, dass die beiden Pfade eine Datei unterschiedlich lesen. Ein Test
prüft, dass ein Log und ein aus derselben Quelle gebauter Fall genau dieselben Ereignisse
enthalten.

### Die Regel-Engine

Regeln sind YAML, eine Datei pro Regel, und die Trefferlogik ist Daten und nicht Code:
Feldselektoren, Operatoren, boolesche Verknüpfung und Zählschwellen. Keine Regel kann
irgendetwas ausführen. Das ist eine Sicherheitseigenschaft, weil Regeln aus einem
öffentlichen Repository kommen und über Text laufen, den möglicherweise ein Angreifer
kontrolliert, und es ist eine Eigenschaft der Nachvollziehbarkeit, weil eine Regel auch von
jemandem gelesen und bestritten werden kann, der kein Python schreibt.

Jede Regel enthält positive und negative Testbeispiele direkt bei sich, die pytest
ausführt, eine Regel ohne Tests kommt also nicht durch die CI. Jede Regel dokumentiert
ausserdem ihre bekannten Fehlalarme, denn die ehrliche Aussage über das Ganze ist: ein Fund
ist ein Hinweis, der geprüft werden muss, und niemals ein Urteil.

Was die Regelpakete bewusst nicht abdecken, ist die Suche nach den eigenen Daten einer
bestimmten Organisation. Das ist ein anderes Produkt, es würde interne Domains und
Projektnamen in ein öffentliches Repository bringen, und es würde die Suite von der Frage
wegziehen, für die sie existiert. Die Pakete bleiben auf das Verhalten der Agenten
fokussiert: Zugangsdaten, die in ein Transkript geraten sind, gefährliche Befehle,
sensible Pfade, Exfiltrationshinweise, Umgehung von Berechtigungen, Anti-Forensik,
Prompt-Injection, Lieferkette und Drittanbieter-Endpunkte.

Funde liegen in der Falldatenbank neben den Ereignissen, auf denen sie ruhen, verbunden
über eine Tabelle statt über eine Spalte. Denn eine Aggregatregel feuert auf eine Gruppe:
zwanzig gelesene Dateien in einer Minute sind ein Fund über zwanzig Ereignisse, und ein
Fund, der nur auf eines davon zeigen könnte, wäre ein Fund, den ein Analyst nicht
nachprüfen kann. Ein Fund wird über seine Regel und seine Beweise geschlüsselt, deshalb
bleiben die Zahlen beim erneuten Scannen nach einer Regelkorrektur erhalten und verdoppeln
sich nicht.

Jeder Scan wird festgehalten, ob etwas gefeuert hat oder nicht, und nennt jede Regel, die
gelaufen ist. Ohne diese Aufzeichnung sehen ein Fall ohne Funde und ein Fall, den niemand
gescannt hat, gleich aus, und das sind entgegengesetzte Schlüsse. Es ist dieselbe Regel,
der die Sammelseite für ein Glob folgt, das sie nicht durchsucht hat.

### Der Viewer

`viewer/index.html` ist eine einzelne Datei ohne Abhängigkeiten, die Sitzungen nur lesend
darstellt. Sie ist älter als die Suite, bleibt als Bestandteil erhalten und ist weiterhin
vollständig eigenständig nutzbar.

Ihre Datenschicht liegt hinter einer Quellenschnittstelle mit zwei Methoden, `listDir` und
`readText`, über undurchsichtige Pfadzeichenketten. Genau das macht drei Betriebsarten
möglich, ohne die Darstellung anzufassen: das Auslesen einer lokalen Verzeichnisliste, das
Lesen eines Ordners über die File System Access API des Browsers, und das Lesen der lokalen
API, die `serve` bereitstellt. Die ersten zwei funktionieren ganz ohne Installation, und
darum bleiben sie erhalten statt ersetzt zu werden.

Die Regel, die der Viewer am strengsten befolgt: kein Datensatz darf verschwinden. Eine
Zeile, die sich nicht parsen lässt, ein Datensatztyp, den kein Parser kennt, ein
Assistenten-Zug ohne Kennung, eine unbekannte Ereignisart, all das erscheint als eigene,
sichtbare Zeile, und der Sitzungskopf zählt die nicht parsbaren Zeilen mit. Still nichts
darzustellen würde zu dem Schluss führen, es sei nichts da gewesen, und das ist der eine
Fehlerfall, den ein Forensikwerkzeug nicht haben darf.

### Die lokale Web-UI

`afx serve --case <db>` legt einen Fall hinter den Viewer, auf 127.0.0.1, nur lesend. Zwei
Module: `webui/api.py` verwandelt einen Fall in die Daten, die ein Viewer zeigt, und weiss
nichts von HTTP, sodass jede Projektion ohne Socket testbar ist; `webui/server.py` bindet
den Socket und trägt die Härtung.

Ein Session-Endpunkt antwortet im vereinheitlichten Log-Format, nicht in einer eigenen Form.
Der Viewer liest einen Fall damit über den Leser, den er schon hatte, und dieses Projekt hat
genau ein Wire-Format für ein Agentenereignis statt eines vierten, das den anderen drei
widersprechen könnte.

Eine Session ist abgeleitet, nicht gespeichert. Ein Fall enthält Ereignisse; was die
Seitenleiste eine Session nennt, ist eine Gruppe von Ereignissen mit sechs gemeinsamen
Werten (Agent, Host, Benutzer, ob es Dateisystem-Zeitstempel sind, Arbeitsverzeichnis,
Session-ID), und der Key in der URL ist ein Hash genau dieser sechs. Derselbe Fall, dieselben
Keys, also übersteht ein Link in eine Session ein erneutes Einlesen.

Die Härtung gehört zur Entscheidung und ist kein Nachgedanke, denn eine forensische
Workstation ist kein freundliches Netz: ausschliesslich Loopback ohne Option auf etwas
anderes, ein zufälliges Pfad-Token pro Lauf, eine `Host`-Prüfung gegen DNS-Rebinding, eine
`Origin`-Prüfung, nur GET und HEAD, eine Anfrage mit Body wird ungelesen abgewiesen, eine
explizite Routentabelle ohne Fallback, der Viewer aus einer Byte-Kette im Speicher, sodass
es keinen Pfad zum Traversieren gibt, eine Content-Security-Policy, die jeden Zugriff
ausserhalb des Servers verbietet, und der Fall mit `mode=ro` geöffnet, sodass SQLite das
Schreiben verweigert. ADR 0006 hält fest, dass eine solche Liste der Teil ist, der am
ehesten verrottet, deshalb hat jeder Punkt seinen eigenen Test.

Siehe ADR 0006 und ADR 0020 sowie docs/WEBUI.de.md.

## Übergreifende Entscheidungen

**Offline, ohne Ausnahme.** Kein Netzzugriff zur Laufzeit, keine Telemetrie, keine
Update-Prüfung, nirgends im Ablauf ein LLM- oder API-Aufruf. Das folgt aus der Aufgabe und
ist keine Vorliebe: eine Analyse-Workstation kann vom Netz getrennt sein, der Umgang mit
Beweismitteln verbietet, Daten irgendwohin zu senden, und eine ausgehende Verbindung
während einer Untersuchung kann die betroffene Person warnen. Es ist auch der Grund, weshalb
die lokale Oberfläche die Standardbibliothek nutzt und nicht ein Web-Framework, dessen
Abhängigkeitsbaum mitgeliefert werden müsste.

**Deterministische Ausgabe.** Gleiche Eingabe, gleiche Ausgabe, stabile Sortierung überall,
Zeitstempel in UTC nach ISO 8601 und die Zeitzone des Endgeräts einmal im Manifest. Zwei
Durchläufe mit unterschiedlichen Bytes würden einen Vergleich sinnlos und einen Hash als
Bezugspunkt unbrauchbar machen.

**Beweismittel nur lesend.** Kollektor und Analyzer verändern, verschieben, benennen oder
löschen niemals ein Quellartefakt und führen auf dem Zielsystem nie eine Agenten-Binary
aus. Versionsangaben werden aus Dateien gelesen. Wo das Lesen einer Datei unvermeidlich
ihren Zugriffszeitpunkt verändert, wird das festgehalten und nicht verschwiegen.

**Wenige Abhängigkeiten, permissiv lizenziert.** Die Kollektoren haben gar keine. Der
Analyzer hält sie minimal, und jede einzelne ist eine Entscheidung mit einem ADR.

## Phasen

| Phase | Inhalt |
| --- | --- |
| 0 | Repository-Hygiene, bereinigter Viewer, Werkzeugkette, CI, OpSec-Wächter |
| 1 | Artefaktkatalog, beide Kollektoren, Bundle-Format, `verify`, synthetische Testdaten |
| 2 | Generierte Sammelregeln für Velociraptor, KAPE, Defender Live Response, KQL, osquery |
| 3 | Analyzer-Kern: Ingest, Parser, Ereignismodell, Falldatenbank, Timeline-Exporte |
| 4 | Regel-Engine und erste Regelpakete |
| 5 | Lokale Web-UI: nur lesende API, API-Quelle im Viewer, Ansichten für Fall, Timeline, Funde und Artefakte |

Bewusst vorerst ausserhalb des Umfangs: Fallverwaltung mit Triage-Status und Notizen,
Berichte als HTML und PDF, Pseudonymisierung, und ein Shell-Kollektor als Rückfallebene für
Rechner ohne Python.
