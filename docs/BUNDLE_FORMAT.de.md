# Beweismittel-Bundle, Format Version 1

[English](BUNDLE_FORMAT.md) | Deutsch

Das ist der Vertrag zwischen Sicherung und Analyse. Alles links davon passiert auf einem
Rechner, der untersucht wird, der möglicherweise kompromittiert ist, unter Zeitdruck, und
auf dem keine Abhängigkeiten verfügbar sind. Alles rechts davon passiert offline und darf
gründlich sein. Zwei unabhängige Kollektoren setzen diese Spezifikation um, einer in Python
3.8 und einer in PowerShell 5.1. Sie ist deshalb so geschrieben, dass sie zweimal
umsetzbar ist, und nicht so, dass sie beschreibt, was ein bestimmtes Programm gerade tut.

## Aufbau

```
<bundle>/
  manifest.json            was gesichert wurde, von wo, mit welchen Hashes
  chain_of_custody.jsonl   fortschreibender, hash-verketteter Nachweis, wer was getan hat
  files/                   gesicherte Inhalte, die Originalpfade nachbildend
    C/Users/alice/.claude/settings.json
    Users/alice/.claude/settings.json
```

Optional wird das ganze Verzeichnis zu `<bundle>.zip` gepackt, mit
`<bundle>.zip.sha256` daneben, das den Hash und den Dateinamen in dem Format enthält, das
`sha256sum` liest.

Die Nachbildung der Originalpfade ist der Grund, weshalb das Einlesen einheitlich sein
kann. Ein eigenes Bundle, ein KAPE-Ausgabebaum und eine Velociraptor-Offline-Sammlung sind
alle eine Wurzel plus Originalpfade, also liest eine Adapterform alle drei, dazu ein
eingebundenes Abbild und ein exportiertes Profil.

## manifest.json

Der vollständige Feldaufbau steht im [englischen Dokument](BUNDLE_FORMAT.md#manifestjson);
das JSON-Beispiel ist identisch und wird hier nicht doppelt geführt, damit die beiden
Fassungen nicht auseinanderlaufen. Die Felder, die nicht selbsterklärend sind:

- `tool.sha256` ist der Hash der Kollektor-Datei, so wie sie gelaufen ist. Damit lässt
  sich belegen, welcher Build das Bundle erzeugt hat, und ob die Datei vor dem Einsatz
  verändert wurde.
- `catalogue_version` ist der Hash des eingebetteten Katalogs, damit eine Sammlung an
  genau die Artefaktdefinitionen gebunden ist, die sie erzeugt haben.
- `local_timezone` wird einmal festgehalten und nicht pro Zeitstempel. Jeder Zeitstempel
  im Bundle ist UTC; der Offset ist das, was den Abgleich einer Protokollzeile mit einer
  Zeugenaussage erlaubt.
- `status` an einem Dateieintrag ist aus dem Katalog übernommen. Es steht hier, damit der
  Analyzer melden kann, dass ein leeres Ergebnis von einem unbestätigten Pfad kommt, was
  unklar ist, und nicht von einem bestätigten, was ein Befund wäre.
- `reason` ist null, wenn `collected` wahr ist, sonst einer von `too_large`,
  `secret_policy`, `permission_denied`, `unreadable`, `not_a_file`, `skipped_symlink`.
  `secret_policy` bedeutet, dass den Pfad mindestens ein Artefakt mit
  `sensitivity: secret` beansprucht hat und `--include-secrets` nicht gesetzt war: der
  Eintrag führt weiterhin Grösse, Hash und Zeitstempel, das Vorhandensein und die
  Identität sind also festgehalten, ohne dass Zugangsdaten kopiert werden. Ein einziger
  solcher Anspruch genügt, eine Zugangsdatendatei, die zusätzlich ein weiter
  Verzeichnis-Glob getroffen hat, wird also ebenfalls zurückgehalten.
- `artifact_ids` steht nur dort, wo mehr als ein Artefakt denselben Pfad beansprucht hat,
  und führt dann alle auf, sortiert. `artifact_id` bleibt einwertig und benennt den
  spezifischsten Anspruch, eine Datei wird also dem Eintrag zugeordnet, der sie benennt,
  und nicht einem Verzeichnis-Glob, der sie zufällig mit eingeschlossen hat, während
  `artifact_ids` festhält, dass auch die anderen getroffen haben.
- `changed_while_reading` wird gesetzt, wenn sich Grösse oder mtime zwischen dem Hashen
  und einem erneuten `stat` danach unterscheiden. Die Bytes im Bundle sind weiterhin
  genau die, die gehasht wurden; die Markierung sagt, dass die Quelle in Bewegung war.
- `symlink` enthält das Ziel, wenn der Eintrag ein Symlink innerhalb des Profils war, und
  der Eintrag wird mit `skipped_symlink` übersprungen, wenn das Ziel ausserhalb liegt.
- `refused_patterns` führt die Katalogmuster auf, die der Collector nicht durchsucht hat,
  jeweils mit dem Muster wie geschrieben, dem Stand der Auflösung und einem der Gründe
  `not_absolute`, `wildcard_too_broad`, `wildcard_only`, `malformed_variable` oder
  `environment_unreadable_offline`. Das Feld gibt es, weil ein nicht durchsuchtes Muster
  eine Lücke in der Abdeckung ist und ein Bundle, das darüber schweigt, genauso aussieht
  wie ein Bundle von einem Host, auf dem das Artefakt gar nicht vorhanden war.

  `environment_unreadable_offline` ist der Grund, den eine Analystin normalerweise sieht,
  und er ist kein Defekt. Mehrere Agenten verschieben ihren gesamten Datenbaum über eine
  eigene Umgebungsvariable, darunter `CLAUDE_CONFIG_DIR` und `CODEX_HOME`. Auf einem
  laufenden Host liest der Collector die Variable und folgt ihr. Bei einem eingebundenen
  Abbild mit `--root` gibt es keine solche Umgebung, und die eigene ist nicht die des
  Endgeräts. Das Muster wird deshalb gemeldet statt geraten: Suchen Sie die Variable in
  den Shell-Profilen des Abbilds und sammeln Sie gegebenenfalls in einem zweiten Durchgang
  nach.

  Ein Muster, das hier einfach nicht zutrifft, steht nicht in dieser Liste. Ein
  Windows-Pfad auf einem Linux-Host, eine freedesktop-Variable unter Windows oder eine
  Verschiebungsvariable, die tatsächlich nicht gesetzt ist, sind der Normalfall, und zu
  jedem davon gibt es im selben Artefakt ein Geschwistermuster, das durchsucht wird.

## Pfadabbildung

Vom absoluten Originalpfad auf einen Pfad unter `files/`, Segment für Segment.

1. **Wurzel.** Ein POSIX-Pfad verliert den führenden `/`. Ein Windows-Laufwerkspfad macht
   aus `C:\` das einzelne Segment `C`, gross, ohne Doppelpunkt. Ein UNC-Pfad
   `\\server\share\...` wird zu `UNC/server/share/...`.
2. **Prozentkodierung.** In jedem Segment wird zuerst `%` zu `%25`, damit die Abbildung
   umkehrbar bleibt. Danach wird jedes Byte aus `< > : " | ? * \` und `/`, jedes
   Steuerbyte unter 0x20 und jedes Byte, das kein gültiges UTF-8 ist, zu `%XX` mit
   Grossbuchstaben in der Hexzahl.
3. **Punkt oder Leerzeichen am Ende.** Windows entfernt die stillschweigend aus einem
   Dateinamen, deshalb wird ein abschliessender `.` oder ` ` prozentkodiert.
4. **Reservierte Gerätenamen.** Ist der Stamm eines Segments in Grossschreibung `CON`,
   `PRN`, `AUX`, `NUL`, `COM0` bis `COM9` oder `LPT0` bis `LPT9`, wird sein erstes Zeichen
   prozentkodiert. Aus `CON.txt` wird `%43ON.txt`, was kein Gerät mehr benennt.
5. **Zu lange Segmente.** Ein Segment, das nach der Kodierung länger als 200 Bytes ist,
   wird auf 190 Bytes an einer UTF-8-Zeichengrenze gekürzt und erhält `~` plus die ersten
   10 Hexzeichen des SHA-256 des Originalsegments.
6. **Kollisionen bei der Gross- und Kleinschreibung.** Kollidiert das Ergebnis ohne
   Rücksicht auf Gross- und Kleinschreibung mit einem bereits benutzten Bundle-Pfad, wird
   `~` plus die ersten 10 Hexzeichen des SHA-256 des vollständigen Originalpfads an das
   letzte Segment angehängt. Das verhindert, dass `Settings.json` und `settings.json`
   einander überschreiben, wenn eine Quelle mit Gross-Klein-Unterscheidung auf ein Ziel
   ohne geschrieben wird.

Die Schritte 1 bis 4 sind exakt umkehrbar. Die Schritte 5 und 6 sind es nicht, und genau
deshalb ist **`original_path` an jedem Dateieintrag Pflicht**: die Kodierung ist nie der
einzige Nachweis, woher etwas kam. Ein Analyzer, der den Originalpfad braucht, liest ihn
aus dem Manifest und niemals durch Dekodieren eines Bundle-Pfads.

## chain_of_custody.jsonl

Ein JSON-Objekt pro Zeile, angefügt, nie neu geschrieben. Jeder Datensatz trägt den Hash
des vorhergehenden und seinen eigenen, berechnet über den Datensatz ohne das Feld `sha256`
und mit sortierten Schlüsseln. Einen Datensatz zu entfernen oder zu verändern bricht die
Kette also an einer feststellbaren Stelle.

Die ehrliche Aussage lautet **manipulationssichtbar, nicht manipulationssicher**. Die Datei
liegt in einem beschreibbaren Verzeichnis, und wer sie schreiben kann, kann die ganze Kette
neu schreiben. Was die Kette bringt, ist, dass das nicht an einem einzelnen Datensatz
unbemerkt geht. Stärkere Zusicherungen brauchen eine Signatur oder einen externen
Zeitstempel, und das ist eine spätere Entscheidung und keine Änderung an diesem Format.

## Zusicherungen für nur lesenden Zugriff

- Der Kollektor schreibt nichts ausserhalb von `--out`. Keine temporären Dateien
  anderswo, keine Protokolle, keine Konfiguration.
- Auf dem Zielsystem wird nichts verändert, verschoben, umbenannt oder gelöscht, und es
  wird keine Agenten-Binary ausgeführt. Versionsangaben werden aus Dateien gelesen.
- Zugriffszeiten: der Kollektor öffnet mit `O_NOATIME`, wo Plattform und Dateieigentum das
  zulassen. Wo er es nicht kann, hält er die ursprüngliche `atime` vor dem Lesen fest, der
  Wert im Manifest ist also der von vor der Sammlung, und dass das Lesen sie verändert
  hat, ist erkennbar und nicht verschwiegen.
- Symlinks werden nicht über das gesammelte Profil hinaus verfolgt. Ein Link, der nach
  ausserhalb zeigt, wird mit seinem Ziel festgehalten und übersprungen.
- Unter Windows werden Reparse Points und Junctions erkannt und festgehalten statt
  durchlaufen, damit eine Junction-Schleife eine Sammlung nicht endlos laufen lässt oder
  Inhalte verdoppelt.
- Eine Datei, die sich während des Lesens ändert, wird einmal gehasht; der Hash passt zu
  den gespeicherten Bytes, und `changed_while_reading` hält die Abweichung fest.
- Dateien, die ein laufender Agent gesperrt hat, werden als `unreadable` mit dem
  Plattformfehler gemeldet. Schattenkopien sind in Version 1 ausserhalb des Umfangs und
  als solche vermerkt.

## Determinismus

Zwei Sammlungen desselben unveränderten Baums müssen bytegleiche Manifeste erzeugen,
abgesehen von den Feldern, die sich tatsächlich unterscheiden (Zeiten, uuid, argv).

- `files` ist nach `artifact_id`, dann `original_path` sortiert, in Byte-Reihenfolge.
- JSON wird mit sortierten Schlüsseln geschrieben, zwei Leerzeichen Einrückung,
  `\n` als Zeilenende, ohne abschliessende Leerzeichen und mit einem letzten
  Zeilenumbruch. Nicht-ASCII wird als UTF-8 geschrieben und nicht maskiert.
- Zeitstempel sind `YYYY-MM-DDTHH:MM:SS.ffffffZ`, Mikrosekunden immer vorhanden, immer
  UTC. Ein Zeitstempel, den die Plattform nicht liefern kann, ist `null`, niemals Null und
  niemals der Epoch-Zeitpunkt.
- Das Zip legt die Einträge in derselben Reihenfolge ab wie `files`, mit Deflate und ohne
  zusätzliche Attribute. Die Zeitstempel der Einträge sind die mtime der Originaldatei und
  nicht der Sammelzeitpunkt, denn ein Zip, dessen Inhalt sich zwischen zwei Läufen über
  einen unveränderten Baum ändert, lässt sich nicht über seinen Hash vergleichen.

## Felder, die zwischen den beiden Kollektoren abweichen dürfen

Diese Liste ist Teil der Spezifikation und kein Umsetzungsdetail. Sie ist die Stelle, an
der sich die Betriebssysteme wirklich uneinig sind, und der Differenztest in der CI
normalisiert genau diese und nichts sonst.

| Feld | Warum es abweicht |
| --- | --- |
| `collection.os`, `os_version`, `architecture`, `hostname`, `collector_user` | Plattformtatsachen |
| `collection.argv`, `uuid`, `started_utc`, `finished_utc` | Pro Lauf |
| `tool.name`, `tool.sha256` | Zwei verschiedene Dateien setzen das um |
| `birthtime_utc` | Unter Linux nicht verfügbar. Dort `null`, auf macOS und Windows vorhanden |
| `ctime_utc` | Unter Unix der Zeitpunkt der letzten Inode-Änderung, unter Windows der Erstellzeitpunkt. Gleicher Feldname, andere Bedeutung, dokumentiert statt eingeebnet |
| `atime_utc` | Auf einem mit `noatime` eingebundenen Datenträger bedeutungslos, unter `relatime` grob |
| Trenner in `bundle_path` | Im Manifest immer `/`, auch unter Windows |
| Trenner in `original_path` | So, wie die Plattform sie meldet, unter Windows also `\` |
| Gross- und Kleinschreibung in Pfaden | Eine Quelle ohne Unterscheidung meldet die Schreibweise, die das Dateisystem gespeichert hat, und die muss nicht der Schreibweise des Globs entsprechen |
| `users[].home` | Je Plattform anderer Aufbau |

## Rückgabewerte

| Wert | Bedeutung |
| --- | --- |
| 0 | Mindestens ein Artefakt gesichert |
| 1 | Gelaufen, aber mindestens ein Fehler steht im Manifest |
| 2 | Konnte nicht laufen: falsche Argumente, Ausgabeverzeichnis unbenutzbar |
| 3 | Erfolgreich gelaufen und nichts gefunden |

Wert 3 existiert, weil „dieses System hat keine Agentenartefakte" ein gültiges und
nützliches Ergebnis ist. Eine aufrufende Stelle muss das von einem Abbruch unterscheiden
können, und eine flottenweite Erhebung, die beides gleich behandelt, ergibt ein falsches
Bild davon, wo Agenten im Einsatz sind.
