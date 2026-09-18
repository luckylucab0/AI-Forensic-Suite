# Mitarbeit

[English](CONTRIBUTING.md) | Deutsch

Danke fürs Reinschauen. Das hier ist Forensik-Werkzeug, deshalb zählen ein paar Dinge mehr
als in einem durchschnittlichen Projekt. Bitte lies die beiden folgenden Abschnitte, bevor
du einen Pull Request aufmachst.

## Die zwei Regeln, die keine Stilfrage sind

### 1. Nichts Organisationsspezifisches, niemals

Dieses Repository ist öffentlich, und sein Hauptpublikum sind Leute, die es innerhalb eines
Unternehmens einsetzen. Eine echte Domain, ein interner Hostname, ein Projektname, eine
Ticket-Nummer oder der Name einer Kollegin würde also die betreibende Stelle verraten,
dauerhaft, an jede Person, die das Repository klont oder forkt. Git macht das endgültig:
ein späterer Commit entfernt es nicht aus der Historie, und Forks, Spiegel und die Caches
von Code-Suchmaschinen behalten ihre Kopie.

Also: nur Platzhalter. `example.org`, `example.internal`, `ACME`, `alice`,
`PROJECT-FALCON`. Das gilt für Code, Kommentare, Dokumentation, Testdaten, ADRs,
Commit-Nachrichten und Branch-Namen. Erkennungsregeln verdienen besondere Aufmerksamkeit,
denn ein internes Hostnamen-Muster in einer Regel ist genauso ein Leck wie eines in einem
Kommentar.

Damit zusammenhängend: die Suite bringt keine Funktion mit, um die Daten einer bestimmten
Organisation zu finden. Regeln beschreiben das Verhalten von Agenten: was ausgeführt wurde,
was gelesen wurde, wohin Daten gingen, ob ein Schutzmechanismus umgangen wurde. Eine Regel,
die nach den Domains oder Projektnamen einer konkreten Firma sucht, müsste diese
Zeichenketten enthalten, und genau die dürfen nicht veröffentlicht werden. Sie würde das
Werkzeug ausserdem von der Frage wegziehen, für die es existiert.

### 2. Kein Datensatz darf verschwinden

Ein Parser, der einen unbekannten Datensatztyp verwirft, eine Darstellung, die für ein
unbekanntes Ereignis nichts zurückgibt, eine stillschweigend gekürzte Protokollzeile: in
einem Forensikwerkzeug sind das keine kleinen Fehler. Sie führen zu dem Schluss, es sei
nichts da gewesen, und das ist schlimmer als ein Abbruch, weil ein Abbruch sichtbar ist.
Erhalte alles, was du nicht interpretieren kannst, stelle es als unbekannt dar, und zähle
es mit. Dafür gibt es Tests, und ein neuer Parser braucht einen.

## Der OpSec-Wächter

`scripts/opsec_check.py` prüft die von git getrackten Dateien, den für den nächsten Commit
vorgemerkten Inhalt und die Commit-Nachricht selbst, ohne Rücksicht auf Gross- und
Kleinschreibung, gegen eine Liste von Zeichenketten, die nie veröffentlicht werden dürfen.

Diese Liste, `.opsec-denylist`, ist **nicht im Repository** und wird es nie sein. Sie nennt
genau das, was sie schützt, ein Commit würde sie also wirkungslos machen. Sie enthält eine
Zeichenkette pro Zeile, `#` beginnt einen Kommentar, und pflegt wird sie von der Person,
die aus diesem Arbeitsverzeichnis veröffentlicht:

```
# .opsec-denylist, eine Zeichenkette pro Zeile, wird nie committet
example-employer-name
example.internal
some-code-name
```

Die Hooks einmal einrichten:

```bash
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

Danach scheitert ein Commit lokal, der eine gelistete Zeichenkette einführen würde. Was man
über das Verhalten wissen sollte:

- **Keine Denylist vorhanden ist der Normalfall.** Ein frischer Klon, eine externe
  beitragende Person und ein CI-Lauf ohne das Secret haben zu Recht keine Liste. Die
  Prüfung endet dann mit 0 und einem Hinweis statt mit einem Fehler, denn ein Fehler an
  dieser Stelle würde nur dazu erziehen, den Hook zu überspringen.
- **Ein Treffer gibt die gefundene Zeichenkette nie aus.** Man bekommt Pfad, Zeilennummer
  und den Index des Denylist-Eintrags, der getroffen hat. Das Geheimnis auszugeben, um zu
  beweisen, dass man das Geheimnis gefunden hat, wäre widersinnig, und diese Ausgabe landet
  in Terminals, CI-Protokollen und Bildschirmfotos.
- **Eine getrackte Denylist ist ein harter Fehler.** Sollte `.opsec-denylist` jemals
  committet werden, verweigert die Prüfung den Dienst ganz, statt vorzugeben, alles sei in
  Ordnung.
- **Es gibt berechtigte Ausnahmen.** Ein Test, der beweist, dass der Wächter funktioniert,
  muss eine verbotene Zeichenkette enthalten. Dann `opsec-check: allow-line` an diese Zeile
  schreiben, oder den Pfad in `.opsec-allowlist` aufnehmen, die ebenfalls ignoriert wird.
- **Die Hook-Modi sehen nur die Gegenwart.** `--mode history` ist der Modus, der das
  bereits Geschriebene liest, und er hängt absichtlich in keinem Hook: er geht jedes
  Objekt durch, das von irgendeinem Ref erreichbar ist, was pro Commit der falsche und
  einmal vor der Veröffentlichung der richtige Aufwand ist. Er ist Punkt 1 der Prozedur
  weiter unten, und die Prozedur existiert, weil die übrigen Punkte menschliche Prüfung
  sind, die kein Skript leisten kann.

Die CI führt dasselbe Skript aus, liest die Denylist aus einem Repository-Secret, wenn
eines konfiguriert ist, und überspringt die Prüfung sonst sauber. Mit konfiguriertem Secret
geht sie einen Schritt weiter als der lokale Hook und durchsucht die gesamte Historie, denn
veröffentlicht wird die Historie.

Abgeflossene Zugangsdaten sind ein anderes Problem als eine verratene Identität und
brauchen ein anderes Werkzeug. Eingerichtet ist heute `detect-private-key` aus pre-commit,
das den offensichtlichen Fall eines mitcommitteten Schlüsselblocks abfängt. Ein
vollwertiger Secret-Scanner wie gitleaks steht in der Checkliste vor der Veröffentlichung
weiter unten und nicht bei jedem Commit, denn seine Zeit lohnt sich dort, wo er über die
Historie läuft.

## Bevor ein solches Repository öffentlich wird

Der Pre-Commit-Hook genügt nicht, weil er die Historie nie angesehen hat. Der Reihe nach,
mit der echten Denylist zur Hand:

1. `uv run python scripts/opsec_check.py --mode history` ausführen und bestätigen, dass
   es mit 0 endet. Der Modus liest jedes Objekt, das von irgendeinem Ref erreichbar ist,
   also jede Version jeder Datei einschliesslich der später gelöschten, dazu jede
   Commit-Nachricht, jede Autoren- und Committer-Identität und jeden Branch- und
   Tag-Namen. Binärdateien liest er mit, was die Hook-Modi überspringen, denn ein vor
   Monaten committeter Screenshot kann einen Hostnamen in einem Textchunk des Bildes
   tragen. Ausgegeben werden Objekt-ID und Pfad eines Treffers, nie der getroffene Text.

   Der frühere Weg war `git log -p --all | grep -i -f .opsec-denylist` und bleibt eine
   nützliche Gegenprobe. Zwei Lücken davon sollte man kennen, bevor man sich allein darauf
   verlässt: ein Patch lässt Binärdateien ganz aus, und der Inhalt eines Merge-Commits
   kommt darin überhaupt nicht vor.
2. `git log --format='%an <%ae> | %cn <%ce>' | sort -u` ausführen und jede Identität
   prüfen. Autor und Committer sind getrennte Felder und beide werden veröffentlicht.
3. `git branch -a` und `git tag` ausführen und die Namen prüfen.
4. Die Commit-Zeitstempel ansehen. Eine durchgehende Historie von Commits zwischen 09:00
   und 18:00 in einem festen Zeitzonen-Offset beschreibt ein Arbeitsmuster und grob einen
   Ort.
5. Text von Issues und Pull Requests, CI-Protokolle und jedes Bildschirmfoto prüfen.
   Bildschirmfotos sind der übliche Fehler: sie tragen Fenstertitel, Hostnamen, Pfade und
   manchmal Metadaten.
6. Einen allgemeinen Secret-Scanner über die Historie laufen lassen, nicht nur über das
   Arbeitsverzeichnis.
7. Bestätigen, dass `.opsec-denylist` und `.opsec-allowlist` nicht getrackt sind.

Wird nach der Veröffentlichung etwas gefunden, ist davon auszugehen, dass es bereits kopiert
ist. Das Umschreiben der Historie holt keinen Fork, keinen Spiegel und kein zwischengespeichertes
Suchergebnis zurück. Je nachdem, was abgeflossen ist, ist ein neues Repository mit frischer
Historie die ehrliche Antwort, und wer davon betroffen ist, sollte es erfahren und es nicht
selbst herausfinden müssen.

## Arbeiten im Repository

Der Analyzer braucht Python 3.14 oder neuer. Das ist eine junge Untergrenze und sie ist
gewollt: ein Agent komprimiert seine Transcripts mit zstd, das ab 3.14 in der
Standardbibliothek liegt, und sie anders zu lesen hiesse eine kompilierte Abhängigkeit.
ADR 0024 nennt die Begründung und den Preis. `uv` holt einen Interpreter, wenn das System
keinen hat. Die Kollektoren sind eine andere Sache und laufen weiter auf Python 3.8 und
PowerShell 5.1, denn sie laufen auf dem, was der Endpunkt gerade hat.

Einrichten, danach die eigene Arbeit mit denselben Befehlen prüfen, die auch die CI
ausführt:

```bash
uv sync --all-extras
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg

uv run ruff check .                   # Linting
uv run ruff format --check .          # Formatierung
uv run mypy src                       # Typprüfung, nur src
uv run pytest                         # Tests
uv run pytest --windows-newlines      # dieselbe Suite, mit Textmodus-Schreibvorgängen,
                                      # die sich verhalten wie unter Windows
```

Der letzte verdient einen Satz. Drei Defekte, die es nur unter Windows gab, sind in drei
aufeinanderfolgenden Commits in die CI gelangt, und jeder davon wurde vom einzigen Runner
gefunden, auf den niemand schaut, während die anderen fünf grün blieben. Einer war ein
Fixture, das im Textmodus geschrieben wurde: Windows macht aus einem Zeilenumbruch CRLF
auf der Platte, und ein Test, der Text oder Bytes genau vergleicht, scheitert dann dort
und sonst nirgends. `--windows-newlines` lässt jeden Textmodus-Schreibvorgang der Suite
sich so verhalten, sodass der Fehlschlag in unter einer Minute auf dem eigenen Rechner
passiert. Die CI führt das als eigenen Job aus. Ein Fixture, das später byteweise
verglichen wird, sollte `newline=""` übergeben und damit sagen, was es will.

Generierte Artefakte. Jedes davon hat einen `--check`-Modus, mit dem die CI bei Abweichung
fehlschlägt, also den Generator ausführen, sobald sich seine Eingabe ändert:

```bash
uv run python scripts/build_collectors.py    # catalog/ in beide Kollektoren einbetten
uv run python scripts/gen_artifact_docs.py   # docs/ARTIFACTS{,.de}.md neu erzeugen
uv run python scripts/check_translations.py  # deutsche Docs hinter dem englischen Stand
uv run python scripts/check_viewer.py        # Viewer-Struktur und JavaScript-Syntax
uv run python scripts/opsec_check.py --mode both
```

uv run python scripts/gen_rule_docs.py gehört ebenfalls dazu, für docs/RULES{,.de}.md.

Das Kommandozeilenwerkzeug selbst heisst `agentforensics`, mit `afx` als Kurzform:

```bash
uv run agentforensics --help
```

Konventionen, kurz gefasst.

- Code, Identifier, Kommentare, Commit-Nachrichten und ADRs auf Englisch. Dokumentation
  zweisprachig, wobei die englische Datei massgeblich ist und eine `.de.md`-Datei daneben
  steht. `scripts/check_translations.py` lässt die CI fehlschlagen, wenn der englische Text
  sich bewegt hat und der deutsche nicht.
- Conventional Commits, klein und in sich abgeschlossen. Linting und Tests grün vor jedem
  Commit.
- Kommentare erklären das Warum, nicht das Was. Module beginnen mit einem Docstring, der
  die Entwurfsvorgabe benennt, der sie dienen, und jeder nicht offensichtliche reguläre
  Ausdruck, jede Pfadkodierung und jede Formateigenheit bekommt einen Kommentar mit
  Begründung, dazu einen Quellenlink, wenn es aus der Herstellerdokumentation kommt.
- Ein ADR pro Entscheidung, kurz, unter `docs/adr/`.
- Frag nach, bevor du eine Abhängigkeit hinzufügst, ein Datenformat änderst oder etwas
  Sicherheitsrelevantes anfasst.
- Generierte Dateien werden nie von Hand bearbeitet: `docs/ARTIFACTS.md` und die deutsche
  Fassung, alles, was künftig unter `exporters/generated/` liegt, und der eingebettete
  Katalogblock in jedem Kollektor. Stattdessen `catalog/` ändern und neu erzeugen. Die CI
  vergleicht.

## Ein Artefakt zum Katalog beitragen

Das ist der wertvollste Beitrag und der, bei dem am leichtesten etwas schiefgeht.

Ein Eintrag ist nur dann `status: verified`, wenn `source` eine URL ist, die diesen Pfad
tatsächlich nennt, und du sie abgerufen hast. Herstellerdokumentation und der
veröffentlichte Quellcode des Agenten zählen beide. Ein Blogbeitrag, der einen anderen
Blogbeitrag zitiert, zählt nicht. Wenn du einen Pfad vom eigenen System kennst, ist das in
Ordnung und nützlich, aber dann gilt `status: unverified` mit
`source: "observed on <os> <version>"` und ohne jedes identifizierende Detail.

Unbestätigte Einträge sind nicht zweitklassig: sie werden trotzdem gesammelt, und sie
werden in der Ausgabe des Analyzers markiert, damit klar ist, dass ein negatives Ergebnis
unklar ist und kein Beweis. Wirklich schädlich ist ein plausibel aussehender Pfad, den nie
jemand gesehen hat. Er führt dazu, dass eine Sammlung leer zurückkommt und daraus
geschlossen wird, der Agent sei nie benutzt worden.

Niemals echte Inhalte aus einem Transkript, einer Konfiguration oder einer Datei mit
Zugangsdaten beilegen. Testdaten sind synthetisch und werden von
`tests/fixtures/generate.py` erzeugt.
