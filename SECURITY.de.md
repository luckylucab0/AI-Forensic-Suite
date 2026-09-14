# Sicherheit

[English](SECURITY.md) | Deutsch

## Eine Schwachstelle melden

Bitte zuerst vertraulich melden, über die private Schwachstellenmeldung von GitHub in
diesem Repository (Reiter Security, „Report a vulnerability"). Damit bleibt die Meldung aus
den öffentlichen Issues heraus, bis eine Behebung vorliegt.

Beschreibe, was du getan hast, was passiert ist und was du erwartet hast. Am hilfreichsten
ist eine minimale Reproduktion, möglichst mit synthetischen Testdaten und nicht mit echten.
Bitte lege keine echten Agenten-Transkripte, Beweismittel-Bundles oder Material aus einer
laufenden Untersuchung bei: das sind Personendaten, und ein Fehlerbericht ist kein
rechtmässiger Ort, um sie zu lagern.

Mit einer Bestätigung innerhalb weniger Tage ist zu rechnen. Das ist ein kleines Projekt,
also bitte etwas Geduld bei den Zeitplänen, und sag von Anfang an, wenn du eine Frist für
die Offenlegung hast.

## Was hier als Schwachstelle zählt

Das ist ein Offline-Analysewerkzeug und kein Dienst, die interessanten Klassen sind also
nicht die üblichen Web-Themen.

- **Pfad-Ausbruch im Bundle-Schreiber oder in den Ingest-Adaptern.** Ein manipulierter
  Originalpfad in einem Beweismittel-Bundle, der den Analyzer ausserhalb des vorgesehenen
  Verzeichnisses lesen oder schreiben lässt. Das Bundle kommt von einem möglicherweise
  kompromittierten Endgerät, sein Inhalt ist also nicht vertrauenswürdige Eingabe.
- **Alles, was aus Beweismitteln ausgeführt wird.** Deserialisierung, Auswertung von
  Vorlagen, ein Unterprozess, der aus einem Feld in einem Protokoll gebaut wird.
  Beweismittel sind Daten und dürfen niemals zu Code werden.
- **Denial of Service durch reguläre Ausdrücke in der Regel-Engine.** Regeln sind Daten aus
  einem öffentlichen Repository und laufen über Text, den möglicherweise ein Angreifer
  beeinflusst, etwa abgerufene Webseiten in Werkzeugausgaben. Eine Regel, die katastrophal
  zurücksetzt, kann eine Untersuchung blockieren.
- **Cross-Site-Scripting im Viewer.** Agenten-Transkripte enthalten Text, den ein Angreifer
  kontrolliert: abgerufene Seiten, Werkzeugausgaben, eingeschleuste Anweisungen. Der Viewer
  stellt das dar, ein Fehler beim Maskieren ist hier also ein echter Fund und keine
  Theorie.
- **Alles, was das Werkzeug auf Beweismittel schreiben lässt.** Die Zusicherung, nur zu
  lesen, ist das Fundament, auf dem alles andere steht. Ein Fehler, der ein Quellartefakt
  verändert, verschiebt oder löscht, oder der einen Zugriffszeitpunkt anfasst, den wir
  nicht anzufassen versprochen haben, ohne das festzuhalten, ist ein schwerer Mangel.
- **Alles, was das Werkzeug ins Netz greifen lässt.** Kein Teil der Verarbeitungskette darf
  eine Netzverbindung aufbauen. Eine versehentliche DNS-Abfrage, eine Update-Prüfung oder
  eine von einem CDN geladene Schriftart brechen die Offline-Zusicherung und können eine
  betroffene Person warnen.
- **Stiller Verlust von Beweismitteln.** Ein Datensatz, der verworfen, gekürzt oder ohne
  Spur ausgeblendet wird. Das ist kein Speicherfehler, führt in diesem Werkzeug aber zu
  einem falschen Schluss und wird darum genauso ernst genommen.
- **Abfluss über die Ausgabe.** Ein Fund, ein Export oder eine Protokollzeile, die ein
  Geheimnis oder eine interne Kennung dort wiedergibt, wo das nicht vorgesehen war.

Nicht im Umfang: dass die Web-Oberfläche von einem anderen Rechner erreichbar ist, wenn du
sie absichtlich an etwas anderes als die Loopback-Adresse bindest, und dass heuristische
Regeln Fehlalarme erzeugen oder etwas übersehen. Heuristiken sind als Heuristiken
dokumentiert.

## Dual Use

Dieses Werkzeug findet Dateien mit Zugangsdaten und rekonstruiert alles, was eine
Entwicklerin oder ein Entwickler getippt hat. Dieselbe Fähigkeit, die einer Untersuchung
eine Antwort verschafft, erlaubt es jemand anderem, den Rechner einer Kollegin auszuwerten,
oder einem Angreifer, der schon Fuss gefasst hat, den schnellsten Weg zu Geheimnissen und
zum Wissen der Entwicklerin zu finden.

Das ist kein Grund, das Wissen zurückzuhalten. Wo Agentendaten liegen, findet jede Person
heraus, die nachsieht, mehrere Hersteller dokumentieren es selbst, und im Nachteil sind
derzeit die Verteidiger: Sicherheitsteams können einfache Fragen zu Werkzeugen nicht
beantworten, die ihre Entwicklerinnen und Entwickler längst täglich benutzen. Was sich
lohnt, ist, die Voreinstellungen schützend zu gestalten.

- Artefakte mit `sensitivity: secret`, vor allem Dateien mit Zugangsdaten, werden
  standardmässig nur als Metadaten samt Hash erfasst. Ihr Inhalt wird nicht kopiert, solange
  das nicht ausdrücklich mit `--include-secrets` verlangt wird, und diese Entscheidung wird
  im Manifest festgehalten.
- Der Kollektor schreibt ausschliesslich in sein Ausgabeverzeichnis, nirgendwo sonst, und
  führt auf dem Zielsystem nie eine Agenten-Binary aus.
- Es wird nichts irgendwohin gesendet. Es gibt keine Telemetrie und keinen Netzzugriff, das
  Werkzeug kann also nicht selbst zum Abflusskanal werden.
- Das Datenmodell ist so gebaut, dass die Pseudonymisierung von Benutzern und Hosts später
  eine Funktion ist und kein Neubau, denn viele legitime Einsätze müssen nicht wissen, wer.
- Die Dokumentation sagt klar, dass der Einsatz eine Befugnis voraussetzt. Siehe die README.

## Erkennungsregeln veröffentlichen, die anti-forensische Techniken benennen

Das Regelpaket `anti_forensics` beschreibt öffentlich, wie man die Historie eines Agenten
unterdrücken würde: welche Einstellung die Aufbewahrung verkürzt, welche Umgebungsvariable
die Persistenz abschaltet, welcher Befehl den Projektzustand löscht. Das zu veröffentlichen
lehrt die Gegenmassnahme zusammen mit der Erkennung.

Wir veröffentlichen es trotzdem, und die Begründung gehört ausgesprochen und nicht
stillschweigend vorausgesetzt. Jeder dieser Mechanismen ist eine dokumentierte
Produktfunktion, die die Hersteller aus legitimen Gründen in ihren eigenen Handbüchern
beschreiben. Wer seine Spuren verwischen will, findet sie über eine Suchmaschine und nicht
hier. Die Leute, die tatsächlich nicht wissen, dass es sie gibt, sind die Verteidiger, und
sie im Dunkeln zu lassen bringt niemandem etwas. Was wir nicht veröffentlichen, ist alles,
was nur einem Angreifer und keinem Verteidiger hilft, und die Regeln bleiben bei ihren
Grenzen ehrlich: jede dokumentiert ihre bekannten Fehlalarme, und ein Fund ist ein Hinweis,
der geprüft werden muss, und niemals ein Urteil.
