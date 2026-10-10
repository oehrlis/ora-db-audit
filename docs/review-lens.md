# Review-Linse - ora-db-audit

> Fuer /repo-audit. Kurz halten (15-35 Zeilen). Invarianten-IDs nie neu vergeben.

## Kronjuwelen

- Kundendaten aus Engagements: Kunden-, Host-, DB-, Schema-, Policy-Namen und Audit-Luecken
  in Beispielen, Tests, Doku, Tasks und Git-Historie
- Korrektheit der Audit-Aussage - ein falsch negativer Befund ist schlimmer als keiner
- die Privilegien-Angabe: ein Kunde gibt dem Tool genau die Rechte, die dokumentiert sind

## Invarianten

- INV-1: Im Baum keine Kundendaten (Kunden-, Host-, DB-SID-, Schema-, Policy-, Context-Namen,
  Pfade in Kundenablagen); Beispiele nur mit generischen Platzhaltern (`APP_*`, `example.com`)
- INV-2: Neue Commits (Diff und Message) tragen keine Kundendaten; Altlasten der Historie
  stehen im Register
- INV-3: `git ls-files .claude` liefert hoechstens `CLAUDE.md` und `aitk.toml`
- INV-4: Die Queries unter `sql/` aendern die Datenbank nicht - ausser `ALTER SESSION`
- INV-5: README nennt die DB-Privilegien des Tools, und die Liste in `docs/installation.md`
  deckt jedes Dictionary-Objekt, das `sql/` liest
- INV-6: Jedes Enable-/DROP-Beispiel fuer Audit-Policies nennt das passende `NOAUDIT POLICY`
- INV-7: Echte Bundles und `*.mapping.json` sind gitignoriert und nie getrackt
- INV-8: Das `.anon`-Bundle traegt keine Kundenwerte im Klartext; unbekannter Schema-Typ oder
  CSV ohne Schema-Zeile bricht ab statt durchzureichen (fail-closed)
- Zuordnung: Kundendaten in der Historie -> `INV-2`, im Baum -> `INV-1`; Credential in der
  Historie -> `history`, im Baum -> `secret`

## Sensible Namen

- Kundenkuerzel und davon abgeleitete Praefixe (Host-, DB-SID-, Schema-, Policy-,
  Context-Namen) aus den Engagements - Repo ist public, deshalb **nicht hier**; das Muster
  steht ausserhalb des Repos (PKM-Projektnotizen der Engagements)
- immer mitgreppen: `ocid1\.`, `objectstorage\.`, `20_Customers`, `OneDrive-`

## Bedrohungsmodell

Das Repo ist public. Ein Leser rekonstruiert aus Beispielen, Tests, Tasks und Historie, bei
welchem Kunden welche Audit-Luecke bestand - oder ein Kunde vertraut einer falschen
Privilegien-Liste.

## Nicht-Ziele

- kein Monitoring-Produkt, keine Dauerinstallation beim Kunden
- keine Policy-Durchsetzung - das Tool analysiert, es aendert keine Audit-Konfiguration

## Bekannte Altlasten

- Kundendaten in der Git-Historie - siehe Register (`INV-2`)

## Verifikation

- `markdownlint` ueber alle `*.md` ausser `.claude/` und `dist/`
- `shellcheck -x -S warning` ueber `bin/` und `scripts/`
- `bats tests/bats/` und `uv run --no-project --with pytest pytest tests/python/`
- `gitleaks git --config .gitleaks.toml --redact --log-opts=--all .`
- `aitk repo hygiene .`
