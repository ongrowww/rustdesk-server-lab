# OnGROW RustDesk Server Thin Fork

Dieser Fork bleibt möglichst nah an `rustdesk/rustdesk-server`. `master` folgt
dem Upstream; OnGROW-Änderungen entstehen auf kleinen Feature-Branches und
werden gegen einen konkreten Upstream-Tag gebaut.

## Custom-ID-Erweiterung

Der Branch `feature/001-ongrow-custom-id` ergänzt den im OSS-Server fehlenden
TCP-Pfad zum Ändern einer Geräte-ID.

- Erlaubtes Format: `OG-` plus genau vier Ziffern.
- Der Client signiert alte ID, neue ID und Geräte-UUID mit seinem bestehenden
  Ed25519-Geräteschlüssel.
- Der Server prüft die Signatur gegen den bereits registrierten Public Key.
- Die SQLite-Zuordnung wird mit Identitätsprüfung und Unique Constraint atomar
  geändert.
- Nicht angepasste Clients erhalten für diesen Vorgang weiterhin
  `NOT_SUPPORT`.

Der Signaturnachweis wird im vorhandenen `RegisterPk.pk`-Feld übertragen. Das
vermeidet eine Änderung am Protobuf-Schema; für normale UDP-Registrierungen
behält das Feld unverändert seine Upstream-Bedeutung als Public Key.

## Upstream-Synchronisierung

```bash
git fetch upstream --tags
git switch master
git merge --ff-only upstream/master
```

Feature-Branches werden anschließend auf den gewünschten getesteten
Upstream-Tag beziehungsweise Commit rebased. Pushes zum Upstream-Remote sind im
lokalen Checkout deaktiviert.
