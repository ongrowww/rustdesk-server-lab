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

## Serverbestätigte Geräteidentität

Der Branch `feature/002-device-attestation` erweitert den Custom-ID-Pfad
rückwärtskompatibel um eine kurzlebige Geräteattestierung:

- Ein V1-Request ohne Nonce verhält sich unverändert und erhält keine
  Attestierung.
- Ein V2-Request bindet eine exakt 32 Byte lange Nonce in den signierten
  Gerätebesitznachweis ein.
- Nach atomarer Prüfung der Zuordnung aus ID, UUID und Geräteschlüssel
  signiert `hbbs` einen fünf Minuten gültigen Identitätssnapshot.
- Die rohe UUID verlässt den Server nicht; die Attestierung enthält
  ausschließlich ihren SHA-256-Hash.
- Ohne privaten Serverschlüssel wird keine unsigned Attestierung ausgegeben.
- Attestierungen sind Identitätsnachweise, keine Sitzung und kein
  Zugriffsrecht.

Die neuen Protobuf-Felder sind auf beiden Forks identisch nummeriert. Die
Signaturkontexte `ongrow-rustdesk-custom-id-v2` und
`ongrow-rustdesk-device-attestation-v1` trennen Besitznachweis und
Serverattestierung voneinander.

## Upstream-Synchronisierung

```bash
git fetch upstream --tags
git switch master
git merge --ff-only upstream/master
```

Feature-Branches werden anschließend auf den gewünschten getesteten
Upstream-Tag beziehungsweise Commit rebased. Pushes zum Upstream-Remote sind im
lokalen Checkout deaktiviert.

## Client-Kompatibilitätsgate

Der dedizierte OnGROW-CI-Workflow prüft zusätzlich einen fest gepinnten
Client-Commit und beide `hbb_common`-Gitlinks. Der Test kompiliert die tatsächlichen
Protobuf-Artefakte beider Forks und vergleicht die OnGROW-Feldnummern,
Signaturkontexte und den kanonischen Attestierungsvektor. Die Server-Unit-Tests
decken Registrierung, Custom-ID, serverbestätigte Identität sowie manipulierte
Nachweise ab.

Das Gate nutzt ausschließlich synthetische Schlüssel und lokale Testdaten. Es
startet keine Verbindung zur Produktionsinfrastruktur und benötigt weder den
produktiven hbbs-Schlüssel noch andere Geheimwerte. Eine Protobuf-Kollision,
abweichende Revision oder ein veränderter Testvektor bricht den Build ab.
