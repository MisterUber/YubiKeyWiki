# OpenPGP

{% include acronyms.md %}

Hier geht es um die generelle Schlüsselerstellung für den OpenPGP Dienst
auf den YubiKeys. Allgemeine Informationen sind auf der [YubyKey Kurzbeschreibung](/docs/kurzbeschreibung#funktionen) Seite
zu finden. Wenn Yubico davon spricht "OpenPGP" als Funktionalität zu
bieten, ist damit eine Implementierung der "OpenPGP Smart Card
Application" Spezifikation gemeint. Also eine Spezifikation, wie genau
man den OpenPGP Standard
([RFC4880](https://tools.ietf.org/html/rfc4880)) auf eine Smart Card
(nach [ISO/IEC 7816](https://en.wikipedia.org/wiki/ISO/IEC_7816))
bekommt. In unserem Fall ist die Smart Card der YubiKey, der die
Funktionalität als CCID zur Verfügung stellt. Die jeweils aktuellste
Version der "OpenPGP Smart Card Application" gibt es auf der Seite von
[GnuPG](https://gnupg.org/ftp/specs/). Mit der derzeitigen
Firmwareversion 5.2.4 implementiert der YubiKey Version
[3.4](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.0.pdf).
<sup>[\[3\]](#quellen)</sup>

## Einrichten von OpenPGP

Am YubiKey werden vier Slots für Schlüssel bereitgestellt. Je ein
Schlüssel zur Authentifizierung, zum Verschlüsseln [^1] und zum
Signieren und ein Platz für einen Beglaubigungsschlüssel
(Attestation-Key). Voraussetzung für die folgende Einrichtung:

  - Yubico Management Tools (Anleitung: [YubiKey Verwaltung](/docs/verwaltung#installation))
  - [GnuPG-Software](https://gnupg.org/software/index.html) (Linux) bzw.
    dessen Implementierung für Windows
    [Gpg4win](https://www.gpg4win.org/) bzw. eine andere GPG
    Implementierung eigener Wahl.

## Schlüsselerzeugung

Unterstützte Algorithmen (RSA):<sup>[\[1\]](#quellen)</sup>

  - ~~RSA 1024~~ laut BSI nicht mehr sicher<sup>[\[4, Kap.
    3.6\]](#quellen)</sup>
  - ~~RSA 2048~~ laut NSA nicht mehr sicher.
    <sup>[\[8\]](#quellen)</sup>
  - RSA 3072
  - RSA 4096

Unterstützte Algorithmen (ECC):<sup>[\[3\]](#quellen)</sup> Zusätzliche
Erläuterung im Kapitel
[Sicherheitserwägung](/docs/OpenPGP#sicherheitserwägung)

  - ~~secp256r1 (NIST P-256)~~ laut NSA nicht mehr sicher.
    <sup>[\[8\]](#quellen)</sup>
  - ~~secp256k1~~ laut NSA nicht mehr sicher.
    <sup>[\[8\]](#quellen)</sup>
  - secp384r1 (NIST P-384)
  - secp521r1 (NIST P-521)
  - ~~brainpoolP256r1~~ laut NSA nicht mehr sicher.
    <sup>[\[8\]](#quellen)</sup>
  - brainpoolP384r1
  - brainpoolP512r1
  - curve25519
      - x25519 (decipher only)
      - ed25519 (sign / auth only)

### GnuPG konfigurieren

Für Schlüssellängen über 2048 bits muss GnuPG Version 2.0 oder höher
verwendet werden.<sup>[\[1\]](#quellen)</sup> Für die Verwendung von ECC
zur Schlüsselerzeugung muss GnuPG Version 2.1 oder höher verwendet
werden.<sup>[\[11\]](#quellen)</sup>

### Hauptschlüssel erzeugen

Zur Demonstration der Standardeinstellungen werden die Schlüssel mit RSA
(Schlüssellänge: 4096 Bit) erzeugt. Dieser Hauptschlüssel wird nur zum
zertifizieren der 3 Unterschlüssel verwendet.

``` bash
gpg --expert --full-gen-key
...
Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
   (9) ECC and ECC
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (13) Existing key
```

"8" für RSA und eigene Eigenschaften

``` bash
Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished
```

Hier einmal "E" und einmal "S", dass nur mehr "zertifizieren"
überbleibt.

``` bash
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048)
```

"4096" für die Schlüssellänge.

``` bash
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0)
```

Es ist für den Hauptschlüssel nicht sinnvoll ein Ablaufdatum zu finden,
dafür sind Widerrufszertifikat in diesem Fall viel besser
geeignet.<sup>[\[7, Kap. Master key\]](#quellen)</sup>

``` bash
Real name:
Email address:
Comment:
```

Weiters den Name, die E-Mail Addresse und optional noch ein Kommentar
zum Schlüssel huinzufügen. Wenn weiters die "USER-ID" in Ordnung ist mit
"O" bestätigen. Ein Dialogfenster für das Schlüsselpasswort erscheint.
Dies sollte gesetzt werden. Es wird dann der Schlüssel erzeugt. Am
Schluss erhält man eine Identifikationsnummer vom Schlüssel, die etwa
so:

``` bash
13AFCE85
```

aussieht. Diese sollte notiert werden, da sie zur weiteren Konfiguration
benötigt wird.

### Unterschlüssel erzeugen

Mit

``` bash
gpg --expert --edit-key 13AFCE85
```

die Bearbeitung des Hauptschlüssels starten.

Und mit

``` bash
gpg> save
```

beenden.

Schlüsselerzeugung verifizieren (Alle generierten privaten Schlüssel
auflisten):

``` bash
gpg -K
```

#### Wieso 3 Unterschlüssel?

Wenn z.B.: ein Encryption Key kompromittiert wird, dann kann aus dem
Hauptschlüssel relativ problemlos ein neuer Unterschlüssel zertifiziert
werden.

#### Signierschlüssel

Nun fügen wir zum Hauptschlüssel einen Signierschlüssel hinzu.

``` bash
addkey
```

Als nächstes muss das Schlüsselpasswort eingegeben werden.

``` bash
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
```

"4" für einen Signierschlüssel.

``` bash
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048)
```

"4096" für die Schlüssellänge.

``` bash
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
```

Hier sollte ein Zeitraum unter 2 Jahren verwendet werden. <sup>[\[6,
Kap. Key configuration\]](#quellen)</sup>

``` bash
Is this correct? (y/N) y
Really create? (y/N) y
```

Eingabe bestätigen und Schlüsselerzeugung bestätigen. Der Schlüssel wird
nun erzeugt.

#### Encryption Key

Nun fügen wir zum Hauptschlüssel einen Encryption Key hinzu.

``` bash
addkey
```

Als nächstes muss das Schlüsselpasswort eingegeben werden.

``` bash
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
```

"6" für einen Encryption Key.

``` bash
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048)
```

"4096" für die Schlüssellänge.

``` bash
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
```

Hier sollte ein Zeitraum unter 2 Jahren verwendet werden. <sup>[\[6,
Kap. Key configuration\]](#quellen)</sup>

``` bash
Is this correct? (y/N) y
Really create? (y/N) y
```

Eingabe bestätigen und Schlüsselerzeugung bestätigen. Der Schlüssel wird
nun erzeugt.

#### Authentifizierungsschlüssel

Nun fügen wir zum Hauptschlüssel einen Authentifizierungsschlüssel
hinzu.

``` bash
addkey
```

Als nächstes muss das Schlüsselpasswort eingegeben werden.

``` bash
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
```

"8" für einen Schlüssel mit eigenen Eigenschaften.

``` bash
Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Sign Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished
```

"S", "E", "A" jeweils einmal eingeben, um

``` bash
Current allowed actions: Authenticate
```

zu erhalten. Mit "Q" bestätigen.

``` bash
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048)
```

"4096" für die Schlüssellänge.

``` bash
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
```

Hier sollte ein Zeitraum unter 2 Jahren verwendet werden. <sup>[\[6,
Kap. Key configuration\]](#quellen)</sup>

``` bash
Is this correct? (y/N) y
Really create? (y/N) y
```

Eingabe bestätigen und Schlüsselerzeugeung bestätigen. Der Schlüssel
wird nun erzeugt.

### Widerrufszertifikat erstellen

Obwohl der Hauptschlüssel gesichert und an einem sicheren Ort aufbewahrt
wird, ist niemals auszuschliessen, dass er verloren geht oder die
Sicherung fehlschlägt. Ohne den Hauptschlüssel ist es unmöglich,
Unterschlüssel zu erneuern oder ein Widerrufszertifikat zu generieren.
Die PGP-Identität ist somit unbrauchbar.

``` bash
gpg --output ./revoke.asc --gen-revoke 13AFCE85
```

Weitere Informationen und die Anleitung zum Schlüssel widerrufen gibt es
im Artikel [Schlüssel
widerrufen](/docs/OpenPGP/mailverschluesselung#schlüssel-widerrufen).

### Backup

Der Speicherort sollte offenkundig nicht irgendein (Cloud)System wie
OwnCloud, welches vom Internet aus erreichbar ist, sein. Am Besten
eignet sich dazu ein sogenannter "cold storage". Damit meint man ein
Speichermedium, dass nur für den Zugriff und am Besten verschlüsselt
aktiviert wird. Dazu eignen sich z.B. USB- Sticks, CD/DVDs, externe
Festplatten oder Magnetbänder. Es spricht außerdem auch nichts dagegen
den Schlüssel ausgedruckt auf Papier in einem Safe aufzubewahren. Ein
Backup ist notwendig, weil wenn die Schlüssel einmal auf den YubiKey
geladen wurden, kann man sie nicht mehr verschieben.

Export des Hauptschlüssels

``` bash
gpg -o \path\to\dir\mastersub.gpg --armor --export-secret-keys 13AFCE85
```

Export der Unterschlüssel

``` bash
gpg -o \path\to\dir\sub.gpg --armor --export-secret-subkeys 13AFCE85
```

### Schlüssel auf den YubiKey laden

```danger
keytocard löscht die lokale Kopie des Schlüssels, also muss er vorher gesichert werden.
```
Transferieren mit

``` bash
gpg --edit-key 13AFCE85
```

starten.

#### Signierschlüssel

Ersten Schlüssel auswählen. (Oder den Schlüssel mit der
Signier-Eigenschaft) Dann auf den YubiKey hochladen.

``` bash
key 1
keytocard
Please select where to store the key:
   (1) Signature key
   (3) Authentication key
```

#### Encryption Key

Ersten Schlüssel abwählen. Zweiten Schlüssel auswählen (Oder den
Schlüssel mit der Verschlüsselung-Eigenschaft) Dann auf den YubiKey
hochladen.

``` bash
key 1
key 2
keytocard
```

#### Authentifizierungsschlüssel

Zweiten Schlüssel abwählen. Dritten Schlüssel auswählen (Oder den
Schlüssel mit der Authentifizierung-Eigenschaft) Dann auf den YubiKey
hochladen.

``` bash
key 2
key 3
keytocard
```

## Metadaten auf den Yubikey laden

Beispielausgabe der Metadaten eines konfigurierten OpenPGP YubiKeys

``` none
gpg --card-status
Reader ...........: Yubico YubiKey OTP FIDO CCID 0
Application ID ...: D2760001240103040006120153700000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 12015370
Name of cardholder: [nicht gesetzt]
Language prefs ...: [nicht gesetzt]
Salutation .......:
URL of public key : https://keys.openpgp.org/vks/v1/by-fingerprint/842C9402A84CFFD2344AF38204D2E3D3F71DBECC
Login data .......: [nicht gesetzt]
Signature PIN ....: nicht zwingend
Key attributes ...: rsa4096 rsa4096 rsa4096
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 7
KDF setting ......: off
Signature key ....: BD76 F20E 3740 6414 E7FB  F85F 8FCC 649B 0FB5 3711
      created ....: 2020-05-04 15:01:08
Encryption key....: C1C2 4A67 E0FD 1B3D 0419  9280 3E96 DDC4 D604 CB19
      created ....: 2020-04-24 16:17:45
Authentication key: B002 73B3 DDAE F45A A1C0  9471 B5D6 D5CF 4266 D204
      created ....: 2020-05-04 15:02:06
General key info..: sub  rsa4096/8FCC649B0FB53711 2020-05-04 Max Muster <ubKe4@tWin.at>
sec   rsa4096/04D2E3D3F71DBECC  erzeugt: 2020-04-24  verfällt: 2025-04-23
ssb>  rsa4096/3E96DDC4D604CB19  erzeugt: 2020-04-24  verfällt: 2025-04-23
                                Kartennummer:0006 12015370
ssb>  rsa4096/8FCC649B0FB53711  erzeugt: 2020-05-04  verfällt: 2025-05-03
                                Kartennummer:0006 12015370
ssb>  rsa4096/B5D6D5CF4266D204  erzeugt: 2020-05-04  verfällt: 2025-05-03
                                Kartennummer:0006 12015370
```

Felder:

  - Application ID: Hersteller ID
  - Application type: Anwendung im Klartext
  - Version: Version der verwendeten OpenPGP Spezifikation
  - Manufacturer: Herstellername der "Karte"
  - Serial Number: eindeutige Nummer für alle "Karten" des Herstellers
  - Name of cardholder: Name des Kartenbesitzers (nur ASCII erlaubt)
  - Language prefs: Sprachpräferenz des Kartenbesitzers gpg ignoriert
    dieses Feld
  - Salutation: Männlich oder Weiblich (gpg ignoriert dieses Feld)
  - URL of public key: URL fürs Herunterladen des öffentlichen
    Schlüssels. Wird für das fetch command bei gpg --edit-card
    verwendet. 
  - Login data: Benutzername des Kartenbesitzers (ist nicht zwingend in
    gpg und wird auch nicht mit den Namen in den Schlüssel überprüft)
  - Signature PIN: 
      - zwingend = bei jeder Signatur ist der PIN erforderlich / 
      - nicht zwingend = solange, wie die Karte stecken bleibt, wird der
        PIN zwischengespeichert.
  - Key attributes: Schlüsselparameter (verwendete Algorithmen)
  - Max. PIN lengths: Feld ist nicht änderbar 
  - Signature counter: Anzahl der für den gespeicherten Schlüssel
    ausgestellte Signaturen
  - KDF setting: Schlüsselableitungsfunktion ein / aus
  - Signature key: standardmäßig verwendeter Signaturschlüssel für
    OpenPGP
  - Encryption key: standardmäßig verwendeter Encryption Key für OpenPGP
  - Authentication key: standardmäßig verwendeter
    Authentizierungsschlüssel für OpenPGP
  - General key info: Wenn ein öffentlicher OpenPGP Schlüssel vorhanden
    ist, wird hier die eindeutige Benutzer ID angezeigt

**Setzen des "URL of public key" Feldes:**

Als erstes mit "gpg -edit-card" in den Konfigurationsmodus wechseln,
dann mit "admin" die Administratorkommandos aktivieren. Jetzt mit "url"
das "URL of public key" Feld setzen. Falls notwendig noch den
Konfigurationspin eingeben.

**Import des Schlüssels vom "URL of public key" Feld:**

``` bash
kali@kali:~$ gpg --edit-card
gpg/card> fetch
gpg/card> quit
```

## Einsatzszenarien

  - [Email Verschlüsselung](/docs/OpenPGP/mailverschluesselung):
    Beispielanwendungen zur OpenPGP Email Verschlüsselung in Thunderbird
    und Enigmail
  - [SSH-Public-Key-Authentication](/docs/OpenPGP/ssh-authentifizierung):
    Beispielanwendungen von OpenPGP zur Public-Key-Authentication für
    eine SSH Shell

## Sicherheitserwägung

Für eine Post-Quantum-Computing Sicherheit sind RSA, wie auch ECC laut
dem "Department of Informatics, University of Oslo, Norway" nicht
geeignet.<sup>[\[9\]](#quellen)</sup> Für RSA ist zu sagen, dass bei
zeit-unkritischen Anwendungen die größtmögliche Schlüssellänge (im Fall
des YubyKey 4096 Bit) verwendet werden sollte, da sich mit längeren
Schlüsseln die Zeit, die benötigt wird um den Schlüssel zu knacken,
ebenfalls verlängert. Bei der Betrachtung der unterstützten ECC
Algorithmen wäre laut "SafeCurves" jede der Kurven, außer die
"curve25519" nicht sicher.<sup>[\[5\]](#quellen)</sup> Die 11
verschiedene Eigenschaften, mit denen die Kurven bewertet wurden:

  - [Fields](https://safecurves.cr.yp.to/field.html)
  - [Equations](https://safecurves.cr.yp.to/equation.html)
  - [Base points](https://safecurves.cr.yp.to/base.html)
  - [The rho method](https://safecurves.cr.yp.to/rho.html)
  - [Transfers](https://safecurves.cr.yp.to/transfer.html)
  - [CM field discriminants](https://safecurves.cr.yp.to/disc.html)
  - [Rigidity](https://safecurves.cr.yp.to/rigid.html)
  - [Ladders](https://safecurves.cr.yp.to/ladder.html)
  - [Twist security](https://safecurves.cr.yp.to/twist.html)
  - [Completeness](https://safecurves.cr.yp.to/complete.html)
  - [Indistinguishability from uniform random
    strings](https://safecurves.cr.yp.to/ind.html)

Ein wichtiger Faktor ist "Rigidity". Dieser besagt, ob die
Parameterfindung der Kurve vollständig erklärt, oder verschwiegen wird.
Durch diesen Faktor fallen alle "NIST"-Kurven durch. Der Vergleich auf
"SafeCurves" wird
[hier](https://satoshinichi.gitlab.io/b/safecurves-scare.html) noch
näher erläutert. Es ist sozusagen eine Glaubensfrage, ob man der
Parameterfindung vertraut, oder nicht.

```tip
**Sicherheitswerwägung:** Die Empfehlung liegt auf der "curve25519", da selbst die "NIST" diese Kurve empfiehlt. [\[10\]](#quellen)
```

-----

## Quellen

\[1\] Yubico, *YubiKey 5 NFC*, Letzter Zugriff 11.05.2020, \[Online\],
URL:
<https://support.yubico.com/support/solutions/articles/15000014174--yubikey-5-nfc>  
\[2\] Yubico, *YubiKey Manager CLI User Guide*, Letzter Zugriff
05.05.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide>  
\[3\] Yubico, *What is PGP?*, Letzter Zugriff 25.04.2020, \[Online\],
URL: <https://developers.yubico.com/PGP/>  
\[4\] BSI, *Cryptographic Mechanisms: Recommendations and Key Lengths*,
Letzter Zugriff 11.05.2020, \[Online\], URL:
<https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile>  
\[5\] Daniel J. Bernstein und Tanja Lange, *SafeCurves:choosing safe
curves for elliptic-curve cryptography*, Letzter Zugriff 11.05.2020,
\[Online\], URL: <https://safecurves.cr.yp.to/>  
\[6\] Riseup Autonomous tech collective, *OpenPGP Best Practices*,
Letzter Zugriff 03.06.2020, \[Online\], URL:
<https://riseup.net/en/security/message-security/openpgp/best-practices>  
\[7\] drduh,GPG: 0xFF3E7D88647EBCDB *YubiKey-Guide*, Letzter Zugriff
03.06.2020, \[Online\], URL: <https://github.com/drduh/YubiKey-Guide>  
\[8\] NSA *​Commercial National Security Algorithm (CNSA) Suite*,
Letzter Zugriff 13.06.2020, \[Online\], URL:
<https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/commercial-national-security-algorithm-suite-factsheet.cfm>  
\[9\] Department of Informatics, University of Oslo, Norway *The Impact
of Quantum Computing on Present Cryptography*, Letzter Zugriff
13.06.2020, \[Online\], URL: <https://arxiv.org/pdf/1804.00200.pdf>  
\[10\] NIST *Transition Plans for Key Establishment Schemes using Public
Key Cryptography*, Letzter Zugriff 13.06.2020, \[Online\], URL:
<https://csrc.nist.gov/News/2017/Transition-Plans-for-Key-Establishment-Schemes>  
\[11\] GnuPG *Release Notes for GnuPG*, Letzter Zugriff 13.06.2020,
\[Online\], URL: <https://www.gnupg.org/download/release\_notes.html>  

**Fußnoten:**

[^1]: Der hierfür gespeicherte Private-Key wird eigentlich zum Entschlüsseln verwendet, obwohl er Encryption-Key ("Verschlüsselungs-Schlüssel") heißt.
