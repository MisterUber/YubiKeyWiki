# Systemlogin mit FIDO2 und U2F

{% include acronyms.md %}

## Linux

**Pluggable Authentication Modules**

PAM bietet eine Infrastruktur, die es Programmen ermöglicht, Benutzer
über konfigurierbare Module zu authentifizieren. Neben der reinen
Authentifizierung ist ein ganzes Session Management möglich.
<sup>[\[1\]](#quellen)</sup> Zusätzliche Infos zum Yubico PAM:
<https://developers.yubico.com/yubico-pam/>

### Installation

Zur Verwendung des YubiKeys als Login bzw. Sudo Authentifikator muss das
Paket "libpam-u2f" aus dem Repo "ppa:yubico/stable" installiert werden.
Das geht beispielsweise über die apt-Paketverwaltung:

``` bash
sudo apt-get install libpam-u2f
```

Falls das Paket nicht gefunden wird muss das PPA von Yubico eingebunden
werden. Dazu

``` bash
sudo add-apt-repository ppa:yubico/stable && sudo apt-get update
```

ausführen. Das sollte aber im Normalfall nicht nötig sein.

### Assoziieren des YubiKeys mit dem Benutzer

Den YubiKey einstecken. Dann den Ordner "Yubico" in /etc erzeugen.

``` bash
sudo mk /etc/Yubico/ 
```

Wenn man hier einen Fehler bekommt, dass der Ordner schon existiert,
kann man diesen ignorieren und fortfahren.

**Authorization Mapping Files**

Dieser Filetyp wird automatisch durch das Tool "pamu2fcfg" erzeugt. Er
enthält die Zuweisung vom Benutzernamen zum jeweiligen "KeyHandle" und
öffentlichen Schlüssel des YubiKeys. Es kann mehrere
"\<KeyHandle1\>,\<UserKey1\>" pro Benutzer geben. Um mehrere Benutzer in
einem File zu verwalten, muss jeder Benutzer in einer eigenen Zeile
stehen. Format: **<username1\>:\<KeyHandle1\>,\<UserKey1\>**.
Weitere Informationen zu Authorization Mapping Files: [Yubico DOC
pam-u2f](https://developers.yubico.com/pam-u2f/#files)

Nun kann man durch das mitinstallierte Programm "pamu2fcfg" einen neuen
U2F-Schlüssel am YubiKey erzeugen lassen und den Key-Handle in die Datei
"u2f\_keys" unter "/etc/Yubico/" schreiben.

``` bash
pamu2fcfg | sudo tee -a /etc/Yubico/u2f_keys
```

Wenn nun der YubiKey zu blinken beginnt, mit einer Berührung bestätigen.

Wenn man einen zweiten Schlüssel als Backup assoziieren möchte, muss man
diesen einfach an die bestehende Datei anhängen:

``` bash
pamu2fcfg -n | sudo tee -a /etc/Yubico/u2f_keys
```

Es ist sehr zu empfehlen einen zweiten Schlüssel zu assoziieren. Falls
ein Schlüssel verloren geht, ist man, je nach Konfiguration, aus seinem
PC ausgesperrt.

```tip
**Sicherheitserwägung:** Wenn man eine weitere Sicherheitsschicht
einziehen will, kann man den Speicherort der Schlüsselassoziationen, auf
einen Speicherbereich der "sudo"-Berechtigung benötigt, verschieben.
(Zum Beispiel: "/etc", wie wir das auch hier im Wiki machen), dabei muss
man jedoch später den Pfad zum File in die jeweilige Konfiguration im
"/etc/pam.d/" einfügen. z.B.: **"authfile=/etc/Yubico/u2f\_keys"** an
die PAM Datei anfügen. Wenn kein "authfile" Parameter beim PAM Eintrag
dabei ist, wird standardmäßig auf das File "
\~/.config/Yubico/u2f\_keys" zugegriffen.
```


### Konfiguration des System

#### Login

Zur Konfiguration der PAM-Module für den Login muss je nach verwendetem
"Display Manager" die adäquate Datei bearbeitet werden. Auf unserem
Kali-Testsystem wäre das der LightDm. (also "/etc/pam.d/lightdm"). Es
gibt nun zwei Varianten, wie man den YubiKey verwenden kann:

  - Zweiter Faktor
  - Einzelner zusätzlicher Faktor (also als optionale Alternative zum
    Passwort)

\<code bash\> sudo nano /etc/pam.d/lightdm \</code\> Soll nun der
YubiKey als zweiter Faktor verwendet werden. Muss \<code bash\> auth
required pam\_u2f.so authfile=/etc/Yubico/u2f\_keys\</code\> unter
"@ include common-auth" eingefügt und mit Ctrl+X und Enter bestätigt und
gespeichert werden. Ab jetzt kann man sich auf den bearbeiteten Benutzer
nur mehr mit Passwort und dem zweiten Faktor einloggen. Anmeldeablauf:

  - Mit YubiKey: Benutzername + Passwort eingeben -\> Einloggen drücken
    -\> YubiKey bestätigen (mit evtl. Pineingabe)
  - Ohne YubiKey: Kein Login möglich

Für die Verwendung als eine weitere Möglichkeit für den Login öffnet man
die PAM Datei des eigenen "Display Managers" wie oben erklärt. Man fügt
nun die Zeile \<code bash\> auth sufficient pam\_u2f.so
authfile=/etc/Yubico/u2f\_keys \</code\> über "@ include common-auth"
ein. So sagt man, dass der Schlüssel alleine ausreichend für den Login
ist. Bei dieser Variante kann man sich, wenn der YubiKey nicht
angesteckt ist, noch ganz normal mit Benutzername und Passwort
einloggen. Anmeldeablauf:

  - Mit YubiKey: Benutzername -\> Einloggen drücken -\> YubiKey
    bestätigen
  - Ohne YubiKey: Benutzername + Passwort eingeben -\> Einloggen drücken

Beide Varianten haben ihre Vor- und Nachteile. Sicherheitstechnisch ist
jedoch nur die Zwei Faktor Authentifizierung zu empfehlen. Da bei der
zweiten Variante nur mehr den Benutzer und den YubiKey braucht um sich
einzuloggen. Das kann positiv (Benutzerfreundlichkeit), wie auch negativ
(2 Einfallstore beim Login) gesehen werden.

#### Sudo

```warning
Wenn man die "sudo" PAM Datei ("/etc/pam.d/sudo") einmal zur Verwendung des YubiKeys konfiguriert hat, kann man dieses nur
mehr mitt dem YubiKey bearbeiten. Das heißt bei einem verlorenen oder
verlegten YubiKey kann man diesen nicht mehr aus der Konfiguration
entfernen. Es empfiehlt sich also zum Testen, ein Admin-Terminal
geöffnet zu halten und in einem neuen Terminal die Verwendung des
YubiKey mit Sudo zu testen. Sollte das nicht klappen, kann man im
Admin-Terminal immer noch die sudo-Datei anpassen.
```

Zur Konfiguration der PAM-Module für "sudo" muss die PAM Datei
"/etc/pam.d/sudo" bearbeitet werden. Es gibt, wie auch beim Login zwei
Möglichkeiten:

  - Zweiter Faktor
  - Einzelner zusätzlicher Faktor (also als optionale Alternative zum
    Passwort)

\<code bash\> sudo nano /etc/pam.d/sudo\</code\> Soll nun der YubiKey
als zweiter Faktor verwendet werden. Muss \<code bash\> auth required
pam\_u2f.so authfile=/etc/Yubico/u2f\_keys\</code\> unter "@ include
common-auth" eingefügt und gespeichert werden. Ab jetzt kann man die
"sudo"-Funktionalität nur mehr mit dem zweiten Faktor benutzen.
Verwendung:

  - Mit YubiKey: Passwort eingeben -\> Enter -\> YubiKey bestätigen
  - Ohne YubiKey: Keine Verwendung möglich

Für die Verwendung als eine weitere Möglichkeit muss die
"sudo"-PAM-Datei, wie oben beschrieben, geöffnet werden und die Zeile
\<code bash\> auth sufficient pam\_u2f.so
authfile=/etc/Yubico/u2f\_keys\</code\> über "@ include common-auth"
eingefügt werden. Nun kann man durch die alleinige Berührung des
YubiKeys "sudo" bestätigen. Wenn der Schlüssel nicht angesteckt ist,
fällt man automatisch auf das Passwort zurück. Verwendung:

  - Mit YubiKey: YubiKey bestätigen
  - Ohne YubiKey: Passwort eingeben

## Windows

Bei "Windows Hello" besteht in der aktuellen Version das Problem, dass
man FIDO2 (also den YubiKey) für Microsoft Accounts setzen kann, aber
nur zur "strong authentication" für den Online Microsoft Account
verwenden kann. Es ermöglicht also derzeit nur die Web-Anmeldung beim
Microsoft-Account, nicht jedoch das lokale Einloggen am
Windows-Rechner\! Die Möglichkeit FIDO 2 über einen AD (Active
Directory) oder AAD (Azure Active Directory) zu verwenden gibt es zwar,
ist aber im privaten Kontext nicht sinnvoll. [Weitere Infos zur FIDO 2
Verwendung im AD / AAD
Umfeld](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless#fido2-security-keys).

Für lokale Benutzer gibt es den proprietären Login-Provider von Yubico.
<sup>[\[2\]](#quellen)</sup> Dieser funktioniert aber über die
Konfiguration eines OTP-Slots (HMAC-SHA-1 mit 20 Byte Schlüssellänge):
[Konfigurationsanleitung für lokale
Windowsbenutzer](https://support.yubico.com/support/solutions/articles/15000028729-yubico-login-for-windows-configuration-guide).
Verwendet man diesen Login-Provider von Yubico, kann man sich beim
ausgewählten lokalen Benutzeraccount nur mehr mit dem YubiKey als
zweiten Faktor einloggen. Wir empfehlen jedoch abzuwarten, bis Microsoft
die Verwendung eines Sicherheitsschlüssels beim System-Login anbietet.

-----

## Quellen

\[1\] Waldmann EDV Systeme & Service, *PAM*, Letzter Zugriff 23.06.2020,
\[Online\], URL: <https://linuxwiki.de/PAM>  
\[2\] Yubico, *Secure Windows with strong authentication*, Letzter
Zugriff 23.06.2020, \[Online\], URL:
<https://www.yubico.com/products/services-software/download/computer-login-tools/>
