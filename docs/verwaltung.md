# YubiKey Verwaltung

{% include acronyms.md %}

Wie bereits in der Kurzbeschreibung erwähnt gibt es von Yubico drei
Programme zur Verwaltung des YubiKey.

  - **YubiKey Manager**
    ([ykman](https://developers.yubico.com/yubikey-manager/))
  - **YubiKey Personalization Tool**
    ([ykpers](https://developers.yubico.com/yubikey-personalization/))
  - **Yubico Authenticator**
    ([ybioath](https://developers.yubico.com/OATH/YubiKey_OATH_software.html))

Abgesehen davon, muss man beim Manager noch zwischen GUI (Grafischer
Anwendung) und der Konsolenanwendung CLI (Command Line Interface)
unterscheiden, da diese einen anderen Funktionsumfang bieten. Die
YubiKey Manager GUI ("ykman") bietet zwar sehr viele Möglichkeit den
YubiKey zu verwalten. Einige Funktionen, die es in der CLI gibt, haben
es aber leider derzeit noch nicht in die GUI geschafft. Die GUI ist in
Entwicklung, also besteht eine gute Chance, das in Zukunft auch der
vollen Funktionsumfang in der GUI abgebildet sein
wird.<sup>[\[1\]](#quellen)</sup> Die verfügbaren Funktionen kann man in
der untenstehenden [Funktionsübersicht](#1-funktionsübersicht) ablesen.

```tip
Wir empfehlen die Verwendung des YubiKey Manager in der
Kommandozeile. Unsere Beschreibungen werden sich im Wiki fast
ausschließlich darauf stützen.
```

```note
Eine vollständige Befehlsübersicht mit allen
Einstellmöglichkeiten bietet das [YubiKey Manager CLI User
Manual](https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide).
Da dort einige Befehle nicht ausreichend beschrieben sind, werden hier
nach der [Installationsbeschreibung](#2-installation) der Verwaltungstools
von Yubico auch einige [Einstellungsmöglichkeiten](#3-einstellungsmöglichkeiten) genauer erklärt
und mit Beispielen und Sicherheitsaspekten versehen.
```

## 1 Funktionsübersicht

Die folgende Tabelle bietet eine Übersicht darüber, welche Einstellungen
man über die jeweiligen Einstellungs-Programme von Yubico verwalten
kann.

| Einstellung                                                         | YubiKey Manager CLI               | YubiKey Manager GUI                           | YubiKey Personalization Tool | Yubico Authenticator |
| ------------------------------------------------------------------- | --------------------------------- | --------------------------------------------- | ---------------------------- | -------------------- |
| [Seriennummer auslesen](#31-seriennummer-auslesen)                   | x                                 | x                                             | x                            | x                    |
| [Firmwareversion auslesen](#32-firmwareversion-auslesen)             | x                                 | x                                             | x                            | x                    |
| [Anwendungsstatus auslesen](#33-anwendungsstatus-auslesen)           | x                                 | x                                             |                              |                      |
| [Anwendungen De/Aktivieren](#34-anwendungen-deaktivieren)           | x                                 | x                                             |                              |                      |
| [Konfigurationspasswort setzen](#35-konfigurationspasswort-setzen)   | x                                 |                                               |                              |                      |
| [OTP Anwendungen verwalten](#36-otp-anwendungen-verwalten)         | x                                 | [vereinfacht](#362-yubikey-manager-gui-otp) | x                            |                      |
| [OATH verwalten und verwenden](#37-oath-verwalten-und-verwenden) | x                                 |                                               |                              | x                    |
| [FIDO verwalten](#38-fido-verwalten)                                 | x                                 | x                                             |                              |                      |
| [PIV verwalten](#39-piv-verwalten)                                   | x                                 | x                                             |                              |                      |
| [OpenPGP verwalten](#310-openpgp-verwalten)                           | [teilweise](#310-openpgp-verwalten) |                                               |                              |                      |

-----

## 2 Installation

### 2.1 Linux

#### 2.1.1 YubiKey Manager CLI

Linux (Debian und Ubunut):

``` bash
sudo apt-get install yubikey-manager
```

Auf der Website von Yubico ist zusätzlich die Installation für Ubuntu
Bionic (18.04 LTS)<sup>[\[1\]](#quellen)</sup> beschrieben, wo das Paket
noch aus einem Private Package Archive (PPA) von Yubico installiert
werden muss:

``` bash
sudo apt-add-repository ppa:yubico/stable
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 32CBA1A9
sudo apt-get update
sudo apt-get install yubikey-manager
```

Alternativ kann man den YubiKey Manager auch über den Quelltext
installieren. Hierzu die folgenden Befehle ausführen:

``` bash
sudo apt-get install swig libykpers-1-1 libu2f-udev pcscd libpcsclite-dev
git clone https://github.com/Yubico/yubikey-manager.git
cd yubikey-manager
pip install -e .
```

  
#### 2.1.2 YubiKey Manager GUI

Für Linux gibt es wieder zwei Wege. Der erste und leichtere Weg ist das
Herunterladen des AppImage-Files
[hier](https://developers.yubico.com/yubikey-manager-qt/Releases/). Das
muss nach dem Herunterladen noch ausführbar gemacht werden und man kann
schon loslegen.

``` bash
chmod +x yubikey-manager-qt-version-linux.AppImage
```

Der zweite Weg ist wieder das Instalieren von der Source:  
Dependencies:

``` bash
sudo add-apt-repository -y ppa:yubico/stable
sudo apt-get update
sudo apt-get install \
  libqt5svg5-dev \
  python3-yubikey-manager \
  qml-module-io-thp-pyotherside \
  qml-module-qt-labs-calendar \
  qml-module-qt-labs-folderlistmodel \
  qml-module-qt-labs-platform \
  qml-module-qt-labs-settings \
  qml-module-qtgraphicaleffects \
  qml-module-qtquick-controls2 \
  qml-module-qtquick-dialogs \
  qml-module-qtquick-layouts \
  qml-module-qtquick-window2 \
  qml-module-qtquick2 \
  qt5-default \
  qtbase5-dev \
  qtdeclarative5-dev \
  qtquickcontrols2-5-dev
```

``` bash
git clone https://github.com/Yubico/yubikey-manager-qt.git
cd yubikey-manager-qt
qmake && make
```

  
#### 2.1.3 YubiKey Personalization Tool

``` bash
sudo apt-get install yubikey-personalization
```

Oder von [dieser
Seite](https://www.yubico.com/products/services-software/download/yubikey-personalization-tools)
herunterladen und wie folgt installieren:

``` bash
sudo apt-get install libusb-1.0-0-dev qt4-qmake libykpers-1-dev \
      libyubikey-dev libqt4-dev
tar xvf yubikey-personalization-gui-3.1.25.tar.gz
cd yubikey-personalization-gui-3.1.25
qmake && make
```

und starten der Anwendung mit:

``` bash
./build/release/yubikey-personalization-gui 
```

  
#### 2.1.4 Yubico Authenticator
Der Authenticator kann
[hier](https://developers.yubico.com/yubioath-desktop/Releases/)
heruntergeladen werden. Für Linux ist es am Einfachsten, das
AppImage-File herunterzuladen. Das AppImage muss dann nur noch
ausführbar gemacht werden.

``` bash
chmod +x yubioath-desktop-<VERSION>-linux.AppImage
```

  
  
### 2.2 Windows

#### 2.2.1 YubiKey Manager CLI/GUI

Für Windows-Benutzer muss die
[GUI-Version](https://www.yubico.com/products/services-software/download/yubikey-manager/)
heruntergeladen werden, da in dessen Version das CLI-Tool integriert
ist.  
Wichtig, um das CLI-Tool zu verwenden muss in den Installationsordner
navigiert werden. Alternativ kann man den Pfad auch zu den
Systemvariablen hinzufügen. Dafür klickt man auf das Winodws Symbol
links unten und gibt "systemvariable" ein. Dann müsste schon die
Systemsteuerung "Systemumgebungsvariablen bearbeiten" auswählbar sein.
Dort einfach bei der "Path"-Variable den Pfad zur "ykman.exe"
hinzufügen.

#### 2.2.2 YubiKey Personalization Tool

[Hier](https://www.yubico.com/products/services-software/download/yubikey-personalization-tools/)
die neueste Version herunterladen und installieren.

#### 2.2.3 Yubico Authenticator

[Hier](https://www.yubico.com/products/services-software/download/yubikey-personalization-tools/)
die neueste Version herunterladen und installieren.  
  
#### 2.3 Android

#### 2.3.1 Yubico Authenticator

Um das Tool zu installieren, einfach im Google Playstore nach "Yubico
Authenticator" suchen.

-----

## 3 Einstellungsmöglichkeiten

### 3.1 Seriennummer auslesen

*Verfügbar für: CLI, GUI, Personalization Tool, Authenticator*  
  
Die Seriennummer ist ein wichtiges Unterscheidungsmerkmal des YubiKey.
Es ist eine eindeutige, achtstellige Zahl, welche jedem YubiKey
zugeordnet ist. Wenn man mehrere YubiKeys gleichzeitig mit dem YubiKey
Manager CLI administrieren möchte, dient sie zur Auswahl bei
Einstellungsvorgängen. Auch bei der Kommunikation mit dem Yubico Support
wird nach dieser gefragt. Verwendet man die YubiKey Manager GUI darf nur
ein YubiKey angesteckt sein, um zu funktionieren. Das Personalization
Tool und der Authenticator hingegen zeigen nur einen Verbundenen YubiKey
an.  
Die Seriennummer ist auch auf der Rückseite des YubiKey 5 NFC
abzulesen:  
![Seriennummer am YubiKey 5 NFC]({{ site.baseurl }}{{ page.dir }}img/yubikey5nfc_back.jpg){: width="100px"}

#### 3.1.1 YubiKey Manager CLI

Um die Seriennummern der verbunden
YubiKeys zu erhalten, muss man folgenden Befehl ausführen. Wenn man zwei
oder mehr YubiKeys verbunden hat, erhält man auch dementsprechend viele
Seriennummern.<sup>[\[2\]](#quellen)</sup>

``` bash
ykman list --serials
```

Hierbei erhält man ausschließlich die Seriennummer. Um mehr
Informationen zu erhalten, kann man folgenden Befehl ausprobieren.

``` bash
ykman info
```

Hier ist zu beachten, dass dieser Befehl nur bei einem verbunden YubiKey
funktioniert. Wenn mehrere verbunden sind, muss der Befehl die Option
***--device SERIAL*** beinhalten. Der Befehl könnte also so
ausschauen:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman --device SERIAL info
```

Die Angabe der Seriennummer ist bei den meisten Befehlen von Nöten, wenn
man mehrere YubiKeys gleichzeitig konfigurieren will.  

#### 3.1.2 YubiKey Manager GUI

Direkt nach dem Starten zeigt der YubiKey Manager Typ, Firmware und
Seriennummer des Yubikey an. Zu dieser Ansicht kann man später auch über
das *Home* Menü zurückkehren.

![]({{ site.baseurl }}{{ page.dir }}img/manager_serialnr.png)

#### 3.1.3 Yubico Personalization Tool

Die Seriennummer ist im rechten Bereich des Tools zu finden.  
![]({{ site.baseurl }}{{ page.dir }}img/pers_tool_serialnr.png)

#### 3.1.4 Yubico Authenticator

In den Settings wird die Seriennumer ausgegeben.  
![]({{ site.baseurl }}{{ page.dir }}img/authenticator_serialnr.png)

-----

### 3.2 Firmwareversion auslesen

*Verfügbar für: CLI, GUI, Personalization Tool, Authenticator*  
  
Die Firmwareversion, eine wichtige Information, um die unterstützten
Features des YubiKey herauszufinden.  
Derzeit kann diese nicht aufgerüstet oder verändert werden, um
potentielle Angriffe auf die Sicherheit des YubiKeys vorzubeugen, so
Yubico<sup>[\[3\]](#quellen)</sup>

Leider gibt es keine durchgängigen Change-Logs oder einen fixe Seite um
den Update-Verlauf der YubiKey Firmware nachzuverfolgen. Nicht zuletzt
auch deswegen, weil die Software [nicht Open
Source](https://github.com/Yubico/ykneo-openpgp/issues/2#issuecomment-218446368)
ist. Handelt es sich aber um funktionale Verbesserungen, die einen
wesentlichen Vorteil für den Kunden bringen, veröffentlich Yubico
natürliche Informationen in seinen Blogs. So auch beim letzten großen
Update zur
[Firmware 5.2.3](https://www.yubico.com/blog/whats-new-in-yubikey-firmware-5-2-3/).
Um aus der Firmware-Version also schlau zu werden empfiehlt sich eine
Online-Suche.

```tip
**Sicherheitserwägung**: Yubico veröffentlicht bei sicherheitsrelevanten
Problemen bezüglich deren Produkte [Security
Advisories](https://www.yubico.com/support/security-advisories/). Es
empfiehlt sich dort regelmäßig vorbeizuschauen, oder die Security
Advisories per E-Mail zu [abonnieren](https://pages.yubico.com/email_subscription.html).
```


#### 3.2.1 YubiKey Manager CLI

Die Firmwareversion erhält man unter anderem mit diesem
Befehl:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman info
```

Die Ausgabe kann beispielsweise folgendermaßen aussehen:

``` bash
Device type: YubiKey 5 NFC
Serial number: SERIAL
Firmware version: 5.2.4
Form factor: Keychain (USB-A)
Enabled USB interfaces: OTP+FIDO+CCID
NFC interface is enabled.

Applications    USB     NFC
OTP             Enabled Enabled
FIDO U2F        Enabled Enabled
OpenPGP         Enabled Enabled
PIV             Enabled Enabled
OATH            Enabled Enabled
FIDO2           Enabled Enabled
```

In Zeile 3 ist die Firmware Version abzulesen.  

#### 3.2.2 YubiKey Manager GUI

Direkt nach dem Starten zeigt der YubiKey Manager Typ, Firmware und
Seriennummer des Yubikey an. Zu dieser Ansicht kann man später auch über
das Home Menü zurückkehren.

![]({{ site.baseurl }}{{ page.dir }}img/manager_serialnr.png)

#### 3.2.3 Yubico Personalization Tool

Die Firmware-Version ist im rechten Bereich des Tools zu finden.  
![]({{ site.baseurl }}{{ page.dir }}img/pers_tool_firmware.png)

#### 3.2.4 Yubico Authenticator

Die selbe Information ist bei dem kleinen i-Symbol unter Settings zu
finden.  
![]({{ site.baseurl }}{{ page.dir }}img/authenticator_firmware.png)

-----

### 3.3 Anwendungsstatus auslesen

*Verfügbar für: CLI, GUI*  
  
#### 3.3.1 YubiKey Manager CLI
Hier ist wieder der Befehl "info" von
Gebrauch. Für jede Schnittstelle wird eine eigene Spalte erstellt. Also
für den YubiKey 5 NFC gibt es die Spalten "USB" und "NFC", wie im
folgenden Snip zu sehen ist.<sup>[\[2\]](#quellen)</sup>

``` bash
ykman info
Device type: YubiKey 5 NFC
Serial number: SERIAL
Firmware version: 5.2.4
Form factor: Keychain (USB-A)
Enabled USB interfaces: OTP+FIDO+CCID
NFC interface is enabled.

Applications    USB     NFC
OTP             Enabled Enabled
FIDO U2F        Enabled Enabled
OpenPGP         Enabled Enabled
PIV             Enabled Enabled
OATH            Enabled Enabled
FIDO2           Enabled Enabled
```

Eine andere Option ist:

``` bash
ykman config usb -l
OTP
FIDO U2F
OpenPGP
PIV
OATH
FIDO2
```

Hierbei erhält man zu einem bestimmten Interface die Namen aller
aktivierten Anwendungen. Im Bespiel sind sämtliche Interfaces aktiviert.
Um die aktivierten Anwendungen für das NFC-Interface anzusehen, muss man
statt usb, nfc tippen.<sup>[\[2\]](#quellen)</sup>  

#### 3.3.2 YubiKey Manager GUI

Der Anwendungsstatus kann unter dem Reiter "Interfaces" erfragt
werden.  
![]({{ site.baseurl }}{{ page.dir }}img/manager_anwendungsstatus.png)

-----

### 3.4 Anwendungen De/Aktivieren

*Verfügbar für: CLI, GUI*  
  
Die verschiedenen Anwendungen die wir uns im vorherigen Absatz angesehen
haben, können jeder einzeln ein- bzw. ausgeschaltet werden. Hier stellt
Yubico den Benutzer frei, bestimmte Anwendungen am YubiKey zu sperren,
die man ohnehin nicht verwenden würde.  

```tip
**Sicherheitserwägung**: Im Sinne des [System
Hardening](https://csrc.nist.gov/glossary/term/Hardening) empfiehlt es
sich alle ungenutzten Services zu deaktivieren.
```

#### 3.4.1 YubiKey Manager CLI

Um jetzt ein Interface zu aktivieren oder zu deaktivieren, verwendet man
das "config"-Attribut. Der Befehl besitzt folgendes
Format:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman config [OPTION] COMMAND [ARG]
```

Das Option-Feld enthält in diesem Fall den Namen des Interfaces, also
entweder **usb** oder **nfc**. Als Command gibt man an, ob aktiviert
oder deaktivert werden soll. Die Kommandos lauten: **- -enable** oder
**- -disable**. Ein **- -enable-all** funktioniert auch, falls man alle
Anwendungen eines Interfaces mit einem Befehl setzen
will.<sup>[\[2\]](#quellen)</sup>  
Als letztes spezifiziert man die gewünschte Anwendung. Dessen Namen kann
man vom **Info-Kommando** ableiten. (*ykman info*)  
Wir nutzen beispielsweise nur die OpenPGP-Funktionalität über das
USB-Interface. Im Sinne des System Hardening deaktivieren wir dafür
zuerst alle Anwendungen und aktivieren dann nur OpenPGP für USB.:

``` bash
ykman config nfc --disable-all
ykman config usb --disable OTP
ykman config usb --disable U2F
ykman config usb --disable FIDO2
ykman config usb --disable PIV
ykman config usb --disable OATH
ykman config usb --enable PGP
```

Es ist leider nicht möglich, gleich mehrere Funktionen anzugeben. Die
**- -disable-all** Funktion gibt es laut Beschreibung eigentlich gar
nicht, für NFC funktioniert sie aber.  

#### 3.4.2 YubiKey Manager GUI

In der GUI ist die Sache um einiges einfacher. Hierzu navigiert man
unter **Interfaces** und klickt einfach neben der Anwendung auf dessen
Häkchen:  
![]({{ site.baseurl }}{{ page.dir }}img/manager_anwendung_aktivieren.png)

-----

### 3.5 Konfigurationspasswort setzen

*Verfügbar für: CLI*  
  
Um die eigene Konfiguration zu schützen, bietet sich das Setzen von
einem Konfigurationspasswort an. Dieses verhindert das Verändern der
Konfiguration anhand der config-Kommandos. Darunter fallen alle
Einstellungen zu den beiden Interfaces USB und NFC, wie zum Beispiel das
de- und aktivieren von Anwendungen. Das Passwort muss im Hex-Format und
32 Zeichen lang sein. Dies kann beispielsweise folgendermaßen aussehen:
*3adb4f45677d6434eaa691cf63d69abd*  

```tip
**Sicherheitserwägung**: Es empfiehlt sich ein Konfigurationspasswort zu
setzen um folgendes Angriffsszenario auszuschließen: Man hat die
PIV-Funktionalität über USB deaktiviert da man sie nicht nutzt. Angenommen für genau diese Funktionalität gibt es eine Sicherheitslücke. Befindet man sich auf einem kompromittierten Rechner, könnte ein Angreifer per Fernsteuerung diese Funktionalität wieder aktivieren und
die Sicherheitslücke ausnutzen. Mit gesetztem Passwort ist das nicht
möglich. Das Passwort ist auf jeden Fall zufällig zu wählen\! Entweder
durch die zufällige Generierung, die vom der YubiKey Manager CLI
angeboten wird, oder extern durch einen Passwortmanager\!
```

#### 3.5.1 YubiKey Manager CLI

Man muss sich keine Gedanken machen um die Erzeugung des Passworts, da
hier Yubico einen eigenen Befehl vorgesehen hat. Dieser ist im folgenden
Bespiel zu sehen:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman config set-lock-code -g
Using a randomly generated lock code: 3adb4f45677d6434eaa691cf63d69abd
Lock configuration with this lock code? [y/N]: y
```

Wie man sieht, wird das Passwort nach dem Generieren ausgegeben.
Anschließend wird erfragt, ob man mit diesem Passwort zufrieden ist und
seinen YubiKey damit schützen möchte.

```danger
An dieser Stelle empfiehlt sich
nun, **das Passwort zu sichern, da bei Vergessen des Passworts kein
Reset möglich ist\!\!\!** [\[4\]](#quellen)
```

```tip
**Sicherheitserwägung**: Wie das Passwort gesichert wird ist jedem
selbst überlassen. Empfehlen kann ich das Sichern mit einem Passwort
Manager oder altmodisch auf Papier.  
Wer sein Passwort selbst erstellen möchte kann dies auch machen. Dazu
muss man folgendes Kommando ausführen: [\[2\]](#quellen)
```

``` bash
ykman config set-lock-code -n PASSWORT
```

Falls man doch kein Passwort setzten möchte, kann man auch dieses wieder
löschen. Das sieht folgendermaßen aus:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman config set-lock-code -c
Enter your current lock code:
```

```tip
**Sicherheitserwägung**: Das Passwort ist auf jeden Fall zufällig zu
wählen\! Entweder durch die zufällige Generierung, die vom der YubiKey
Manager CLI angeboten wird, oder extern durch einen Passwortmanager\! Das Passwort ist 128 Bit lang und bietet somit, wenn es zufällig gewählt
wurde, ein Sicherheitsniveau von 128 Bit. Das BSI empfiehlt bis zum Jahr
2022 ein Sicherheitsniveau von mindestens 100 Bit, darüber hinaus
mindestens 120 Bit [\[5, S. 14\]](#quellen). Unser Passwort
liegt über diesem Schwellwert, also kann man die Behauptung aufstellen,
dass das Passwort sicher vor Brute-Force Attacken ist. Ein Angriff kann
derzeit nicht in absehbarer Zeit erfolgreich sein.
```

-----

### 3.6 OTP Anwendungen verwalten

*Verfügbar für: CLI, GUI, Personalization Tool*  
  
Der YubiKey bietet für die tastaturbasierten Anwendungen insgesamt zwei
Slots. Die zwei Slots müssen sich OTP, Challenge-Response, das statische
Passwort und OATH-HOTP teilen. In diesem Kapitel wird nur die
Yubico-OTP-Anwendung behandelt. Wir empfehlen wo es geht FIDO zu nutzen,
aufgrund der guten Sicherheit und Nutzbarkeit. Die OATH-HOTP-Möglichkeit
ist ohnehin auch mit der zusätzlichen
[OATH](#37-oath-verwalten-und-verwenden) Unterstützung gegeben und
das statische Passwort zu setzen ist nicht schwer. Wir möchten hier nur
exemplarisch eine OTP-Möglichkeit zeigen zeigen um ein Gefühl zu
bekommen wie die Verwaltung der zwei OTP-Slots funktioniert.  
Der erste Slot des YubiKeys kommt vom Werk mit einem OTP-Credential
voreingestellt. Das hat den Sinn, dass man den YubiKey out-of-the-box
benutzen kann. Slot 1 wird mit einem kurzen Druck auf den Kontakt am
YubiKey aktiviert. der zweite Slot wird aktiviert, wenn man den Kontakt
mindestens drei Sekunden lang hält.  
Beim Verwenden eines dieser Anwendungen arbeitet der YubiKey als
virtuelle Tastatur und benutzt somit, wie in der Kurzbeschreibung
angesprochen, einen normalen USB-HID-Treiber. Das heißt, Ausgaben des
YubiKeys sind einer Serie von Tastaturanschlägen gleich.  
Verwendung hat OTP als starker zweiter Faktor oder sogar als einziger
Faktor, beim Anmelden zu einem Service.<sup>[\[6\]](#quellen)</sup>  
Das Einmalpasswort des Yubico-OTP hat eine bestimmte Struktur. Die
ersten zwölf Zeichen sind die öffentliche Identität, die ein
Validierungsserver zu einem User verbinden kann, während die nächsten 32
Zeichen das eigentliche Einmalpasswort sind, das sich jedes Mal ändert.
Dieses kann zum Beispiel so aussehen: *ccccccvjgkcuekrubjcvcjngijchjvcbjevjetedtgkn*  
Das Leerzeichen ist nur eingefügt, damit man zwischen ersten und zweiten
Teil besser unterscheiden kann. Die beiden Teile sind in der Praxis
zusammen. Der Code mag vorerst ein wenig komisch aussehen, da man
möglicherweise Hexadezimalzahlen erwarten würde, doch dazu gibt es eine
Erklärung: Das Problem liegt bei den Tastaturlayouts, welche in jedem
Land verschieden sind. Eine USB-Tastatur sagt dem Computer nur, welche
Taste gedrückt worden ist, aber nicht welches Zeichen\! Die Decodierung
wird am Computer nach dem eingestellten Tastaturlayout vorgenommen. Das
kann dann zu unterschiedlichen Eingaben führen. Yubico löst dieses
Problem, indem nur Zeichen verwendet werden, die auf allen Layouts
gleich sind. Yubico nennt diese Codierung
"Modhex".<sup>[\[6\]](#quellen)</sup>

#### 3.6.1 YubiKey Manager CLI

Die Einstellungen für OTP folgen diesem
Befehlsschema:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman otp [OPTIONS] COMMAND [ARGS]
```

Um sich einen Überblick über die programmierten Slots zu verschaffen,
empfiehlt sich der Befehl:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman otp info
Slot 1: programmed
Slot 2: empty
```

Um jetzt den zweiten Slot schnell mit dem Yubico-OTP zu programmieren,
könnte man das folgende Kommando ausführen:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman otp yubiotp -gGs 2
Using YubiKey serial as public ID: vvccccnngniu
Using a randomly generated private ID: 1e0669ee4287
Using a randomly generated secret key: 630809543256ea4ff065248d55c88182
Upload credential to YubiCloud? [y/N]:
Program an OTP credential in slot 2? [y/N]:
```

Der Befehl weist hier drei Optionen auf:<sup>[\[2\]](#quellen)</sup>

  - \-g: Dieser Tag gibt an, dass eine private Identität erzeugt werden
    soll. Diese wird als Input Parameter im OTP Generierungs Algorithmus
    verwendet.
  - \-G: Hier wird angegeben, dass ein Secret Key erzeugt werden soll.
    Dieser dient für die AES-Verschlüsselung, die bei jedem Erzeugen
    eines OTP erfolgt. Wer den OTP-Algorithmus ins Detail verstehen
    will, wird
    [hier](https://developers.yubico.com/OTP/OTPs_Explained.html)
    fündig.
  - \-s: Hier wird dem YubiKey gesagt, er soll seine Seriennummer als
    öffentliche ID verwenden.

Man kann alle Parameter selber erzeugen, falls man möchte. Dazu
verwendet man folgende Optionen:

  - \-p: steht für das Setzen der privaten Identität. Diese muss 6 Byte
    groß sein.
  - \-P:Public identifier prefix. setzt die öffentliche Identität. Diese
    ist gewöhnlich 12 Zeichen lang. Hierbei ist zu beachten, dass nur
    Modhex-Zeichen(cbdefghijklnrtuv) verwendet werden dürfen.
  - \-k: setzt den Secret Key. Dieser muss 16 Byte lang sein. (siehe
    auch nachfolgende Sicherheitserwägung)

```tip
**Sicherheitserwägung**: Der Secret Key muss zufällig gewählt werden.
Entweder durch Verwendung der -G Option oder mithilfe eines
Passwortmanagers, dessen zufällig generiertes Passwort mit der -k Option
gesetzt wird. Die Zufälligkeit des Schlüssels ist für die Sicherheit der
AES-Verschlüsselung ausschlaggebend\! 
```

Um nochmal zum letzten Befehl zurückzukehren. Hier stellt der Manager
die Frage, ob man seine Zugangsdaten auf die YubiCloud hochladen möchte.
Die YubiCloud ist ein möglicher Validierungsserver. Dessen Aufgabe ist
es, von Fremdservices, welche die API von Yubico implementieren, ein von
einem YubiKey erzeugtes OTP, der sich bei dem Service anmelden möchte,
entgegen zu nehmen. Der Server informiert den Service, ob das Passwort
valide ist oder nicht.  
  
Falls man jetzt beide Slots belegt hat und diese die Plätze tauschen
sollen, gibt es den swap-Befehl.<sup>[\[2\]](#quellen)</sup>

``` bash
ykman otp swap
```

Wenn man eine Konfiguration löschen möchte, ist der delete-Befehl zu
empfehlen. Hier muss nur die Slot-Nummer angegeben
werden.<sup>[\[2\]](#quellen)</sup>

``` bash
ykman otp delete [1|2]
```

Um noch sicherer unterwegs zu sein, kann man noch pro Slot einen eigenen
Accesscode setzen. Dieser verhindert das unberechtigte Schreiben auf
einen Slot.<sup>[\[2\]](#quellen)</sup>

``` bash
ykman otp settings -A HEX
```

Dieser Code muss 6 Byte bzw. 12 Hex-Zeichen lang sein.

#### 3.6.2 YubiKey Manager GUI OTP

Die GUI beinhaltet die meisten Funktionen, die im CLI-Abschnitt erwähnt
wurden. Es fehlt nur das Setzen von den Accesscodes. Die müssen über die
CLI oder auch das Personalization Tool,das im nächsten Abschnitt
behandelt wird, gesetzt werden.  
  
Die OTP-Einstellungen findet man im Reiter "Applications" und dann OTP.
Hier werden die beiden Slots angezeigt.  
![]({{ site.baseurl }}{{ page.dir }}img/manager_otp_slots.png)  
Beim Klick auf "Configure" wird man gefragt, welches Verfahren man
benutzen möchte. Hier wählt man "Yubico OTP". Dann trifft man auf
bereits bekannte Begriffe aus dem letzten Abschnitt. Um den Slot am
einfachsten zu konfigurieren, setzt man die Boxen "Use serial" und
"Upload". Anschließend drückt man die Knöpfe "Generate". Das sollte
ähnlich zum nächsten Bild aussehen.
![]({{ site.baseurl }}{{ page.dir }}img/manager_otp_konfigurieren.png)  
Natürlich kann man die Felder auch wieder selbständig befüllen, wenn man
möchte.

#### 3.6.3 Yubico Personalization Tool

Das Personalization Tool bietet einen "Yubico OTP" Reiter. Darunter
befinden sich zwei Knöpfe "Quick" und "Advanced".  
Wie der Knopf "Quick" schon sagt, werden nur die wichtigsten Felder
angezeigt. Man muss nur auswählen, welcher Slot konfiguriert werden
soll. Anschließend kann die Konfiguration schon geschrieben werden. Wenn
man die YubiCloud verwenden möchte, kann man die Konfiguration auch
sofort hochladen.  
![]({{ site.baseurl }}{{ page.dir }}img/pers_tool_otp_quick.png)  
Die zweite Option ist der "Advanced"-Mode. Hier findet man unter anderem
die in der GUI vermisste Option der Access Codes. Es besteht auch die
Möglichkeit die erstellte Konfiguration auf mehrere YubiKeys gleich zu
übertragen. Dazu muss man die Box "Program Multiple YubiKeys"
anklicken.  
Bei dieser Ansicht fehlt jedoch der "Upload to Yubico"-Button. Dies muss
man selbstständig auf [dieser](https://upload.yubico.com/) Seite
machen.  
![]({{ site.baseurl }}{{ page.dir }}img/pers_tool_otp_advanced.png)

-----

### 3.7 OATH verwalten und verwenden

*Verfügbar für: CLI, Authenticator*  
  
In OATH und dessen Funktionen HOTP und TOTP konnte man in der
[Kurzbeschreibung](/YubiKeyWiki/docs/kurzbeschreibung) schon einen
kleinen Einblick gewinnen. In diesem Abschnitt wird auf die Nutzung der
beiden OTP-Protokolle eingegangen.  
Der YubiKey bietet Platz für 32 OATH-Credentials. Abgesehen davon kann
man in den beiden
[OTP-Slots](/YubiKeyWiki/docs/kurzbeschreibung#funktionen) bereits
HOTP nutzen. Diese Slots muss man sich aber Yubico-OTP,
Challenge-Response und dem statischen Passwort teilen. Diese zwei Slots
können können kein TOTP aufnehmen, da dieses Verfahren die aktuelle Zeit
benötigt und der YubiKey die Zeit nur von einem externen Programm
übermittelt bekommt. Außerdem werden die beiden OTP-Slots mit einem
Druck auf den YubiKey aktiviert, die 32 Credentialplätze von OATH werden
über die YubiKey Manager CLI oder den Yubico Authenticator verwaltet und
genutzt. Die Funktionen des Yubico Authenticators sind das Mitteilen der
aktuellen Zeit an den YubiKey für die TOTP-Funktion und das Anstoßen des
YubiKey zur Neuberechnung der
Einmalpasswörter.<sup>[\[7\]](#quellen)</sup>

#### 3.7.1 Yubico Authenticator

Das Anlegen eines Service ist im Authenticator-Tool sehr einfach.
Deswegen empfehle ich auch diese Variante. Hierzu klickt man auf das
große Plus-Symbol oben rechts im Fenster. Hier sollte sich ein "Add
Account"-Fenster öffnen:  
![]({{ site.baseurl }}{{ page.dir }}img/authenticator_add.png)  
Die einfache Methode ist "Scan". Hier wird vom Bildschirm ein QR-Code
eingescannt, der von der Anwendung, in der man OATH einrichten möchte,
angezeigt wird. Von diesem kann die Authenticator App alle relevanten
Informationen extrahieren. Hier ist ein Bespiel die App "Discord":  
![]({{ site.baseurl }}{{ page.dir }}img/authenticator_example.png)  
Manuell eingeben funktioniert auch in diesem Fall. Dazu benöigt man den
angegebenen Security Key und den Account Namen.  
Im Hauptfenster des Authenticators sollte man nun eine Spalte mit
"Discord" sehen. Um die Aktivierung der Zweifaktornutzung mit OATH bei
Discord zu finalisieren, muss ein Code generiert werden, der dann in das
"Login with your Code"-Feld eingetragen werden muss. Den Code erhält man
indem man einen Doppelklick auf die Spalte "Discord" durchführt.
Anschließend wird man aufgefordert einen Druck auf den YubiKey
durchzuführen und man hat seinen Code. Dieser ist, wenn es sich bei der
Einrichtung um TOTP handelt, üblicherweise 30 Sekunden gültig:  
![]({{ site.baseurl }}{{ page.dir }}img/authenticator_code_generated.png)  
Nachdem man einmal diesen TOTP Code generiert hat und eingibt, ist der
Service fertig konfiguriert. Das Hinzufügen ist immer so einfach und
sollte problemlos verlaufen.  
Um mehr Services zu finden, die Zweifaktorauthentifizierung
unterstützen, sollte auf [dieser Seite](https://twofactorauth.org/#)
suchen.

#### 3.7.2 YubiKey Manager CLI

Das Hinzufügen über die CLI ist nicht viel komplizierter. Dazu benötigt
man folgenden Befehl:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath add [OPTIONS] NAME [SECRET]
```

Als Optionen kommen folgende infrage:

  - \-o: OATH-Typ --\> HOTP|TOTP(default)
  - \-d: Anzahl der Zeichen des generierten Codes --\> 6(default)|7|8
  - \-a: Algorithmus --\> SHA1(default)|SHA256|SHA512
  - \-c: Initialer Zähler-Wert für HOTP
  - \-i: Issuer
  - \-p: Zeit indem der generierte Code valide ist --\> 30(default)
  - \-t: Ein Druck auf den YubiKey wird vorgeschrieben

Für das Beispiel "Discord" würde nur die Option -i und evetuell -t
relevant sein, da alle anderen Optionen den Default-Werten
entsprechen.  
Um sich nun nun die eingefügten Credentials anzusehen, gibt man einfach
folgenden Befehl ein:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath list
Discord:max.muster@mann.at
```

Um nun einen Code zu generieren, ist der Befehl "code" von
Nutzen:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath code
```

Dieser Befehl generiert in dieser Variante für jedes hinzugefügte
Credential ein Passwort\! Wenn man dies nicht möchte, ist dem Befehl
eine Definition anzuhängen. Zum Beispiel folgender Befehl generiert nur
ein Passwort für die "Discord"-App:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath code Discord:max.muster@mann.at
Discord:max.muster@mann.at  924246
```

  
Natürlich gibt es die Möglichkeit ein Credential wieder zu löschen. Dazu
einfach nur den Delete-Befehl mit dem Namen eines Credentials
ausführen:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath delete Discord:max.muster@mann.at
```

Eine Steigerung dieses Befehls gibt es noch. Nämlich einen Reset. Dieser
setzt den kompletten Stand der OATH-Applikation
zurück\!<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath reset
```

Um die Einstellungen der OATH-Applikation sicherzustellen, gibt es
wieder die Möglichkeit eines Passworts. Dieses schützt die gesamten 32
Credentials.<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath set-password -n TEXT
```

Optional ist die Option -r. Damit wird bei Verwendung der gleichen
Maschine nicht mehr nach dem Passwort gefragt. Das kann aber auch
nachträglich mit diesem Befehl getan
werden:<sup>[\[2\]](#quellen)</sup>

``` bash
ykman oath remember-password
```

Zum "set-password"-Befehl ist noch hinzuzufügen, dass die "-c"-Option
das Passwort wieder löscht.

-----

### 3.8 FIDO verwalten

*Verfügbar für: CLI, GUI*  
  
In der
[Kurzbeschreibung](/YubiKeyWiki/docs/kurzbeschreibung)
konnte man einen Einblick in das Thema "FIDO" bekommen. Hier sind
nocheinmal die wesentlichen Punkte:

  - FIDO2 ist eine Sammlung von Spezifikationen von 2019 und wird für
    die passwortlose bzw. Zwei- oder Mehrfaktorauthentifizierung bei
    Webservices verwendet.
  - Es können 25 Credentials bei FIDO2 gespeichert werden. Mit FIDO U2F
    kann man sich bei beliebig vielen Web Services registrieren.
  - Das Verfahren basiert auf Public-Key-Krypthographie. Der initiale
    Schlüsselaustausch muss also nicht geheim erfolgen, es bleibt aber
    die Problematik der Authentizität von Schlüsseln.

Weitere Informationen, über das Hinzufügen eines Service bzw. das
Verwalten der Credentials findet ihr auf unserer
[FIDO2](/YubiKeyWiki/docs/FIDO2)
Seite.  

-----

### 3.9 PIV verwalten

*Verfügbar für: CLI, GUI*  
  
Die PIV-Applikation ermöglicht es, den YubiKey wie eine Smartcard zu
nutzen. Es können also Signatur- bzw. Verschlüsselungsoperationen
mittels RSA oder ECC durchgeführt werden.<sup>[\[8\]](#quellen)</sup>  
Die Operationen werden auf vier unabhängige Keys aufgeteilt. Je ein Key
zum Signieren, Authentifizieren, Verschlüsseln und zur
Zutrittsauthentifizierung bei Gebäuden. Der Slot 9a der PIV-Applikation
ist beispielsweise für die Authentifizierung gedacht. Die
Funktionalitäten von PIV sind grundsätzlich gleich wie bei jene von
OpenPGP. PIV wird jedoch häufiger im Unternehmensumfeld eingesetzt. PIV
arbeitet beispielsweise mit X.509 Zertifikaten und somit mit
zertifizierten Schlüsseln. Das ermöglicht es Unternehmen, eine zentrale
Schlüsselverwaltung aufzubauen.<sup>[\[9\]](#quellen)</sup>  
OpenPGP ist der quasi der Standard in der
Linux-Welt.<sup>[\[10\]](#quellen)</sup> Es ist dafür konzipiert, dass
Einzelpersonen ihre eigenen Keys erstellen und durch gegenseitiges
Signieren der Schlüssel anderer Personen wird ein Vertrauensnetz
geschaffen. Wir werden aus genannten Gründen in diesem Wiki nicht näher
auf PIV eingehen. Falls jemand an der Verwendung von PIV interessiert
ist, können wir die Beschreibung von
[Yubico](https://developers.yubico.com/PIV/Guides/) empfehlen.

-----

### 3.10 OpenPGP verwalten

*Verfügbar für: CLI*  
  
Für die Verwaltung von [OpenPGP](/YubiKeyWiki/docs/OpenPGP) stützt
sich Yubico auf Software-Implementierungen des OpenPGP Standards
([RFC4880](https://tools.ietf.org/html/rfc4880)). Zur allgemeinen
Verwaltung von OpenPGP und der Speicherung von Schlüsseln am YubiKey
sind also die [GnuPG-Software](https://gnupg.org/software/index.html)
(Linux) bzw. dessen Implementierung für Windows
[Gpg4win](https://www.gpg4win.org/) zu nutzen. Genauere Informationen
zur Verwendung von OpenPGP und der sicheren Erstellung von Keys gibt es
in unserem allgemeinen [OpenPGP](/YubiKeyWiki/docs/OpenPGP)
Artikel. Abgesehen von der GnuPG-Implementierung gibt es aber noch
zusätzliche, YubiKey-spezifische Einstellungen die über den YubiKey
Manager eingestellt werden können. Diese werden wir hier erläutern.

#### 3.10.1 YubiKey Manager CLI

##### Info

Informationen über den aktuellen Status der OpenPGP Anwendung lassen
sich mithilfe des folgenden Befehls anzeigen:

``` bash
ykman openpgp info
```

Output:

``` bash
OpenPGP version: 3.4
Application version: 5.2.4

PIN tries remaining: 3
Reset code tries remaining: 0
Admin PIN tries remaining: 3

Touch policies
Signature key           Off
Encryption key          Off
Authentication key      Off
Attestation key         Off
```

Wir sehen hier einerseits wieder die **Firmware-Version** des YubiKey
"5.2.4" in Zeile 2, aber auch die **OpenPGP Version** "3.4" in Zeile 1.
Diese Version bezieht sich auf die "OpenPGP Smart Card Application"
Spezifikation die auf der Seite von
[GnuPG](https://gnupg.org/ftp/specs/) zu finden ist. Für uns als
Endnutzer ist natürlich Interessant welche Kryptografischen Standards
(also Schlüssellängen und Algorithmen) wir auf unserem YubiKey erwarten
dürfen. Die Spezifikation selbst ist dabei eher weniger hilfreich da die
Verpflichtenden Algorithmen die unterstützt werden müssen mit RSA 2048,
und nicht einmal einer einzigen verpflichtenden Elliptischen Kurve, sehr
mager ausfallen. <sup>[\[11, Sec. 4.4.3.10\]](#quellen)</sup> Wichtig
für uns ist also die Firmwareversion und die Tatsache, dass wir einen
YubiKey aus der YubiKey 5 Serie haben. Mit diesen Informationen lässt
sich herausfinden, dass der YubiKey RSA bis zu einer Schlüssellänge von
4096 Bit<sup>[\[12\]](#quellen)</sup> und die Elliptische Kurven
curve25519, secp und brainpool (in verschiedenen
Ausführungen)<sup>[\[13\]](#quellen)</sup> unterstützt.

Danach sehen wir Zähler für die **Eingabeversuche von Pins** (Zeile
4-6). Jedes mal wenn einer dieser Pins falsch eingegeben wird, wird der
zugehörige Zähler um 1 verringert. Ist der Zähler bei 0 kann man diesen
Pin (und die Funktionalität die er schützt) nicht mehr verwenden. Gibt
man einen dieser Pins richtig ein (bevor der Zähler auf 0 ist), so wird
der Zähler auf seinen ursprünglichen Wert zurückgesetzt. Folgende Pins
gibt es:

  - **PIN**: Dies ist der hauptsächlich verwendete Pin. Er wird dann
    benötigt, wenn man einen der OpenPGP Schlüssel zum
    Signieren/Verschlüsseln/Authentifizieren nutzen möchte. Das heißt,
    jedes mal, wenn man beispielsweise eine E-Mail signieren möchte,
    wird man nach diesem Pin gefragt (ausgenommen man lässt den Pin vom
    YubiKey cachen). Hat man den Pin zu oft falsch eingegeben, so kann
    man die gespeicherten OpenPGP Schlüssel nicht mehr nutzen, bis man
    das mittels Admin Pin oder Reset Code wieder ermöglicht.
  - **Admin Pin**: Dieser wird für alle OpenPGP bezogenen Einstellungen
    benötigt. Es wird danach gefragt, wenn man OpenPGP Schlüssel auf den
    YubiKey transferieren möchte und wenn man die Pin Retries setzen
    möchte. **Gibt man diesen zu oft falsch ein und der Retry Counter
    ist auf 0, sind die Schlüssel am YubiKey unwiederruflich
    verloren\!\!** Das macht auch Sinn: selbst wenn der YubiKey in
    falsche Hände gerät, kann ein Angreifer ohne Wissen der Pins die
    OpenPGP Schlüssel nicht nutzen.
  - **Reset Code**: Sollte der YubiKey z.B. von einem Arbeitgeber für
    seine Mitarbeiter fertig aufgesetzt werden, ist es Sinnvoll den
    Mitarbeitern den Admin Pin nicht mitzuteilen. Sie bekommen dafür
    einen Reset Code. Mit diesem kann man OpenPGP Einstellungen nicht
    verändern, dafür aber den Pin neu setzen, falls dieser zu oft falsch
    eingegeben wurde. <sup>[\[10, Sec. 4.3.4\]](#quellen)</sup>

Die Zähler für die Pins können mit folgendem Befehl gesetzt werden:

``` bash
ykman openpgp set-pin-retries [OPTIONS] PIN-RETRIES RESET-CODE-RETRIES ADMIN-PIN-RETRIES
```

```tip
**Sicherheitserwägung**: Das BSI empfiehlt eine Pin-Retry Beschränkung
auf 3 Versuche. [\[5, Tabelle 6.2\]](#quellen)
```

``` bash
ykman openpgp set-pin-retries 3 0 3
```

In den Zeilen 8-12 des obigen Outputs sehen wir noch die Einstellungen
für die **Touch Policy**. Es ist möglich für die Verwendung jedes
einzelnen Schlüssels vor der Nutzung einen Knopfdruck beim YubiKey zu
erfordern. Das hat den Sinn, den zweiten Faktor "Besitz" noch einmal
aufzufrischen. Angenommen ich habe den YubiKey aus Bequemlichkeit
permanent an meinem Rechner stecken. Dann wäre ich ja theoretisch nur
noch auf den Faktor "Wissen" (meinen Pin) zurückgeworfen.

##### Touch Policy

Wie im Absatz darüber beschrieben kann man die Touch Policy für die
Verwendung von OpenPGP Schlüsseln ändern. Der Befehl dafür ist wie folgt
aufgebaut:

``` bash
ykman openpgp set-touch [OPTIONS] KEY POLICY
```

Folgende Attribute gehören gesetzt:

  - KEY: Auswahl des Slots (Schlüssels) für den die Touch Policy gesetzt
    werden soll (sig, enc, aut oder att).
  - POLICY: Touch Policy für den jeweiligen Key (on, off, fixed, cached
    oder cached-fixed)
      - on: Für jede Verwendung eines GPG Schlüssels ist ein Knopfdruck
        erforderlich.
      - off: Für die Verwendung eines GPG Schlüssels ist kein Knopfdruck
        erforderlich.
      - fixed: Für jede Verwendung eines GPG Schlüssels ist ein
        Knopfdruck erforderlich und diese Einstellung kann nicht
        geändert werden, außer bei einem Reset der OpenGPG
        Funktionalität
      - cached: Für die Verwendung eines GPG Schlüssels ist initial ein
        Knopfdruck erforderlich, darauf folgende Schlüsselverwendungen
        werden für 15 Sekunden ebenfalls ermöglicht.
      - cached-fixed: Vereint die Funktionalitäten von fixed und cached.

```tip
**Sicherheitserwägung** zur Touch-Policy:

  - Generell ist, wenn man die Touch-Funktionalität nutzen möchte, die **Touch-Policy "fixed" bzw. "cached-fixed" gegenüber "on" und
    "cached" zu bevorzugen**. Folgendes Angriffsszenario wird dadurch
    ausgeschlossen: Angenommen das System an dem der YubiKey verwendet
    wird ist kompromittiert, sodass der Angreifer die Eingabe des
    Admin-Pins während einer Verwendung des YubiKey mitlesen kann.
    Anschließend könnte er von der Ferne die Touch-Policy auf "off"
    setzen und könnte somit, ohne physisch im Besitz des YubiKey zu
    sein, von der Ferne die gespeicherten Schlüssel nutzen. Dies gelingt
    dem Angreifer bei "fixed" nicht, da er zur Änderung der Touch-Policy
    die Schlüssel am YubiKey löschen müsste.
  - **Für alle Schlüssel empfehlen wir für optimale Sicherheit die
    Touch-Policy "fixed"**. Sobald nämlich der YubiKey mit dem Computer
    per USB-Schnittstelle verbunden ist und einer der Schlüssel einmal
    verwendet wurde (unter Abfrage des Pins), wird der Pin bis zum Ende
    der Session (Entfernung des YubiKey) am YubiKey gecached\! Würde man
    hier die "cached-fixed" Funktion verwenden, könnte ein Angreifer
    nach einer Touch-Verwendung für eine Zeitdauer von 15 Sekunden
    weitere Aktionen von der Ferne auslösen. Da die Ausstellung einer
    Signatur oder eine Authentifizierung in der Regel innerhalb von 15
    Sekunden nicht mehrfach vorkommt und jede Verwendung der Schlüssel
    einzeln genehmigt werden sollte, empfiehlt sich diese Einstellung. Auch beim Attestation-Schlüssel, den man ohnehin nur 3 Mal zur
    Attestierung der anderen Schlüssel benötigt.
  - Wer **mehr Usability auf Kosten der Sicherheit** möchte kann auch
    andere Touch-Policy Optionen in Erwägung ziehen. Sollte das bei
    einer Anwendung Sinn machen, werden wir es beim jeweiligen Beispiel ansprechen.
```


##### Reset

Um alle Schlüssel auf dem YubiKey und die zugehörigen
Zertifikatsspeicher für die Beglaubigung (Attestation) zu löschen und
die Pins und Retries auf ihren Default-Wert zu setzen nutzt man
Reset-Kommando:

``` bash
ykman openpgp reset
```

Der Beglaubigungsschlüssel (Attestation-Key) und das zugehörige
Zertifikat bleiben vom Reset jedoch unberührt.

##### Attestation

Die grundsätzliche Funktionalität und der Vorteil der
Attestation-Funktionalität wird in unserem allgemeinen
[OpenPGP](/YubiKeyWiki/docs/OpenPGP) Artikel erklärt. Hier werden
nur die zugehörigen Befehle erläutert.  
  
Folgender Befehl dient zum Beglaubigen von Schlüsseln:

``` bash
ykman openpgp attest [OPTIONS] KEY CERTIFICATE
```

Folgende Attribute gehören gesetzt:

  - KEY: Auswahl des Slots (Schlüssels) für den man ein
    Attestation-Zertifikat erstellen möchte (sig, enc oder aut).
  - CERTIFICATE: File in welches das Zertifikat gespeichert werden soll
    ("-" für stdout).

Das erstellte X.509-Zertifikat wird abgesehen von der Ausgabe auf stdout
oder in ein File auch in den Zertifikatsspeicher des jeweiligen
Schlüssels am YubiKey gespeichert.<sup>[\[14\]](#quellen)</sup> Von
dort kann es jederzeit ausgelesen werden:

``` bash
ykman openpgp export-certificate [OPTIONS] KEY CERTIFICATE
```

Hierbei kann man auch das Zertifikat für den Attestierungsschlüssel
auslesen, indem man das KEY-Attribut auf "att" setzt. Das Löschen eines
Zertifikates erfolgt mit dem Befehl:

``` bash
ykman openpgp delete-certificate [OPTIONS] KEY
```

**Vorsicht:** Die beiden folgenden Befehle sind gedacht für die
Verwendung in Unternehmen, die ihre eigene Zertifikatskette innerhalb
des Unternehmens zur Attestierung verwenden möchten. Als Privatperson
sollte man den bereits am YubiKey befindlichen Attestierungsschlüssel
mit dem zugehörigen Zertifikat von Yubico nutzen und unverändert
lassen\!

Zum Speichern eines Zertifikats (das macht eigentlich nur für den
Attestation-Schlüssel Sinn, da die anderen ja am YubiKey mit der
Attestation-Funktion erstellt werden) nutzt man den Befehl:

``` bash
ykman openpgp import-certificate [OPTIONS] KEY
```

Eine Veränderung des Zertifikats zum Attestation-Schlüssel geht
natürlich einher mit einer Änderung des Attestation-Schlüssels:

``` bash
ykman openpgp import-attestation-key [OPTIONS] PRIVATE-KEY
```

Das PRIVATE-KEY-Attribut gibt das File an, in dem der Private-Key liegt
(oder "-" für stdin).

-----

## Quellen

<sup>\[1\]</sup> Yubico, *YubiKey Manager*, Letzter Zugriff 05.05.2020,
\[Online\], URL: <https://developers.yubico.com/yubikey-manager-qt/>  
<sup>\[2\]</sup> Yubico, *YubiKey Manager CLI User Guide*, Letzter
Zugriff 05.05.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide>  
<sup>\[3\]</sup> Yubico, *Upgrading YubiKey Firmware*, Letzter Zugriff
05.05.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000006434-upgrading-yubikey-firmware>  
<sup>\[4\]</sup> Yubico, *Removing a Configuration Protection Access
Code*, Letzter Zugriff 05.05.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000006477-removing-a-configuration-protection-access-code>  
<sup>\[5\]</sup> *BSI TR-02102-1 "Kryptographische Verfahren:
Empfehlungen und Schlüssellängen"*, BSI Technische Richtlinie, Version
2020-01, Stand 24.03.2020, Letzter Zugriff 07.05.2020 \[Online\], URL:
<https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf>  
<sup>\[6\]</sup> Yubico, *OTPs explained*, Letzter Zugriff 05.05.2020,
\[Online\], URL:
<https://developers.yubico.com/OTP/OTPs\_Explained.html>  
<sup>\[7\]</sup> Yubico, *OATH*, Letzter Zugriff 05.05.2020, \[Online\],
URL: <https://developers.yubico.com/OATH/>  
<sup>\[8\]</sup> Yubico, *PIV*, Letzter Zugriff 05.05.2020, \[Online\],
URL: <https://developers.yubico.com/PIV/>  
<sup>\[9\]</sup> Yubico, *YubiKey 5 Series Technical Manual*, Letzter
Zugriff 05.05.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual#Smart_Card_(PIV_Compatible)84fcon>  
<sup>\[10\]</sup> Yubico, *PGP*, Letzter Zugriff 05.05.2020, \[Online\],
URL: https://developers.yubico.com/PGP/  
<sup>\[11\]</sup> Yubico, *OpenPGP Smart Card Application 3.4*, Letzter
Zugriff 28.04.2020, \[Online\], URL:
<https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.0.pdf>  
<sup>\[12\]</sup> Yubico, *YubiKey 5 Series Technical Manual*, (2020),
Letzter Zugriff 28.04.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual>  
<sup>\[13\]</sup> Yubico, *YubiKey 5.2.3 Enhancements to OpenPGP 3.4
Support*, Letzter Zugriff 28.04.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000027139-yubikey-5-2-3-enhancements-to-openpgp-3-4-support>  
<sup>\[14\]</sup> Yubico, *OpenPGP Attestation*, Letzter Zugriff
03.05.2020, \[Online\], URL:
<https://developers.yubico.com/PGP/Attestation.html>
