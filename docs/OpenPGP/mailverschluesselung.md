# Email Verschlüsselung

{% include acronyms.md %}

OpenPGP ist ein Standard, der grundsätzlich für das Verschlüsseln der
Email Kommunikation geschaffen wurde<sup>[\[1\]](#quellen)</sup>. In
diesem Artikel wird die genaue Vorgehensweise erklärt, wie man unter
Verwendung des OpenPGP Standards und des YubiKey, seine Emails sicher
verschlüsseln und signieren kann. Um die Email Verschlüsselung wie hier
beschrieben aufsetzen zu können, wird vorausgesetzt, dass sich am
YubiKey bereits OpenPGP-Schlüssel befinden. Das sichere Generieren von
OpenPGP-Schlüsseln und deren Transfer auf den YubiKey ist
[hier](/YubiKeyWiki/docs/OpenPGP) erklärt. Eine Liste aller Email
Anwendungen die OpenPGP direkt oder mit zusätzlicher Software (z.B.
Plugins) unterstützen findet sich online auf
[openpgp.org](https://www.openpgp.org/software/).  
In diesem Wiki beschreiben wir die Verwendung von:

  - **Thunderbird** für **Windows** und **Linux**
  - **FairEmail** für **Android**.

## Thunderbird

[Thunderbird](https://www.thunderbird.net/en-US/) ist eine kostenlose
Email Anwendung unter der [MPL2](https://www.mozilla.org/en-US/MPL/2.0/)
Lizenz. Seit Thunderbird78 wird OpenPGP ohne zusätzliche Plugins oder Software unterstützt. Leider haben sich die Entwickler bei der OpenPGP Integration (aufgrund von Lizenzproblemen) für die Verwendung der [RNP](https://www.rnpgp.com/) Bibliothek, anstatt von [GnuPG](https://gnupg.org/) entschieden. Ein direkter Einsatz von OpenPGP-Smartcards wie etwa dem YubiKey wird daher nicht nativ unterstützt. Dafür muss zusätzlich GnuPG installiert sein, um die nötigen Smartcard-Funktionalitäten für Thunderbird bereitzustellen. Das hat zur Folge, dass mit zwei Schlüsselspeichern gearbeitet wird: Einerseits dem Thunderbird-internen Schlüsselbund von RNP, andererseits dem Schlüsselbund von GnuPG. Vielleicht wird in einer späteren Thunderbird-Version die Smartcard-Unterstützung implementiert - das ist aber zumindest derzeit nicht auf der [Roadmap der Entwickler](https://wiki.mozilla.org/Thunderbird:OpenPGP:Status). <sup>[\[2\]](#quellen)</sup>

Informationen und Hilfestellungen bei der generellen Verwendung von
Thunderbird gibt es auf der [offiziellen Seite](https://support.mozilla.org/de/products/thunderbird/how).

### Installation von Thunderbird

#### Linux

Die Installation erfolgt z.B. über das APT Paketverwaltungssystem:

``` bash
sudo apt install thunderbird
```

Thunderbird lässt sich dann einfach in der Konsole starten:

``` bash
thunderbird &
```

Für die Verwendung des YubiKey muss außerdem GnuPG installiert sein.
Sollte das nicht der Fall sein ist das Paket ebenfalls zu installieren:

``` bash
sudo apt install gpg scdaemon
```

#### Windows

Zur Installation auf Windows ist die aktuellste Version von der
offiziellen Seite [herunterzuladen](https://www.thunderbird.net/de/) und
zu installieren. Nachdem der Smartcard-Support auf GnuPG aufbaut, muss zusätzlich
[Gpg4win](https://www.gpg4win.de/) installiert sein.

Damit Thunderbird die benötigte libgpgme.dll findet, muss deren Pfad zum Speicherort in der Path-Umgebungsvariable gesetzt werden. Ganz einfach geht das über folgenden Befehl in einer Kommandozeile (cmd) mit Administratorrechten:

```warning
Dieser Befehl funktioniert AUSSCHLIESSLICH in der Kommandozeile (cmd) und nicht in der PowerShell! In der PowerShell fürht dieser Befehl zur Löschung der PATH-Variable! Abgesehen davon empfiehlt es sich zur Sicherheit die PATH-Variable vor der Veränderung zu sichern.
```

``` bash
setx /m PATH "C:\PfadZurGPGInstallation\Gpg4win\bin_64;%PATH%"
```

### OpenPGP Einrichtung

Alle weiteren Schritte werden direkt in Thunderbird, oder über das
Kommandozeilenprogramm "gpg" ausgeführt und sind vom Betriebssystem
unabhängig. Sollte doch ein unterschied zwischen Windows und Linux bestehen, wird darauf speziell hingewiesen.

#### Voraussetzungen

Bevor mit der Einrichtung gestartet werden kann, muss ein GPG-Schlüssel am YubiKey erstellt werden. Eine entsprechende Anleitung hierfür findet sich in unserem [OpenPGP Artikel](/YubiKeyWiki/docs/OpenPGP/#schlüsselerzeugung). Hat man bereits einen privaten Schlüssel am YubiKey und möchte auf einem neuen System den zugehörigen öffentlichen Schlüssel in den GnuPG-Schlüsselbund importieren, kann man dafür beispielsweise das gesetzte "URL of public key" Feld verwenden, wie in unserem [OpenPGP Artikel](/YubiKeyWiki/docs/OpenPGP/#metadaten-auf-den-yubikey-laden) beschrieben.

Wenn alles passt, sollte der gewünschte PGP-Schlüssel vom YubiKey auch im GPG-Schlüsselbund ersichtlich sein:
```bash
gpg -K
/home/kali/.gnupg/pubring.kbx
-----------------------------
sec>  rsa4096 2020-04-16 [SC] [expires: 2025-04-15]
      A662724593E61256E4ADB82E1E360B1A218AAFAE
      Card serial no. = 0006 12015372
ssb>  rsa4096 2020-04-16 [E] [expires: 2025-04-15]
ssb>  rsa4096 2020-04-16 [A] [expires: 2025-04-15]
```
Die ">"-Zeichen neben sec und ssb geben an, dass sich der private Schlüssel auf der Smartcard (dem YubiKey) befinden.

```note
Die Key-ID des Schlüssels (in diesem Fall "A662724593E61256E4ADB82E1E360B1A218AAFAE") wird später für die Einrichtung in Thunderbird benötigt!
```

Für den weiteren Verlauf der Einrichtung emfpiehlt es sich die Menüleiste zu fixieren. Sie
kommt durch Drücken der "F10"-Taste zum Vorschein und kann dort über
*View/Toolbars/Menu Bar* fixiert werden.  

#### Externe GnuPG-Verwendung erlauben

Um die Verwendung von GnuPG in Thunderbird freizugeben, navigiert man zuerst zu den Einstellungen unter */Edit/Preferences* und geht dann zum *Config Editor.* ganz untern auf der Seite. Hier muss die Einstellung **mail.openpgp.allow_external_gnupg** durch einen Doppelklick auf "true" gesetzt werden.

### Arbeiten mit OpenPGP in Thunderbird

Die Hauptkomponente um mit den OpenPGP-Schlüsseln zu arbeiten ist der **OpenPGP Key Manager** welcher über das Menü */Tools/OpenPGP Key Manager* erreichbar ist. Folgende Einstellungen können dort vorgenommen werden:

  - Generieren von OpenPGP Schlüsselpaaren
  - [Importieren](#schlüssel-importieren) und Exportieren von
    Schlüsseln
  - Interaktion mit fremden Schlüsseln
      - [Schlüsseln vertrauen](#schlüsselauthentizität)
  
#### Schlüssel importieren
Wenn man jemandem eine verschlüsselte
Email senden oder Signaturen von jemandem überprüfen möchte, braucht man
dazu dessen öffentlichen Schlüssel. Dieser lässt sich über verschiedene
Wege mithilfe des *OpenPGP Key Manager* in den lokalen Schlüsselbund
importieren. Auch private Schlüssel lassen sich über diese Wege
importieren.(das *OpenPGP Key Manager* Fenster findet man über die
Menüleiste: *Tools/OpenPGP Key Manager*).

  - **Importieren des Schlüssels über eine Datei**: Dafür muss ich den
    öffentlichen Schlüssel in Form einer Datei auf das eigene System
    transferieren und dann im *OpenPGP Key Manager* über
    *File/Import keys from file* den Schlüssel importieren.
  - **Importieren des Schlüssels über die Zwischenablage**: Habe ich den
    Schlüssel im ASCII-armor Format vorliegen, muss ich ihn nicht extra
    in eine Datei speichern, sondern kann ihn einfach in die
    Zwischenablage kopieren und über *Edit/Import Keys from Clipboard*
    einfügen.
  - **Importieren des Schlüssels über eine URL**: Hat der Empfänger
    seinen Schlüssel auf einem Server zum Download bereit, kann man über
    die Eingabe der URL (also den Download-Link) die Datei mit dem
    öffentlichen Schlüssel herunterladen und importieren. Dafür muss
    man im *OpenPGP Key Manager* die Option *Edit/Import Keys from
    URL* nutzen.
  - **Importieren des Schlüssels über einen Keyserver**: Im Grunde ist
    hier kein großer Unterschied zum Import von einer URL, da man
    genauso eine Datei von einem Keyserver herunterlädt. Der große
    Vorteil ist aber die Suchfunktion. Im *OpenPGP Key Manager*
    navigiere ich dafür auf *Keyserver/Discover keys online*. Ich importiere
    hier beispielhaft den öffentlichen Schlüssel meines fiktiven
    Testkollegen Troye Finnegan:  
    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_import_troye.png){: width="500px"}  
    Nachdem ich nach ihm gesucht habe, sehe ich seinen Schlüssel und
    kann diesen importieren. Dabei kann ich gleich festlegen, ob ich diesem Schlüssel vertrauen möchte oder nicht. Ich vertraue in diesem Fall dem Schlüssel von Troy, weil ich seinen Fingerprint kenne.
    
    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_import_troye_fingerprint.png){: width="500px"}  
    Ich sehe nun den Schlüssel von Troye in meinem Schlüsselbund. Grundsätzlich
    kann im *OpenPGP Key Manager* auf einen Blick sehen ob es sich
    bei Schlüsseln um private (fette Schrift) oder öffentliche Schlüssel
    (normale Schrift) handelt. In unserem Fall ist das aber nicht möglich, da aus Sicht des Key Managers nur die öffentlichen Schlüssel vorliegen. Deshalb sind beide Einträge (sowohl der von Troye als auch der eigene Schlüssel, zu dem wir den passenden privaten Schlüssel am YubiKey haben) in normaler Schrift:  
    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_import_troye_done.png){: width="500px"}  

```tip
**Sicherheitserwägung**: Beim Hinzufügen von öffentlichen Schlüsseln **soll** sichergestellt werden, dass es sich wirklich um den öffentlichen Schlüssel meines gewünschten Kommunikationspartners handelt\! Die Überprüfung der Authentizität des importierten Schlüssels hat unbedingt auf einem zweiten Kommunikationskanal zu erfolgen. Denkbar sind ein persönliches Treffen oder ein Telefongespräch, wenn ich die Stimme meines Gegenüber erkennen kann. Über diesen zweiten Kommunikationskanal muss der **Fingerprint des Schlüssels abgeglichen** werden. Auf dieser initialen Authentifizierung baut die Sicherheit bei der OpenPGP-Kommunikation auf\! Überprüft man die Authentizität nicht, so muss man sich der Tatsache und Konsequenzen der fehlenden Authentizität bewusst sein\! 
```

#### Privaten Schlüssel vom YubiKey verfügbar machen

Im Ausschnitt oben hat man bereits meinen öffentlichen Schlüssel
gesehen. Dieser hat die Key-ID mit der Endung "AAFAE". Wenn ich aber
Thunderbird und gpg auf einem neuen System installiere ist mein Schlüssel noch
nicht am System. In diesem Absatz gehe ich davon aus, dass der eigene
Schlüssel noch nicht am System bekannt ist. Ich sehe also nur den zuvor
hinzugefügten Schlüssel von Troye:  
![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_privavail_troye.png){: width="500px"}
Zuerst muss der öffentliche Schlüssel im **OpenPGP Key Manager** hinzugefügt werden. Dieser ist erreichbar über das Menü */Tools/OpenPGP Key Manager*. Dort gibt es mehrere Import-Möglichkeiten. Am schnellsten geht es wieder über die "URL of public key". Ist sie auf der Smartcard gesetzt, lässt sie sich einfach über den Karten-Status abrufen:

```bash
gpg --card-status
...
URL of public key : https://keys.openpgp.org/vks/v1/by-fingerprint/A662724593E61256E4ADB82E1E360B1A218AAFAE
...
```
Diese URL muss dann kopiert werden, im *OpenPGP Key Manager* unter */Edit/Import Key(s) from URL* eingefügt, und der Schlüssel hinzugefügt werden:

![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key_manager.png){: width="500px"}

Je nachdem ob man den Schlüssel beim Import Akzeptiert hat oder nicht, muss nun noch die Authentizität des
Schlüssels bestätigt werden. Diese Akzeptanz des schlüssels gibt an, ob Thunderbird Signaturen von diesem Schlüssel vertrauen und diese als valide ansehen soll. Ein kleiner Einstieg in das Thema [Schlüsselauthentizität](#schlüsselauthentizität) gibt es
weiter unten.

Besitzervertrauen setzen im *OpenPGP Key Manager*: Mit einem
Rechtsklick auf den gewünschten Schlüssel öffnet man das Menü *Key
Properties* und setzt die Akzeptanz auf die höchste Stufe.
![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_certify_keys.png){: width="500px"}

Zusätzlich muss nun für die externe GnuPG-Verwendung, der Schlüssel auch im gpg-Schlüsselbund hinzugefügt werden.
Da es sich bei den privaten Schlüsseln am YubiKey ausschließlich um
Subschlüssel handelt, benötigen wir im gpg-Schlüsselbund zumindest
den öffentlichen Schlüssel. Dieser liefert uns die notwendigen
Informationen über die Struktur unseres OpenPGP-Schlüssels. Der gesamte
OpenPGP-Schlüssel besteht nämlich aus dem Hauptschlüssel (dieser hat den
Fingerprint mit der Endung "AAFAE") und den drei zugehörigen
Subschlüsseln deren private Teile sich am YubiKey befinden. Um nun den
eigenen öffentlichen Schlüssel zu importieren nutzen wir die "URL of public key", die wir auf unserem YubiKey [hinterlegt haben](/YubiKeyWiki/docs/OpenPGP#metadaten-auf-den-yubikey-laden).
Dieser Weg des Imports ist nur über das gpg-Kommando möglich und kann lediglich Schlüssel in den gpg-Schlüsselbund hinzufügen.
Dazu ist der YubiKey am System anzustecken und in der Kommandozeile
folgender Befehl auszuführen:

``` bash
kali@kali:~$ gpg --edit-card
gpg/card> fetch
gpg/card> quit
```

Wir haben gerade einen öffentlichen Schlüssel hinzugefügt. GnuPG erkennt
aber, dass eine Smartcard (YubiKey) am System angeschossen ist, der die
privaten Subschlüssel gespeichert hat. Daher sehe ich den zugehörigen
Schlüssel auch im privaten Schlüsselbund:

``` bash
kali@kali:~$ gpg -K
/home/kali/.gnupg/pubring.kbx
-----------------------------
sec>  rsa4096 2020-04-16 [SC] [expires: 2025-04-15]
      A662724593E61256E4ADB82E1E360B1A218AAFAE
      Card serial no. = 0006 12015372
uid           [ unknown] Kristoffer Dorfmayr <kristoffer.dorfmayr@gmail.com>
uid           [ unknown] Kristoffer Dorfmayr <S1810239005@students.fh-hagenberg.at>
uid           [ unknown] Kristoffer Dorfmayr <kristoffer.dorfmayr@hagenbergerkreis.at>
ssb>  rsa4096 2020-04-16 [E] [expires: 2025-04-15]
ssb>  rsa4096 2020-04-16 [A] [expires: 2025-04-15]
```

Das Größer-Zeichen ("\>") neben "sec" (Privates Schlüsselpaket) und "ssb" (Privates
Subschlüsselpaket) zeigt an, dass sich der private Schlüssel auf einer
Smartcard (YubiKey) befindet. 

Abschließend muss im jeweiligen Mailaccount, bei welchem der PGP-Schlüssel verwendet werden soll, die Nutzung dieses Schlüssels festgelegt werden. In die Account-Einstellungen gelangt man über */Edit/Account Settings* und wählt dort beim gewünschten Mailaccount den Menüpunkt *End-To-End Encryption* aus. Jetzt kann unter **OpenPGP** ein Schlüssel durck Klick auf *+ Add Key...* hinzugefügt werden. Dazu muss die 16-Zeichen lange Key-ID eingegeben werden. (siehe dazu die [Voraussetzungen](/YubiKeyWiki/docs/OpenPGP/mailverschluesselung.html#voraussetzungen))

![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key2account.png){: width="500px"}


#### Geschützte Email versenden

Jetzt wird es Zeit die erste OpenPGP-geschützte Email zu versenden\!
Beim Erstellen von Emails kann man auswählen, ob diese verschlüsselt
werden sollen und ob sie signiert werden soll. Ich versende eine Email an
Troye und wähle sowohl Verschlüsseln als auch Signieren im Drop-Down-Menü *Security* aus.
Je nachdem was ausgewählt ist erscheint beim Signieren rechts unten ein kleines Siegel und beim Verschlüsseln ein kleines Schloss. Außerdem wird das verwendete Verfahren (OpenPGP oder S/MIME) angezeigt.
![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_sendmail.png){: width="600px"}  
  
Wenn ich auf "Send" klicke werden im Hintergrund automatisch die
passenden Schlüssel herausgesucht:

  - Thunderbird findet einen öffentlichen Schlüssel für
    "finnegan.troye@gmail.com" und nutzt diesen zur
    Email-Verschlüsselung.
  - Thunderbird nutzt auch meinen öffentlichen Schlüssel zur
    Email-Verschlüsselung, damit ich sie selbst wieder entschlüsseln
    und somit lesen kann.
  - Thunderbird erkennt, dass es zum Signieren einen privaten
    Signaturschlüssel auf einer SmartCard gibt. Bevor der YubiKey die
    Email signiert, werde ich noch nach dem Pin gefragt, und muss den
    Signaturvorgang mit einer Berührung am YubiKey bestätigen:  
    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_sendmail_pin.png)  
    Falls ihr die Touch Policy und das Pin Setup noch nicht konfiguriert
    habt findet ihr Informationen dazu [hier](/YubiKeyWiki/docs/verwaltung#310-openpgp-verwalten).  
      

#### Geschützte Email empfangen

Auf meine versandte Email habe ich nun eine Antwort von Troye erhalten.
Sofort wenn ich auf die erhaltene Nachricht klicke, versucht Enigmail
diese zu entschlüsseln. Natürlich muss ich auch hier wieder meinen Pin
eingeben und die Entschlüsselung mit meinem privaten Schlüssel durch
eine Berührung des YubiKey autorisieren.  
![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_getmail.png){: width="600px"} 
Das Schlosssymbol mit dem kleinen grünen Haken zeigt uns, dass es sich um eine verschlüsselte
Nachricht handelt. Das kleine Siegel sagt uns, dass es sich um eine valide und akzeptierte (vertraute) Signatur handelt. Mehr dazu im nächsten Abschnitt.
  
#### Schlüsselauthentizität

In Thunderbird sind das Signieren von Schlüsseln und die Nutzung des Web-of-Trust im Gegensatz zu GnuPG nicht möglich. (Stand: Oktober 2021) Jeden Schlüssel, welchem man vertrauten möchte, muss man selbst akzeptieren. Dies kann auf zwei Arten geschehen:
  - Unmittelbar beim Importieren des Schlüssels, so wie im Abschnitt [Schlüssel Importieren](#schlüssel-importieren) gezeigt.
  - Über die *Key Properties* des jeweiligen Schlüssels im *OpenPGP Key Manager*.
    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key_properties.png){: width="600px"}

Je nachdem wie ich die Akzeptanz eingestellt habe, ändert sich bei der erhaltenen E-Mail das Signatur-Icon und die Zusatzinformation:
  - Akzeptanz auf **"Ablehnen"** (*No, reject this key*):

    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key_rejected.png){: width="450px"}

  - Akzeptanz auf **"Unentschieden"** (*Not yet, maybe later.*):

    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key_unaccepted.png){: width="450px"}

  - Akzeptanz auf **"Akzeptiert und unverifiziert"** (*Yes, but i have not verified that it is the correct key.*) - diese Option würde man wählen, wenn man zwar den Schlüssel verwenden möchte, man jedoch den Fingerprint des Schlüssels noch nicht auf seine Korrektheit überprüft hat:

    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key_accepted_unverified.png){: width="450px"}

  - Akzeptanz auf **"Akzeptiert und verifiziert"** (*Yes, I've verified in person this key has the correct fingerprint*):

    ![]({{ site.baseurl }}{{ page.dir }}img/thunderbird_key_accepted_verified.png){: width="450px"}


#### Verteilen von Schlüsseln

Um seinen eigenen Schlüssel anderen Personen zugänglich machen zu
können, gibt es Keyserver. Auf diese kann man öffentliche Schlüssel
hochladen. Um das "Web of Trust" aufzubauen, wäre ursprünglich angedacht
gewesen, dass jede beliebige Person öffentliche Schlüssel hochladen
kann. Ich signiere zum Beispiel den öffentlichen Schlüssel eines
Freundes, und lade ihn wieder auf den Keyserver hoch. Lädt nun eine
andere Person diesen Schlüssel herunter, die meinen Schlüssel bereits
signiert hat und für Authentisch befindet, so geht aufgrund des
Besitzervertrauens und meiner angebrachten Signatur die Authentizität
gleich auf den neuen Schlüssel über. Im Internet gibt es sehr viele
Keyserver, die eine Schlüsselverteilung in dieser einfachen Art
unterstützen. Zur Erhöhung der Ausfallsicherheit gibt es außerdem einen
Verbund von Schlüsselservern, wie beispielsweise die [SKS-Keyserver
Pools](https://sks-keyservers.net/overview-of-pools.php). **Die
Verwendung dieser Server ist jedoch nicht empfohlen**\! Grund dafür
sind<sup>[\[6\]](#quellen)</sup>:

  - Denial of Service: Ein Angreifer kann für einen öffentlichen
    Schlüssel beliebig viele Signaturen erstellen und auf den
    Schlüsselserver laden. Würde man sich diesen Schlüssel vom Server
    herunterladen, erhielte man den Schlüssel mit seinen vielen
    Signaturen. GnuPG kommt mit dieser Flut an Signaturen nicht zurande
    und wird unnutzbar.
  -  Identity Fraud: Selbst wenn ich gar keinen Schlüssel für meine
    Email Adresse besitze, kann eine fremde Person für diese Email einen
    Schlüssel erstellen und hochladen. Wenn der Schlüsselserver vor dem
    Upload aber zumindest eine Bestätigungsmail an die zum Schlüssel
    gehörige Email-Adresse sendet, ist das Risiko verringert.

Die Community rund um [Sequoia-PGP](https://sequoia-pgp.org/),
[OpenKeychain](https://www.openkeychain.org/) und
[Enigmail](https://enigmail.net/index.php/en/) hat sich dieser
Problematik angenommen und betreibt nun einen neuen Keyserver:
[keys.openpgp.org](https://keys.openpgp.org). Beim Hochladen eines Schlüssels
wird eine Email an alle zugehörigen Identitäten (also Email Adressen)
verschickt. Erst wenn diese Emails über einen Link bestätigt werden, ist
der Schlüssel mit der jeweiligen Identität online verfügbar. Auch die
Suche nach Schlüsseln ist nur möglich, wenn man die genaue Email Adresse
kennt. Damit wird verhindert, dass Bots automatisiert Schlüssel
herunterladen können. Und um die Problematik der vielen Signaturen zu
adressieren, werden beim Hochladen eines Schlüssels alle Signaturen von
fremden Schlüsseln entfernt.<sup>[\[8\]](#quellen)</sup>  
In Thunderbird ist der Standard Schlüsselserver keys.openpgp.org.

Kurz zusammengefasst bedeutet das: Die Standardeinstellung in Thunderbird ist in Bezug auf die Problematiken der Keyserver ausreichend
sicher.

```tip
**Sicherheitserwägung**: Wir empfehlen aus oben genannten Gründen
ausschließlich Schlüsselserver zu verwenden, welche die Email-Adresse
eines hochgeladenen Schlüssels verifizieren: *hkps://keys.openpgp.org*, *hkps://keys.mailvelope.com*,
*hkps://keyserver1.pgp.com/*
```   

#### Schlüssel widerrufen

Für den Fall, dass der private Schlüssel kompromittiert wird, gibt es
die Möglichkeit diesen zu widerrufen. Ein Widerruf soll auch
durchgeführt werden, wenn man den eigenen Schlüssel verliert oder ihn
einfach nicht mehr nutzen möchte. Es gibt zwei Wege einen Schlüssel zu
widerrufen:

  - Über ein zuvor erstelltes Widerrufszertifikat, welches in einer
    Datei abgespeichert wird. Die Datei kann in Enigmail ganz einfach im
    *OpenPGP Key Manager* über *File/Import Revocation(s) From File*
    importiert werden. Es ist daher empfohlen für den Fall des
    Schlüsselverlustes bereits beim Erstellen des eigenen
    OpenPGP-Schlüssels ein Widerrufszertifikat zu erstellen. Das wurde
    aber bereits in unserem Hauptartikel [OpenPGP](/YubiKeyWiki/docs/OpenPGP) beschrieben.
  - Wenn man den Hauptschlüssel noch besitzt, kann man ihn zum
    Widerrufen nutzen. Dafür navigiert man im *OpenPGP Key Manager*
    über den gewünschten Schlüssel und wählt nach einem Rechtsklick die
    *Revoke Key* Option.

Mit den oben genannten Methoden kann aber nur der gesamte Schlüssel
widerrufen werden\! Fremde Signaturen beziehen sich immer nur auf den
Hauptschlüssel. Es ist somit möglich Unterschlüssel auszutauschen, ohne
dass meine Kommunikationspartner sie neu signieren muss. Um einen
Unterschlüssel einzeln zu widerrufen muss man das GnuPG
Kommandozeilenprogramm nutzen. Mit der nachfolgenden Befehlssequenz
widerruft Troye seinen Authentifizierungs-Unterschlüssel:

``` bash
gpg --edit-key Troye
  > sec  rsa4096/2885B7BE8060F8B3
  >      created: 2020-05-15  expires: never       usage: SC  
  >      card-no: 0006 12015306
  >      trust: ultimate      validity: ultimate
  > ssb  rsa4096/78C5BC525C4821D5
  >      created: 2020-05-15  expires: never       usage: E   
  >      card-no: 0006 12015306
  > ssb  rsa4096/00E80C9E691B5140
  >      created: 2020-05-28  expires: never       usage: A   
  >      card-no: 0006 12015306
  > [ultimate] (1). Troye Finnegan <finnegan.troye@gmail.com>
key 2
revkey
save
```
  
Sobald ich einen Schlüssel widerrufen habe, muss ich diese Änderung
sofort an alle Kommunikationspartner weiterleiten\! Dafür kann ich
entweder den öffentlichen Schlüssel exportieren und selbst verteilen,
oder ich lade den Schlüssel erneut auf den Schlüsselserver hoch und
informiere meine Kommunikationspartner, dass sich der Schlüssel geändert
hat. Diese müssen dann im *Enigmail Key Management* unter
*Keyserver/Refresh All Public Keys* ihren lokalen Schlüsselbund
aktualisieren und Änderungen vom Schlüsselserver herunterladen. Seit
Enigmail 2.0 geschieht das in unregelmäßigen Intervallen
automatisch<sup>[\[11\]](#quellen)</sup>.  
Beim Hochladen der Schlüssel auf den Schlüsselserver
[keys.openpgp.org](https://keys.openpgp.org/) gilt es jedoch zu
beachten, dass derzeit jeweils nur ein Schlüssel pro Email Adresse
gespeichert werden kann\! Lädt man also einen neuen Schlüssel hoch (bei
dem sich der Hauptschlüssel geändert hat), wird der Alte gelöscht\! Für
eine Änderung der Unterschlüssel stellt das aber kein Problem dar.

```tip
**Sicherheitserwägung**: Wir empfehlen vor der Verwendung eines fremden
Schlüssels, dessen Wiederrufsstatus durch eine erneuten Zugriff auf den
Schlüsselserver abzufragen. Möglich ist das im *Enigmail Key Management* unter *Keyserver/Refresh All Public Keys*. 
``` 
  

#### Ablaufdatum von Schlüsseln ändern

Wenn das Ablaufdatum eines Schlüssels erreicht ist, kann dieser nicht
mehr verwendet werden. Das ist aber überhaupt kein Problem, da man das
Ablaufdatum des Haupt- und der Unterschlüssel mithilfe des
Zertifizierungsschlüssels (=Hauptschlüssel) verlängern kann. Im
Hintergrund wird einfach eine neue Signatur über den Öffentlichen
Schlüssel und dessen zugehörige Informationen (z.B. der
Verwendungszweck, Erstellungszeit, verwendeter Algorithmus, ...)
inklusive dessen neuen Ablaufdatum erstellt. Mit der nachfolgenden
Befehlssequenz setzt Troye das Ablaufdatum seiner Schlüssel auf 2 Jahre:

``` bash
gpg --edit-key Troye

  > sec  rsa4096/2885B7BE8060F8B3
  >      created: 2020-05-15  expires: 2020-06-16  usage: SC
  >      trust: unknown       validity: full
  > ssb  rsa4096/78C5BC525C4821D5
  >      created: 2020-05-15  expires: 2020-06-16  usage: E
  > ssb  rsa4096/953BB6B6F8B2856E
  >      created: 2020-05-29  expires: 2020-06-16  usage: A
  >      card-no: 0006 12015306
  > The following key was revoked on 2020-05-29 by RSA key 2885B7BE8060F8B3 Troye Finnegan <finnegan.troye@gmail.com>
  > sub  rsa4096/00E80C9E691B5140
  >      created: 2020-05-28  revoked: 2020-05-29  usage: A
  > [ ultimate ] (1). Troye Finnegan <finnegan.troye@gmail.com>
expire
2y
key 1
key 2
expire
2y
```
#### Fehlende Funktionalität

Nachdem mit Thunderbird 78 die unterstützung für das Enigmail-Plugin, welches im Hintergrund GnuPG verwendete, auslief, wurde die OpenPGP-Funktionalität in Thunderbird direkt eingebaut. Leider fehlen hier derzeit noch einige Features, welche möglicherweise mit folgenden Versionen ergänzt werden: (Stand Oktober 2021)

  - Signieren von Schlüsseln
  - Vertrauen von Schlüsseln auf Basis der Signaturen
  - Web-of-Trust Funktionalität
  - Automatischer Key-Refresh von Schlüsselservern
  - Nutzen von passwort-geschützten Schlüsseln (on-demand unlocking)


  
## FairEmail & OpenKeychain
![]({{ site.baseurl }}{{ page.dir }}img/0_fairemail_playstore.jpg)  
FairEmail ist ein open-source Email Client für Android-Geräte. Dieser
unterstützt unter anderem die Ver- und Entschlüsselung von Emails
mittels OpenPGP und S/MIME. Nach der Einrichtungsanleitung der App wird
werden wir auch die Verwendung mit dem YubiKey erklären.

### Installation und generelle Einrichtung

Der FairEmail-Client kann gratis über denn Google Playstore bezogen
werden. Die Einrichtung ist sehr simpel und wird hier in wenigen
Schritten gezeigt.  
Beim ersten Start wird man mit einer Einrichtungsseite begrüßt.  
![]({{ site.baseurl }}{{ page.dir }}img/1_fairemail_schnelleinrichtung.jpg)  
Hier empfielt es sich die Schnelleinrichtung zu verwenden. Im
Optimalfall hat man dadurch in nur einem Schritt ein Email-Konto
hinzugefügt:  
![]({{ site.baseurl }}{{ page.dir }}img/2_fairemail_einrichtung.jpg)  
Hier müssen ein Name, die Email Adresse und das zugehörige Passwort
eingegeben werden. Die Servereinstellungen versucht die App eigenständig
zu abzuleiten. Sie werden dann zur Kontrolle im unteren Bereich
angezeigt.  
Es können noch viele weitere Einstellungen getroffen werden. Interessant
ist für dieses Kapitel nur der *Verschlüsselung*-Tab. Hier kann die
gewünschte Verschlüsselungsmethode gewählt werden. Außerdem kann
festgelegt werden, ob jede Email standardmäßig signiert und
verschlüsselt werden soll. Abgesehen davon sind hier keine weiteren
Einstellungen zu tätigen.  
  
Das Setup wird abgeschlossen, wenn man im *Haupteinstellungen*-Tab ganz
nach unten scrollt und bei *Zu Nachrichten wechseln* auf *Los* klickt.
Nun sollte man den Posteingang sehen.  
Doch bevor man mit dem Verschlüsseln loslegen kann, benötigt man noch
eine weitere App: *OpenKeychain*.  
![]({{ site.baseurl }}{{ page.dir }}img/4_openkeychain_playstore.jpg)  
Diese übernimmt die Kommunikation mit dem YubiKey und ermöglicht das
Verschlüsseln von Dateien und der Email-Kommunikation. Nach der
Installation von OpenKeychain trägt FairEmail automatisch im Abschnitt
*OpenPGP-Anbieter* den Schlüsselbund von OpenKeychain ein. Die Option
*Autocrypt verwenden* sollte auf alle Fälle deaktiviert werden\! Infos
dazu siehe auch in den Thunderbird [Konfigurationsempfehlungen](#konfigurationsempfehlungen)  
![]({{ site.baseurl }}{{ page.dir }}img/3_fairemail_pgp_einstellungen.jpg)  
Die App kann man natürlich wieder über dem Playstore beziehen. Beim
Start der App wird gleich ein Setup Bildschirm angezeigt. Natürlich
müssen sich erst OpenPGP Schlüssel auf dem Gerät befinden, bevor man
mit ihnen arbeiten kann. Man kann Schlüssel am Smartphone erzeugen, aus
einer Datei importieren oder die Schlüssel auf einem Security Token
nutzen. Letzteres wird für den YubiKey benötigt.  
![]({{ site.baseurl }}{{ page.dir }}img/5_openkeychain_start.jpg)  
Im nächsten Schritt wird man aufgefordert, den YubiKey an das Smartphone
zu halten, da die App die NFC-Funktion verwendet.  
![]({{ site.baseurl }}{{ page.dir }}img/6_openkeychain_karte_anhalten.jpg)  
Wenn der YubiKey erkannt wird, wird anhand der [hinterlegten
URL](/yubikey4hk/funktionen/openpgp#metadaten_auf_den_yubikey_laden) der
zugehörige öffentlichen Schlüssel importiert. Dies muss noch mit dem
grünen Button *Import* bestätigt werden.  
![]({{ site.baseurl }}{{ page.dir }}img/7_openkeychain_key_hinzufuegen.jpg){: width="200px"}  
Der Schlüssel wird nun importiert:  
![]({{ site.baseurl }}{{ page.dir }}img/8_openkeychain_key_hinzugefuegt.jpg){: width="200px"}  
Wenn man nun auf *Schlüssel ansehen* klickt, kann man den
Schlüsselstatus überprüfen. Hier sollte stehen, das der Schlüssel
*stripped* ist und zum Signieren und Verschlüsseln geeignet ist.
*Stripped* heißt, dass der Hauptschlüssel fehlt. Dieser befindet sich
nicht am YubiKey, sondern nur die drei Unterschlüssel. Das hat den
Nachteil, dass man fremde öffentliche Schlüssel nicht signieren kann.  
![]({{ site.baseurl }}{{ page.dir }}img/9_openkeychain_keystatus.jpg)  
Die generelle Einrichtung der App ist nun abgeschlossen. Nun müssen noch
die öffentlichen Schlüssel der Kommunikationspartner hinzugefügt werden.

### Fremde Schlüssel importieren

Es gibt drei Möglichkeiten einen fremden Schlüssel hinzuzufügen:

  - QR-Code einscannen
  - Schlüssel suchen
  - Aus Datei importieren

![]({{ site.baseurl }}{{ page.dir }}img/10_openkeychain_fremden_schluessel_import.jpg){: width="200px"}   
Den QR-Code eines Schlüssels erhält man, indem man unter *Meine
Schlüssel* auf den Schlüsseleintrag klickt. Der QR-Code wird dann am
Bildschirm angezeigt und kann mithilfe der *QR-Code einscannen* Option
auf einem anderen Gerät hinzugefügt werden.  
Die zweite Option *Schlüssel suchen* ermöglicht es Schlüssel von einem
Schlüsselserver heruntergeladen. Mithilfe dieser Option können wir
beispielsweise den Schlüssel von *finnegan.troye@gmail.com* hinzufügen.
Auch hier gilt, wie schon bei Thunderbird: unbedingt den Fingerprint des
Schlüssels überprüfen\! Der Fingerprint lässt sich nach dem Hinzufügen
des Schlüssels anzeigen. Dazu navigiert man auf *Schlüssel
auswählen/.../Erweitert/Teilen*.  
![]({{ site.baseurl }}{{ page.dir }}img/11_openkeychain_key_suche.jpg)  
Bevor man jedoch Schlüssel finden kann, muss ein Schlüsselserver
eingestellt werden. Dafür navigiert man in den Einstellungen, die oben
rechts mit den drei vertikalen Punkten aufrufbar sind. Hier findet man
folgendes Menü vor:  
![]({{ site.baseurl }}{{ page.dir }}img/12_openkeychain_keyserver_menu.jpg)  
Der Keyserver wird nun unter *OpenPGP Schlüsselserver verwalten*
eingestellt. Hier findet man ein paar voreingestellte Server. Wir
empfehlen, wie bereits bei Thunderbird die Nutzung von Schlüsselservern,
welche die Email-Adresse verifizieren. Die von uns empfohlenen Server
(siehe [Verteilen von Schlüsseln](#verteilen-von-schlüsseln)) haben
leider auf unserem Testtelefon (Android 8.0) nicht funktioniert. Immer
wieder gibt es deswegen auch Bug-Reports auf github wie auch
[hier](https://github.com/open-keychain/open-keychain/issues/2499) und
[hier](https://github.com/open-keychain/open-keychain/issues/2469). Am
besten man importiert die bereits signierten Schlüssel aus einem File,
das man auf das Telefon kopiert. Der oberste Schlüsselserver ist grün
hinterlegt. Es wird immer dieser Server befragt.  
![]({{ site.baseurl }}{{ page.dir }}img/13_openkeychain_keyserver_settings.jpg)  
Nachdem man den richtigen Server ausgewählt und eventuell auch
hinzugefügt hat, kann man nach einen fremden Schlüssel suchen.  
  
Nachdem wir am Smartphone ohnehin keine Möglichkeit haben, fremde
Schlüssel zu signieren, empfiehlt es sich die bereits signierten
Schlüssel vom Computer auf das Smartphone zu transferieren. Der Import
erfolgt dann über die Option *Aus Datei importieren*.  
Sobald man den öffentlichen Schlüssel des Empfängers importiert hat,
kann man eine verschlüsselte Email an ihn senden.

### Email versenden

Wenn man eine Email in FairEmail senden möchte, muss man nur auf das
Stift-Symbol im unteren Bereich des Bildschirms drücken. Nun sieht man
diesen Bildschirm:  
![]({{ site.baseurl }}{{ page.dir }}img/14_fairemail_email_senden.jpg)  
Wenn man eine durch OpenPGP geschützte Email versenden möchte, muss man
im oberen Bereich das Schloss-Symbol antippt, bis es grün wird. Dies ist
im vorherigen Screenshot rot umrandet. Das kann auch beim Sende-Symbol
kontrolliert werden, indem darunter *Verschlüsseln* steht. Dieses
"Verschlüsseln" sagt aber nichts darüber aus, ob verschlüsselt und/oder
signiert wird, sondern lediglich, dass OpenPGP zum Einsatz kommt.  
Nun muss man noch einen Empfänger eintragen und einen netten Text
schreiben und man kann die Email versenden. Vor dem Senden, werden zur
Kontrolle noch einmal die Einstellungen ausgegeben::  
![]({{ site.baseurl }}{{ page.dir }}img/15_fairemail_email_settings.jpg)  
Hier sieht man, dass unter *Verschlüsselung* *PGP signieren und
verschlüsseln* ausgewählt ist. Wenn man möchte kann man hier auch
auswählen, dass die Email nur signiert werden soll. Wenn die
Einstellungen korrekt sind, drückt man auf *Senden*. Es wird dann
automatisch OpenKeyChain gestartet und die Kommunikation mit dem YubiKey
initialisiert. Man muss diesen an das Smartphone halten und mit dem PIN
entsperren, damit die NFC-Funktion genutzt werden kann. Durch diesen
Vorgang wird man visuell begleitet. Bei Erfolg wird die Email
automatisch versendet\!  
Dieser Ablauf ist für jede Email dieselbe. Man muss daran denken, dass
man den verwendeten öffentlichen Schlüssel zuerst auf OpenKeyChain
importiert, bevor an die zugehörige Email-Adresse eine verschlüsselte
Nachricht senden kann..

## Quellen

<sup>\[1\]</sup> OpenPGP Git, *OpenPGP History*, Letzter Zugriff
15.05.2020, \[Online\], URL: <https://www.openpgp.org/about/history/>  
<sup>\[2\]</sup> Mozilla, *Thunderbird:OpenPGP*,
(2021), Letzter Zugriff 05.09.2021, \[Online\], URL:
<https://wiki.mozilla.org/Thunderbird:OpenPGP>  
<sup>\[3\]</sup> The Enigmail Project, *2019-10-08 Future OpenPGP
Support in Thunderbird*, Letzter Zugriff 12.05.2020, \[Online\], URL:
<https://www.enigmail.net/index.php/en/home/news/70-2019-10-08-future-openpgp-support-in-thunderbird>  
<sup>\[4\]</sup> J. Callas, *OpenPGP Message Format*. RFC 4880 (PROPOSED
STANDARD), Internet Engineering Task Force, Nov. 2007, Updated by RFC
5581 \[Online\]. URL: <https://tools.ietf.org/html/rfc4880>  
<sup>\[5\]</sup> Matthew Copeland et. al., *The GNU Privacy handbook*,
Letzter Zugriff 23.05.2020, \[ONLINE\], URL:
<https://www.gnupg.org/gph/en/manual.html#AEN385>  
<sup>\[6\]</sup> Robert J. Hansen, *SKS Keyserver Network Under Attack*,
Letzter Zugriff 27.05.2020, \[ONLINE\], URL:
<https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f>  
<sup>\[7\]</sup> Werner Koch, *GnuPG 2.2.17 released to mitigate attacks
on keyservers*, Letzter Zugriff 27.05.2020, \[ONLINE\], URL:
<https://lists.gnupg.org/pipermail/gnupg-announce/2019q3/000439.html>  
<sup>\[8\]</sup> keys.openpgp.org, *Frequently Asked Questions*, Letzter
Zugriff 27.05.2020, \[ONLINE\], URL:
<https://keys.openpgp.org/about/faq>  
<sup>\[9\]</sup> The Enigmail Project, *Changelog*, Letzter Zugriff
27.05.2020, \[ONLINE\], URL:
<https://enigmail.net/index.php/en/download/changelog>  
<sup>\[10\]</sup> Autocrypt Team, *Example Data Flows and State
Transitions*, Letzter Zugriff 27.05.2020, \[ONLINE\], URL:
<https://autocrypt.org/examples.html>  
<sup>\[11\]</sup> The Enigmail Project, *Enigmail FAQ*, Letzter Zugriff
29.05.2020, \[ONLINE\], URL:
<https://enigmail.net/index.php/en/user-manual/handbook-faq#auto-key-refresh>
