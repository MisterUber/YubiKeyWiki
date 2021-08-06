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
Lizenz. Um OpenPGP verwenden zu können gibt es das
[Enigmail](https://addons.thunderbird.net/de/thunderbird/addon/enigmail/)
Plugin, das von [Patrick
Brunschwig](https://addons.thunderbird.net/de/thunderbird/user/patrick-brunschwig/)
entwickelt wird. Dieses wird aber aufgrund einer Änderung im Add-on
Support im neuen Thunderbird 78, dessen Release für den Sommer 2020
geplant ist, nicht mehr unterstützt\! Brunschwig wird aber mit den
Entwicklern von Thunderbird zusammenarbeiten um die
OpenPGP-Funktionalität direkt in Thunderbird 78 zu
integrieren<sup>[\[2\]](#quellen)</sup>. Thunderbird 68 wird noch bis im
Herbst 2020 gewartet<sup>[\[2\]](#quellen)</sup>, der Support für
Enigmail läuft bis 6 Monate nach dem Release von Thunderbird 78 im
Sommer 2020<sup>[\[3\]](#quellen)</sup>. Damit ihr gleich mit der Email
Verschlüsselung loslegen könnt, haben wir uns dazu entschieden im
Folgenden das Setup für Enigmail auf Thunderbird 68 zu erklären. Weiter
unten gibt es einen [Ausblick für Thunderbird 78](#thunderbird-78) und
dessen aktuellen Entwicklungsstand in Bezug auf die Integration von
OpenPGP, damit ihr möglichst gut gerüstet seid für den Umstieg auf die
Built-In Variante im Herbst 2020.  
Informationen und Hilfestellungen bei der generellen Verwendung von
Thunderbird gibt es auf der [offiziellen
Seite](https://support.mozilla.org/de/products/thunderbird/how).

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

Für die Verwendung von Enigmail muss außerdem GnuPG installiert sein.
Sollte das nicht der Fall sein ist das Paket ebenfalls zu installieren:

``` bash
sudo apt install gpg
```

#### Windows

Zur Installation auf Windows ist die aktuellste Version von der
offiziellen Seite [herunterzuladen](https://www.thunderbird.net/de/) und
zu installieren. Nachdem Enigmail auf GnuPG aufbaut muss zusätzlich
[Gpg4win](https://www.gpg4win.de/) installiert sein.

### Das Enigmail Plugin

Alle weiteren Schritte werden direkt in Thunderbird, oder über das
Kommandozeilenprogramm "gpg" ausgeführt und sind vom Betriebssystem
unabhängig. Um später über die Menüleiste auf das Enigmail Plugin
zugreifen zu können, empfiehlt es sich, die Menüleiste zu fixieren. Sie
kommt durch Drücken der "F10"-Taste zum Vorschein und kann dort über
*View/Toolbars/Menu Bar* fixiert werden.  
Enigmail kann über den Add-ons Manager installiert werden. Um diesen
aufzurufen navigiert man in der Menüleiste auf *Tools/Add-ons*. Dort
kann im Suchfeld nach "Enigmail" gesucht werden und durch einen Klick
auf den "*+ Add to Thunderbird*" Knopf wird Enigmail hinzugefügt. Danach
ist ein Neustart von Thunderbird erforderlich.  
Nach dem Neustart sollte oben in der Menüleiste der Reiter "Enigmail"
hinzugekommen sein. Enigmail ist im Grunde nichts anderes als ein
grafisches Frontend für GnuPG. Deshalb sieht man, wenn man über die
Menüleiste zur Schlüsselverwaltung navigiert (*Enigmail/Key
management*) möglicherweise bereits den eigenen Schlüssel aus dem GnuPG
Schlüsselbund:  
![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_key_management.png)  
Es empfiehlt sich außerdem, mehr Informationen im *Enigmail Key
Management* anzeigen zu lassen. Dann hat man einen viel besseren
Überblick über alle Keys und deren jeweilige Stati. Die entsprechende
Einstellung findet sich in der rechten oberen Ecke der
Schlüsseltabelle:  
![](/YubiKeyWiki/images/openpgp/enigmail_keymanagement_index_tab.png)  
Um die Informationen von Smartcards (also dem YubiKey) abrufen zu
können, muss man im Enigmail noch den "Expertenmodus" aktivieren. Das
macht man über die Menüleiste *Enigmail/Preferences* durch einen Druck
auf die Taste "Display Expert Settings and Menus":  
![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_expert_settings.png)  
Die Funktionalitäten des *Enigmail Key* Management sind jene von GnuPG,
da Enigmail ein grafisches Frontend für GnuPG ist. Enigmail nutzt also
das "gpg" Programm um Schlüssel zu verwalten und ruft für die
Bearbeitung von Emails die Signatur- und Ver-/Entschlüsselungsfunktionen
von GnuPG auf. Alle Schlüssel die im *Enigmail Key Management* angezeigt
werden, liegen also im GnuPG Schlüsselbund. Dieser Schlüsselbund ist im
jeweiligen Nutzerverzeichnis zu finden: *\~/.gnupg* bei Linux und
*%appdata%/gnupg* in Windows. Alle Schlüsselmanagementaufgaben können
also sowohl in der Kommandozeile mithilfe von *gpg* oder im *Enigmail
Key Management* vorgenommen werden. Folgende Einstellungen können im
*Enigmail Key Management* vorgenommen werden:

  - Generieren von OpenPGP Schlüsselpaaren
  - [Importieren](#schlüssel-importieren) und Exportieren von
    Schlüsseln
  - Interaktion mit fremden Schlüsseln
      - [Signieren/Zertifizieren](#schlüssel-signieren)
      - [Besitzervertrauen festlegen](#besitzervertrauen-und-schlüsselauthentizität)
  - Anpassen der Informationen am YubiKey

  
  
#### Schlüssel importieren
Wenn man jemandem eine verschlüsselte
Email senden oder Signaturen von jemandem überprüfen möchte, braucht man
dazu dessen öffentlichen Schlüssel. Dieser lässt sich über verschiedene
Wege mithilfe des *Enigmail Key Management* in den lokalen Schlüsselbund
importieren. Auch private Schlüssel lassen sich über diese Wege
importieren.(das *Enigmail Key Management* Fenster findet man über die
Menüleiste: *Enigmail/Key management*).

  - **Importieren des Schlüssels über eine Datei**: Dafür muss ich den
    öffentlichen Schlüssel in Form einer Datei auf das eigene System
    transferieren und dann im *Enigmail Key Management* über
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
    man im *Enigmail Key Management* die Option *Edit/Import Keys from
    URL* nutzen.
  - **Importieren des Schlüssels über einen Keyserver**: Im Grunde ist
    hier kein großer Unterschied zum Import von einer URL, da man
    genauso eine Datei von einem Keyserver herunterlädt. Der große
    Vorteil ist aber die Suchfunktion. Im *Enigmail Key Management*
    navigiere ich dafür auf *Keyserver/Search for Keys*. Ich importiere
    hier beispielhaft den öffentlichen Schlüssel meines fiktiven
    Testkollegen Troye Finnegan:  
    ![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_import_troye.png)  
    Nachdem ich nach ihm gesucht habe, sehe ich seinen Schlüssel und
    kann diesen importieren.  
    ![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_import_troye_fingerprint.png)  
    Ich sehe nun den Schlüssel von Troye in meinem Schlüsselbund. Ich
    kann im *Enigmail Key Management* auf einen Blick sehen ob es sich
    bei Schlüsseln um private (fette Schrift) oder öffentliche Schlüssel
    (normale Schrift) handelt:  
    ![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_import_troye_done.png)  

```tip
**Sicherheitserwägung**: Beim Hinzufügen von öffentlichen Schlüsseln **soll** sichergestellt werden, dass es sich wirklich um den
öffentlichen Schlüssel meines gewünschten Kommunikationspartners
handelt\! Die Überprüfung der Authentizität des importierten Schlüssels
hat unbedingt auf einem zweiten Kommunikationskanal zu erfolgen. Denkbar
sind ein persönliches Treffen oder ein Telefongespräch, wenn ich die
Stimme meines Gegenüber erkennen kann. Über diesen zweiten
Kommunikationskanal muss der **Fingerprint des Schlüssels abgeglichen** werden. Auf dieser initialen Authentifizierung baut die Sicherheit bei
der OpenPGP-Kommunikation auf\! Überprüft man die Authentizität nicht, so **darf der Schlüssel nicht [signiert](#schlüssel-signieren)** werden\! Außerdem muss man sich der Tatsache und Konsequenzen der
fehlenden Authentizität bewusst sein\! 
```
 
  
  

#### Privaten Schlüssel vom YubiKey verfügbar machen

Im Ausschnitt oben hat man bereits meinen öffentlichen Schlüssel
gesehen. Dieser hat die Key-ID mit der Endung "59C51". Wenn ich aber
Enigmail auf einem neuen System installiere ist mein Schlüssel noch
nicht am System. In diesem Absatz gehe ich davon aus, dass der eigene
Schlüssel noch nicht am System bekannt ist. Ich sehe also nur den zuvor
hinzugefügten Schlüssel von Troye:  
![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_privavail_troye.png)  
Da es sich bei den privaten Schlüsseln am YubiKey ausschließlich um
Subschlüssel handelt, benötigen wir im lokalen Schlüsselbund zumindest
den öffentlichen Schlüssel. Dieser liefert uns die notwendigen
Informationen über die Struktur unseres OpenPGP-Schlüssels. Der gesamte
OpenPGP-Schlüssel besteht nämlich aus dem Hauptschlüssel (dieser hat den
Fingerprint mit der Endung "59C51") und den drei zugehörigen
Subschlüsseln deren private Teile sich am YubiKey befinden. Um nun den
eigenen öffentlichen Schlüssel zu importieren gibt es die gleichen Wege
wie oben im Abschnitt [Schlüssel importieren](#schlüssel-importieren)
beschrieben. Ein Import der öffentlichen Schlüssel direkt vom YubiKey
auf das jeweilige System ist nicht möglich, da dafür nicht genügend
Informationen über den öffentlichen Schlüssel auf dem YubiKey
gespeichert sind\! Eine weitere sehr praktische Variante ist die Nutzung
der "URL of public key", die wir auf unserem YubiKey [hinterlegt
haben](/YubiKeyWiki/docs/OpenPGP#metadaten-auf-den-yubikey-laden).
Dieser Weg des Imports ist aber nur über das gpg-Kommando möglich.
Einfach den YubiKey am System anstecken und in der Kommandozeile
folgende Befehle ausführen:

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
sec#  rsa4096 2020-04-16 [C] [expires: 2025-04-15]
      3E0F0BA9061396B9302767F860E2EB9A7EF59C51
uid           [ultimate] Kristoffer Dorfmayr <kristoffer.dorfmayr@hagenbergerkreis.at>
ssb>  rsa4096 2020-04-16 [E] [expires: 2025-04-15]
ssb>  rsa4096 2020-04-16 [S] [expires: 2025-04-15]
ssb>  rsa4096 2020-04-16 [A] [expires: 2025-04-15]
```

Der Hash ("\#") neben "sec" (Privates Schlüsselpaket) sagt mir, dass der
Hauptschlüssel nicht verfügbar ist. Das ist auch verständlich, da am
YubiKey nur die drei Subschlüssel zum Signieren, Verschlüsseln und zur
Authentisierung liegen. Das Größer-Zeichen ("\>") neben "ssb" (Privates
Subschlüsselpaket) zeigt an, dass sich der private Schlüssel auf einer
Smartcard (YubiKey) befindet. Jetzt müssen wir die Authentizität des
Schlüssels noch bestätigen. Um einen Schlüssel als authentisch zu
erklären, muss man diesen mit dem eigenen Zertifizierungsschlüssel
Signieren/Zertifizieren. Der Zertifizierungsschlüssel ist in diesem Fall
der Hauptschlüssel, dessen Verwendung mit einem \[C\] für "Certify"
ausgestattet ist. Nachdem der eigene Schlüssel (und seine Subschlüssel)
immer automatisch bei der Erstellung signiert werden (="self signed"),
ist das schon erledigt. Wir müssen aber zusätzlich festlegen, ob wir der
Person vertrauen die mit diesem Zertifizierungsschlüssel andere
Schlüssel Signiert/Zertifiziert. Dieses "Vertrauen" nennt sich "Owner
Trust". Derzeit ist das Benutzervertrauen "\[unknown\]". Das lässt sich
sowohl im Enigmail als auch in der Komandozeile ändern. Da es sich hier
um unseren eigenen Schlüssel handelt, vertrauen wir Zertifizierungen die
mit diesem Schlüssel gemacht werden ultimativ ("Ultimate"). Ein kleiner
Einstieg in das Thema [Vertrauen und Authentizität](#übersicht-vertrauen-und-authentizität) gibt es
gleich im Anschluss an diesen Abschnitt.

  - Besitzervertrauen setzen im *Enigmail Key Management*: Mit einem
    Rechtsklick auf den gewünschten Schlüssel öffnet man das Menü *Key
    Properties* und setzt das Vertrauen auf "Ultimate"  
    ![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_certify_keys.png)
  - Besitzervertrauen setzten in der Kommandozeile:
  ```
kali@kali:~$ gpg --edit-key kristoffer.dorfmayr@hagenbergerkreis.at
    gpg> trust
    Please decide how far you trust this user to correctly verify other users' keys (by looking at passports, checking fingerprints from different sources, etc.)
    
            1 = I don't know or won't say
            2 = I do NOT trust
            3 = I trust marginally
            4 = I trust fully
            5 = I trust ultimately
            m = back to the main menu
    
    Your decision? 5
    Do you really want to set this key to ultimate trust? (y/N) y
    ```

  

#### Übersicht Vertrauen und Authentizität

Der Begriff "Vertrauen" ist bei OpenPGP mit zwei Bedeutungen überlagert.
Einerseits das "Vertrauen in einen Schlüssel", andererseits das
"Vertrauen in den Besitzer (Eigentümer) eines Schlüssels". Um hier eine
klare Abtrennung zu schaffen verwenden wir die Begriffe "Authentizität"
des Schlüssels (siehe 1.) und "Besitzervertrauen" (siehe 2.):

1.  **Schlüsselauthentizität**: Ich [signiere](#schlüssel-signieren)
    öffentliche Schlüssel und sage damit aus, dass ich diese für
    authentisch befinde. Ich binde also den öffentlichen Schlüssel zu
    den Angaben des Besitzers (Name und Email), nachdem ich diese
    Zusammengehörigkeit überprüft/verifiziert/validiert habe.
2.  **Besitzervertrauen**: Jeder Schlüssel in meinem Schlüsselbund hat
    ein Vertrauenslevel (=Besitzervertrauen). Damit gebe ich an, wie
    sehr ich dem Besitzer des Schlüssels vertraue, dass er die
    Authentizität anderer Schlüssel überprüft, bevor er sie signiert.

Ob GnuPG einen Schlüssel als authentisch betrachtet hängt davon ab:

  - ob ich ihn signiert habe, oder
  - ob genügend Vertrauenswürdige (Besitzervertrauen\!) Personen den
    Schlüssel signiert haben.

Was "genügend" hier genau bedeutet ist im Abschnitt [Besitzervertrauen und Schlüsselauthentizität](#besitzervertrauen-und-schlüsselauthentizität)
erklärt.  
  

#### Geschützte Email versenden

Jetzt wird es Zeit die erste OpenPGP-geschützte Email zu versenden\!
Beim Erstellen von Emails kann man auswählen, ob diese verschlüsselt
werden sollen (Anklicken des kleinen Schloss Symbols) und ob sie
Signiert werden soll (kleines Stiftsymbol). Ich versende eine Email an
Troye und wähle sowohl Verschlüsseln als auch Signieren aus. Zusätzlich
kann ich noch überprüfen, ob Enigmail auch den Betreff der Email
schützen wird. Dafür Schaue ich ins Enigmail Menü und versichere mich,
dass der Haken bei "Protect Subject" gesetzt ist.  
![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_sendmail.png)  
  
Wenn ich auf "Send" klicke werden im Hintergrund automatisch die
passenden Schlüssel herausgesucht:

  - Enigmail findet einen öffentlichen Schlüssel für
    "finnegan.troye@gmail.com" und nutzt diesen zur
    Email-Verschlüsselung.
  - Enigmail nutzt auch meinen öffentlichen Schlüssel zur
    Email-Verschlüsselung, damit ich sie selbst wieder entschlüsseln
    und somit lesen kann.
  - Enigmail erkennt, dass es zum Signieren einen privaten
    Signaturschlüssel auf einer SmartCard gibt. Bevor der YubiKey die
    Email signiert, werde ich noch nach dem Pin gefragt, und muss den
    Signaturvorgang mit einer Berührung am YubiKey bestätigen:  
    ![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_sendmail_pin.png)  
    Falls ihr die Touch Policy und das Pin Setup noch nicht konfiguriert
    habt findet ihr Informationen dazu [hier](/YubiKeyWiki/docs/verwaltung#310-openpgp-verwalten).  
      

#### Geschützte Email empfangen

Auf meine versandte Email habe ich nun eine Antwort von Troye erhalten.
Sofort wenn ich auf die erhaltene Nachricht klicke, versucht Enigmail
diese zu entschlüsseln. Natürlich muss ich auch hier wieder meinen Pin
eingeben und die Entschlüsselung mit meinem privaten Schlüssel durch
eine Berührung des YubiKey autorisieren.  
![](/YubiKeyWiki/images/openpgp/thunderbird_enigmail_getmail.png)  
Das Schlosssymbol zeigt uns, dass es sich um eine verschlüsselte
Nachricht handelt. Der kleine Brief sagt uns, dass es sich um eine
signierte Nachricht handelt. Zusätzlich bekommen wir die Nachricht "Good
Signature from Troye..". Das bedeutet, dass die Email, seit Anbringen
der Signatur nicht verändert wurde. Beim kleinen Briefsymbol befindet
sich aber ein blaues Fragezeichen und die Bannerinformation ist türkis
hinterlegt. Das sind Hinweise darauf, dass GnuPG den Schlüssel noch
nicht für authentisch befindet. Das kann man ändern, indem man ihn mit
dem privaten Zertifizierungsschlüssel (also dem Hauptschlüssel)
signiert. Weitere Informationen hierzu im nächsten Abschnitt.  
  

#### Schlüssel signieren

Wenn man den OpenPGP-Schlüssel von jemandem signiert, wird dessen
öffentlichem OpenPGP-Schlüssel einfach ein Signaturenpaket ("Signature
packet") angehängt. In diesem Paket befindet sich eine Signatur über das
"Public Key Packet" (also den öffentlichen Hauptschlüssel) und ein "User
ID Packet" (also eine spezifische Identität bestehend aus Email und
Name). Sollte man einen öffentlichen Schlüssel signieren, der mehrere
Identitäten (also Email Adressen) hat, wird für jede Identität ein
eigenes Signaturenpaket erstellt und dem öffentlichen Schlüssel
angehängt.<sup>[\[4, Kapitel 5.2\]](#quellen)</sup> Wenn von
"Zertifizieren" die Rede ist (= certify), dann meint man damit das
Signieren eines Schlüssels. Im Enigmail sieht man die Äquivalenz dieser
beiden Ausdrücke sehr gut. In den *Key Properties* eines Schlüssels gibt
des den Knopf *Certify* zum Signieren von Schlüsseln. Ein Rechtsklick
auf einen Schlüssel im *Enigmail Key Management* ermöglicht die Auswahl
der Option *Sign Key* die ebenfalls zum Signieren von Schlüsseln dient.
Beide Wege öffnen das exakt gleiche Fenster und dienen dem Signieren von
Schlüsseln (=Zertifizieren).  

```tip
**Sicherheitserwägung**: Beim signieren von öffentlichen Schlüsseln **muss** sichergestellt werden, dass es sich wirklich um den
öffentlichen Schlüssel meines gewünschten Kommunikationspartners
handelt\! Die Überprüfung der Authentizität des importierten Schlüssels
hat unbedingt auf einem zweiten Kommunikationskanal zu erfolgen. Denkbar
sind ein persönliches Treffen oder ein Telefongespräch, wenn ich die
Stimme meines Gegenüber erkennen kann. Über diesen zweiten
Kommunikationskanal muss der **Fingerprint des Schlüssels abgeglichen** werden. Auf dieser initialen Authentifizierung baut die Sicherheit bei
der OpenPGP-Kommunikation auf\!
```
  
  
Wie im Abschnitt [Geschützte Email empfangen](#geschützte-email-empfangen) bereits angesprochen, wird
zum Signieren von Schlüsseln, der Zertifizierungsschlüssel (also der
private Hauptschlüssel, mit der Eigenschaft \[C\] für "Certify")
benötigt. Der Hauptschlüssel liegt aber nicht am YubiKey, da dieser nur
Platz für die drei Unterschlüssel bietet. Dieser soll ausschließlich auf
unserem sicheren System liegen, auf dem wir unseren OpenPGP-Schlüssel
erstellt haben. Er ist aufgrund seiner Fähigkeiten besonders
schützenswert: Mit ihm kann man andere Schlüssel signieren und den
eigenen Schlüssel verwalten (Ablaufdatum verändern, (Sub-)Schlüssel
widerrufen und neue Subschlüssel hinzufügen).  
Andere Schlüssel zu Signieren ist uns also nur auf dem einen sicheren
System möglich. Öffentliche Schlüssel müssen dort signiert, exportiert
und auf alle gewünschten Systeme transferiert werden. Für den Transfer
der Schlüssel bietet sich beispielsweise eine Email an, die man an sich
selbst versendet. In den Anhang legt man alle exportierten öffentlichen
Schlüssel, die man bereits signiert hat, und hat so die Schlüssel mit
ihren Signaturen auf allen Email Clients verfügbar.  
Nun aber zurück zum Signieren von Schlüsseln in Enigmail. Derzeit habe
ich den Schlüssel von Troye noch nicht signiert, weshalb die
Authentizität des Schlüssel auch noch nicht angegeben ist ("-" Eintrag
im Feld "Key Validity"):  
![](/YubiKeyWiki/images/openpgp/enigmail_sign1.png)  
Mit einem Rechtsklick auf den Schlüssel "Sign Key" öffnet sich das
Fenster zum Signieren des Schlüssels:  
![](/YubiKeyWiki/images/openpgp/enigmail_sign2.png)  
Wenn man mehrere Schlüssel im privaten Schlüsselbund hat, welche die
"Certify" Eigenschaft besitzen, kann man diese über das "Key for
signing" Drop-Down Menü auswählen. Ich habe nur den einen Hauptschlüssel
mit der Endung "59C51" und werde mit diesem, den öffentlichen Schlüssel
von Troye signieren.  
Die Abfrage, wie genau man die Authentizität des Schlüssels überprüft
hat, hat Auswirkung auf den Signaturtyp<sup>[\[4, Kapitel 5.2.1\]](#quellen)</sup>, der im Signaturpaket vermerkt ist. Im Grunde
ist das für Enigmail aber unerheblich - signiert ist signiert.  
Die Auswahl "Local signature" ermöglicht es, schlüssel lokal, also nicht
exportierbar zu signieren. Das heißt, dass sich Enigmail die Signatur
merkt, das Signaturenpaket aber nicht im GPG-Schlüsselbund an den
jeweiligen Schlüssel angehängt wird. Exportiert man diesen signierten
öffentlichen Schlüssel wird eine lokale Signatur also nicht
mit-exportiert. Sollte man später von einer lokalen Signatur auf eine
"normale" Signatur umsteigen wollen, kann man den Schlüssel einfach
erneut signieren, nur ohne die Auswahl der lokalen Signatur.  
Nach Bestätigen des Dialoges und Eingabe der Passphrase wird meine
Signatur dem öffentlichen Schlüssel angehängt. Ersichtlich ist diese
Signatur in den Schlüsseleigenschaften des signierten Schlüssels
(*rechtsklick/Key Properties/Certifications*):  
![](/YubiKeyWiki/images/openpgp/enigmail_sign3.png)  
Hier können ohne weiteres auch mehrere Signaturen aufscheinen.
Einerseits die Signaturen des Hauptschlüssels über sich selbst und seine
Subschlüssel, andererseits Signaturen von den Schlüsseln anderer Nutzer.
Mithilfe des Kommandozeilenprogrammes *pgpdump* kann man sich den
genauen Aufbau eines Schlüssels sehr gut ansehen. Man sieht hier das
hinzugefügte Signaturpaket (Zeile 13), das mit meinem Schlüssel mit der
Endung "59C51" (Zeile 19) über den öffentlichen Schlüssel (Paket beginnt
in Zeile 2) und die Identität (Paket beginnt in Zeile 8) erstellt wurde:


```bash
1     kali@kali:~$ pgpdump finnegan.troye_pub.asc 
2     Old: Public Key Packet(tag 6)(525 bytes)
3             Ver 4 - new
4             Public key creation time - Fri May 15 20:30:53 CEST 2020
5             Pub alg - RSA Encrypt or Sign(pub 1)
6             RSA n(4096 bits) - ...
7             RSA e(17 bits) - ...
8     Old: User ID Packet(tag 13)(41 bytes)
9             User ID - Troye Finnegan <finnegan.troye@gmail.com>
10    
11            - Zeilen gekürzt -
12    
13    Old: Signature Packet(tag 2)(563 bytes)
14            Ver 4 - new
15            Sig type - Positive certification of a User ID and Public Key packet(0x13).
16            Pub alg - RSA Encrypt or Sign(pub 1)
17            Hash alg - SHA256(hash 8)
18            Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
19             v4 -   Fingerprint - a6 62 72 45 93 e6 12 56 e4 ad b8 2e 1e 36 0b 1a 21 8a af ae 
20     
21            - Zeilen gekürzt -
```



Durch das Signieren des Schlüssels ist die Autzentizität des Schlüssels
(Gültigkeit) auf "trusted" gewechselt:  
![](/YubiKeyWiki/images/openpgp/enigmail_sign4.png)  
  
Weitere Informationen über das Vertrauen gegenüber von Schlüsseln und
Schlüsselbesitzern im nächsten Abschnitt.  
  

#### Besitzervertrauen und Schlüsselauthentizität

(Der Begriff "Vertrauen" bezieht sich im folgenden Abschnitt
ausschließlich auf das Besitzervertrauen\!)

Ob GnuPG (und in weitere Folge auch wir) einen Schlüssel für Authentisch
befinden, also ob dessen "Key Validity" auf "trusted" gesetzt wird,
hängt von zwei Faktoren ab. Einerseits der Anzahl an Zertifizierungen
von anderen Personen. Andererseits aber auch vom Besitzervertrauen, das
wir für diese Personen jeweils festlegen. Wie genau sich diese Faktoren
auswirken ist im [GNU Privacy
Handbook](https://gnupg.org/gph/de/manual/x420.html#AEN482) beschrieben
und wurde aus diesem leicht adaptiert
übernommen<sup>[\[5\]](#quellen)</sup>:  
  
Ein Schlüssel *K* erhält den Status *gültig* (*trusted*), wenn beide der
folgenden Bedingungen erfüllt sind:

1.  Der Schlüssel *K* ist von genügend gültigen (authentischen)
    Schlüsseln unterschrieben, was hießt, dass er entweder
      - von *Ihnen persönlich* ("*Ultimate* Trust")
      - von *einem Schlüssel vollen Vertrauens* ("*Complete* Trust")
        oder
      - von *drei Schlüsseln teilweisen Vertrauens* ("*Marginal* Trust")
        unterschrieben wurde.
2.  Der Pfad unterschriebener Schlüssel, der vom Schlüssel K zurück zu
    Ihrem eigenen Schlüssel führt, besteht aus *maximal fünf
    Schritten*.  
      

Wie sehr wir dem Besitzer eines Schlüssel vertrauen, dass er andere
Schlüssel vor dem Zertifizieren gewissenhaft überprüft, legen wir im
jeweiligen *Key Properties* Fenster fest. Zu dem kommen wir über das
*Enigmail Key Management* durch *Rechtsklick/Key Properties* auf den
Schlüssel, dessen Besitzervertrauen wir festlegen möchten. Dort können
wir Fenster zum Ändern des Benutzervertrauens aufrufen:  
![](/YubiKeyWiki/images/openpgp/enigmail_trust1.png)  
Hier finden wir nun die Vertrauensstufen wieder, die schon in obigem
Algorithmus zur Festlegung des Schlüsselvertrauens vorgekommen sind. Ich
setze das Besitzervertrauen für Troye auf "Complete":  
![](/YubiKeyWiki/images/openpgp/enigmail_trust2.png)  
Das gesetzte Benutzervertrauen sehe ich nun auch im *Enigmail Key
Management*:  
![](/YubiKeyWiki/images/openpgp/enigmail_trust3.png)  
Durch dieses gegenseitige Zertifizieren und Vertrauen kann ein komplexes
"Vertrauensgebilde" entstehen, das sich "Web of Trust" nennt. Ein
konkretes Beispiel für eine solche Vertrauenskette findet sich im [GNU Privacy Handbook](https://gnupg.org/gph/de/manual/x420.html#AEN482). Hier zur Veranschaulichung nur ein kleines Beispiel:

##### Beispiel Besitzervertrauen

Angenommen Troye hat den Schlüssel von seinem Freund Tristan signiert
und hat ihn mir übermittelt. Wenn ich nun diesen Schlüssel von Tristan
importiere, wird er als authentisch angezeigt (die "Key Validity" ist
"trusted"), obwohl ich ihn nicht signiert habe und auch das
Besitzervertrauen von Tristan nicht gesetzt ist:  
![](/YubiKeyWiki/images/openpgp/gpg_mail_trust_01.png)  
Beim Schlüssel von Troye handelt es sich nach dem [obigen Algorithmus zur Festlegung der Authentizität](#besitzervertrauen-und-schlüsselauthentizität) um
einen "Schlüssel vollen Vertrauens". Wir haben nämlich das
Besitzervertrauen für Schlüsselsignaturen von Troye auf "trusted"
gesetzt. In weiterer Folge werden alle Schlüssel als Authentisch
eingestuft, die von ihm signiert wurden. Die Signatur von Troye in
Tristans Schlüssel können wir in den Schlüsseldetails sehen:  
![](/YubiKeyWiki/images/openpgp/gpg_mail_trust_02.png)  
Bekommen wir nun eine signierte Email von Tristan, wird diese Email als
authentisch eingestuft. Das erkennen wir am grünen Banner und dem Kuvert mit dem roten Siegel:

![](/YubiKeyWiki/images/openpgp/gpg_mail_trust_03.png)  
  

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

Aufgrund dieser Problematiken gibt es seit GnuPG
2.2.17<sup>[\[7\]](#quellen)</sup> die Standardeinstellung, dass beim
Herunterladen von Schlüsseln aus Schlüsselservern immer alle Signaturen
von Dritten entfernt werden. Damit geht leider die Funktionalität des
"Web of Trust" verloren. Signierte Schlüssel, die nicht über
Schlüsselserver importiert werden, lassen sich aber nach wie vor mit
ihren Signaturen importieren.  
Auch die Community rund um [Sequoia-PGP](https://sequoia-pgp.org/),
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
In Enigmail ist seit Version 2.1 (für Thunderbird 68) der Standard
Schlüsselserver keys.openpgp.org.<sup>[\[9\]](#quellen)</sup>  
Kurz zusammengefasst bedeutet das: Die Standardeinstellungen in Enigmail
und GnuPG sind in Bezug auf die Problematiken der Keyserver ausreichend
sicher. Wir empfehlen dennoch ausschließlich Schlüsselserver zu
verwenden, die eine Email-Verifizierung durchführen. (mehr dazu unter
[Konfigurationsempfehlungen](#Konfigurationsempfehlungen) Leider ist es
aber aufgrund der Standardeinstellungen nicht mehr möglich, Signaturen
fremder Schlüssel über Schlüsselserver zu
beziehen.<sup>[\[8\]](#quellen)</sup> Die Community des keys.openpgp.org
Schlüsselservers arbeitet aber bereits daran, dass Signaturen Dritter
wieder möglich werden, wie sie in ihren
[News](https://keys.openpgp.org/about/news) berichten. Eine Signatur
soll demnach nur dann über den Schlüsselserver verfügbar sein, wenn der
Schlüsselbesitzer diese attestiert (also signiert). Die
[OpenPGP-WorkingGroup](https://datatracker.ietf.org/wg/openpgp/documents/)
arbeitet dafür schon an einer [Änderung für den
RFC4880](https://gitlab.com/openpgp-wg/rfc4880bis/-/merge_requests/20/diffs).
(Stand Mai 2020)

```tip
**Sicherheitserwägung**: Wir empfehlen aus oben genannten Gründen
ausschließlich Schlüsselserver zu verwenden, welche die Email-Adresse
eines hochgeladenen Schlüssels verifizieren: \<code\>
hkps:*keys.openpgp.org, hkps:*keys.mailvelope.com,
hkps://keyserver1.pgp.com/ \</code\>  
```   

#### Schlüssel widerrufen

Für den Fall, dass der private Schlüssel kompromittiert wird, gibt es
die Möglichkeit diesen zu widerrufen. Ein Widerruf soll auch
durchgeführt werden, wenn man den eigenen Schlüssel verliert oder ihn
einfach nicht mehr nutzen möchte. Es gibt zwei Wege einen Schlüssel zu
widerrufen:

  - Über ein zuvor erstelltes Widerrufszertifikat, welches in einer
    Datei abgespeichert wird. Die Datei kann in Enigmail ganz einfach im
    *Enigmail Key Management* über *File/Import keys from file*
    importiert werden. Es ist daher empfohlen für den Fall des
    Schlüsselverlustes bereits beim Erstellen des eigenen
    OpenPGP-Schlüssels ein Widerrufszertifikat zu erstellen. Das wurde
    aber bereits in unserem Hauptartikel [OpenPGP](/YubiKeyWiki/docs/OpenPGP) beschrieben.
  - Wenn man den Hauptschlüssel noch besitzt, kann man ihn zum
    Widerrufen nutzen. Dafür navigiert man im *Enigmail Key Management*
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

Ich erstelle auch gleich einen neuen Authentifizierungs-Unterschlüssel.
Wie man Schlüssel erstellt und auf den YubiKey transferiert erklären wir
in unserem [OpenPGP](/YubiKeyWiki/docs/OpenPGP) Artikel. Das
Ergebnis kann ich gleich in den *Key Properties* von Enigmail unter dem
Tab *Structure* einsehen:  
![](/YubiKeyWiki/images/openpgp/enigmail_revoc1_new.png)  
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

#### YubiKey Management

Enigmail bietet auch ein Interface zum Verwalten von Smartcards.
Ernsthafte Konfigurationseinstellungen kann man damit allerdings nicht
vornehmen, weshalb unbedingt das GnuPG Kommandozeilentool verwendet
werden soll. In Enigmail ist es nicht möglich, selbst erstellte
Schlüssel auf den YubiKey zu transferieren. Die Generierung von
Schlüsseln auf dem YubiKey ist überdies voreingestellt nur für 2048-Bit
RSA Schlüssel möglich. Für einen schnellen Blick auf die Einstellungen
des YubiKey und das Ändern der PINs ist Enigmail aber ausreichend. Über
die Menüleiste *Enigmail/Manage SmartCard ...* öffnet sich das *OpenPGP
SmartCard Details* Fenster. Hier werden OpenPGP bezogene Informationen
über den YubiKey angezeigt:  
![](/YubiKeyWiki/images/openpgp/enigmail_smartcard1.png)  
Über *SmartCard/Edit Card Data* lassen sich in eben diesem Fenster Name,
Sprache, Geschlecht, Link zum öffentlichen Schlüssel, Login-Daten für
den Keyserver, und das "Force signature PIN"-Flag ändern.  
Über das Menü *SmartCard/Change PIN* öffnet sich ein Fenster zum Ändern
des *PIN*, *Admin PIN* und des *Unblock PIN*.

#### Konfigurationsempfehlungen

In Enigmail gibt es zwei zentrale Menüs, über die man
Konfigurationseinstellungen treffen kann. Einerseits die Einstellungen
von Enigmail selbst (*Menüleiste/Enigmail/Preferences*), andererseits
die Enigmail-bezogenen Einstellungen für jeden Mailaccount (*rechte
Maustaste auf Mailaccount/Settings/OpenPGP Security*). Beginnen wir mit
den generellen Enigmail Einstellungen unter
*Menüleiste/Enigmail/Preferences*:

  - Allgemein (Basic):
      - Die Ablaufzeit der Passphrase sollte auf 0 Minuten gestellt
        werden. Ein Merken der Passphrase würde mehr Komfort bieten,
        wenn wir keinen YubiKey hätten, da wir dann beim Signieren und
        Entschlüsseln immer die Passphrase eingeben müssten. Wir
        benötigen die Passphrase aber lediglich für den Hauptschlüssel
        (die Unterschlüssel liegen am YubiKey). Wir nutzen ihn also
        ohnehin nur selten und dann für einzelne Anwendungen (zB.: wenn
        man einen Schlüssel signieren möchte). Je kürzer das Passwort
        gecached wird desto besser.
      - Das Anzeigen der "Experten-Einstellungen" ist zu empfehlen.
  - Senden (Sending): Wir empfehlen die Standardeinstellungen zu
    verwenden.
      - Erläuterung: Zum Verschlüsseln empfehlen wir alle verwendbaren
        Schlüssel zuzulassen. Das bewahrt Einen davor, Schlüssel
        voreilig zu signieren, nur um mit dem Gegenüber verschlüsselte
        Nachrichten austauschen zu können. Das Signieren fremder
        Schlüssel darf nur nach Überprüfung des Fingerabdruckes auf
        einem zweiten Kommunikationskanal erfolgen, über den auch die
        Authentizität des Gegenüber sichergestellt ist\! Emails einfach
        so zu verschlüsseln hat dann zumindest den Sinn, dass nicht
        jeder im Internet die Email mitlesen kann, sondern nur der
        Empfänger. Der ist halt leider nicht ganz sicher jener, der er
        vorgibt zu sein.
  - Schlüsselauswahl (Key Selection):
      - Hier empfehlen wir die Kontrolle der ausgewählten Schlüssel vor
        dem Senden immer auch manuell zu überprüfen\! Vielleicht hat
        jemand einen zweiten Schlüssel für die gleiche Email Adresse.
  - Erweitert (Advanced): Standardeinstellungen belassen.
  - Schlüsselserver (Keyserver):
      - Wir empfehlen aussschließlich Schlüsselserver, die eine
        Email-Verifizierung durchführen: (Information dazu unter
        [Verteilen von Schlüsseln](#verteilen-von-schlüsseln))
      - \<code\> hkps:*keys.openpgp.org, hkps:*keys.mailvelope.com,
        hkps://keyserver1.pgp.com/ \</code\>

  
Enigmail bietet außerdem noch Einstellungen, die spezifisch für jeden
Mailaccount gesetzt werden müssen. Dafür öffnet man die zugehörigen
Accounteinstellungen und navigiert auf den Reiter *OpenPGP Security*.
Grundsätzlich geht es hier nicht unbedingt um sicherheitsrelevante
Einstellungen. Vorsicht ist nur bei Autocrypt geboten: **Autocrypt
unbedingt deaktivieren\!** Autocrypt versucht automatisiert Schlüssel
mit anderen Autocrypt-fähigen System auszutauschen. Das geschieht ganz
transparent für den Nutzer. So werden Schlüssel verwendet obwohl deren
Authentizität nicht überprüft wurde\! <sup>[\[10\]](#quellen)</sup>

### Thunderbird 78

(Stand Mai 2020)

Wie bereits im einleitenden [Absatz über Thunderbird](#thunderbird)
beschrieben, wird Enigmail aufgrund einer Änderung im Add-on Support im
neuen Thunderbird 78 nicht mehr unterstützt\! Die Entwickler von
Thunderbird arbeiten daran, die OpenPGP-Funktionalität direkt in
Thunderbird 78 zu integrieren<sup>[\[2\]](#quellen)</sup>. Bis im Juni
2020 läuft der [Thunderbird Virtual
Summit](https://wiki.mozilla.org/Thunderbird/2020_Virtual_Summit), wo
die Entwickler online Präsentationen über die aktuellen Entwicklungen
von Thunderbird halten. Zum OpenPGP Support gab es am 21. Mai 2020 eine
Präsentation von [Kai Engert](https://mozillians.org/de/u/kaie/), dem
zuständigen Entwickler für die OpenPGP Implementierung. Diese
Präsentation ist auch auf
[YouTube](https://www.youtube.com/watch?v=zwmPwcC2Ie4) abrufbar und
fasst den aktuellen Entwicklungsstand sehr gut zusammen. Im Folgenden
haben wir die wichtigsten Infos für euch zusammengefasst:

  - Aufgrund der eingeschränkten Zeit- und Personalressourcen wird der
    OpenPGP Support mithilfe einer bestehenden Bibliothek realisiert.
  - GnuPG kommt dafür nicht in Frage, aufgrund einer Lizenzproblematik
    zwischen [GPL](https://www.gnu.org/licenses/gpl-3.0.en.html) und
    [MPL](https://www.mozilla.org/en-US/MPL/2.0/).
  - Deshalb wird die [RNP](https://www.rnpgp.com/) Bibliothek unter der
    [BSD](https://github.com/rnpgp/rnp/blob/master/LICENSE.md) Lizenz
    verwendet. Diese bietet:
      - Signieren/Verifizieren
      - Ver-/Entschlüsseln
      - Arbeiten mit Schlüsseln und dem Schlüsselbund
  -  Abgesehen davon wird Code von Enigmail wiederverwendet.
  - Aufgrund des Zeitdrucks, dass Thunderbird 78 schon im Juli
    veröffentlicht werden soll, ist mit vielen Bugs zu rechnen\!
  - Die Nutzung von Smartcards wird NICHT direkt unterstützt, da RNP
    keine Smartcard Funktionalität bietet. Es ist aber geplant, dass
    innerhalb eines Jahres nach Release von Thunderbird 78 eine
    Schnittstelle zur Nutzung von GnuPG geben wird. Dafür müssen Nutzer
    selbst wieder GnuPG installieren und können dessen Smartcard
    Funktionalität über Thunderbird nutzen.
  - Gearbeitet wird mit einem Thunderbird-internen Schlüsselbund und
    nicht mehr mit dem Schlüsselbund von GnuPG.

Der aktuelle Umsetzungsstatus von OpenPGP in Thunderbird kann
[online](https://wiki.mozilla.org/Thunderbird:OpenPGP:Status) eingesehen
werden. Mit 29. Mai 2020 ist folgendes Arbeitspaket bereits auf *Done*
gesetzt: "initial preparation for supporting GnuPG smartcards for secret
key operations (decryption works, need to enable pref
mail.openpgp.allow\_external\_gnupg)".

#### Thunderbird 77.0 Beta

(Stand Mai 2020)

Derzeit gibt es schon eine
[Betaversion](https://www.thunderbird.net/en-US/thunderbird/77.0beta/releasenotes/)
die wir getestet haben. Da Menüs von Thunderbird wiederverwendet werden,
sehen viele Fenster sehr vertraut aus. Viele Komfort-Funktionen fehlen
natürlich noch, am wichtigsten für uns ist aber die fehlende
Unterstützung von Schlüsselservern und Smartcards.  
Der Reiter *Enigmail* in der Menüleiste ist natürlich nicht mehr zu
finden. Die einzige Konfigurationseinstellung findet sich derzeit in den
Einstellungen des jeweiligen Mailaccounts (*rechte Maustaste auf
Mailaccount/Settings/End-To-End Encryption*). Es handelt sich hier um
das ehemalige *S/Mime* Menü, zu dem neben der Namensänderung, auch die
OpenPGP Einstellung hinzugekommen ist. Hier kann man den gewünschten
Schlüssel für den Mailaccount auswählen und kommt auch ins
Schlüsselmanagement:
\\\\![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_menu.png)  
Das Schlüsselmanagement erreicht man aber auch über die Menüleiste
*Tools/OpenPGP Key Management...*. Dieses Fenster ist ganz vertraut, da
es sich um das gleiche Layout handelt wie schon bei Enigmail:  
![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_keymanagement.png)  
Auch die Schlüsseleigenschaften *Rechte Maustaste/Key Properties* sehen
ähnlich vertraut aus. Leider können aber noch keine Schlüssel signiert
werden\! Die Authentizität muss man daher bei jedem Schlüssel einzeln
setzen:  
![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_keyproperties.png)  
Möchte man eine Email versenden, gibt es nun den Menüpunkt *Security*,
wo man OpenPGP zur Verschlüsselung auswählen kann:  
![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_mailerstellung.png)  
Ob die Signatur von einem authentischen Schlüssel durchgeführt wurde,
wird nun mit einem Personensymbol angezeigt. Ist der Schlüssel nicht
authentisch, so sieht man ein gelbes Warndreieck. Das Briefsymbol zeigt
lediglich, dass die Signatur gültig ist. Das kleine Schloss, dass die
Nachricht verschlüsselt ist, sieht man im folgenden Bild:  
![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_mailnottrusted.png)  
Vertraut man der Signatur hingegen, sieht man einen grünen Haken beim
Personensymbol:  
![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_mailtrusted.png)  
Natürlich sind die Funktionalitäten noch nicht ganz ausgereift.
Beispielsweise gibt es keine klare Fehlermeldung, wenn man dem
Empfängerschlüssel nicht für authentisch befindet. Möchte ich eine
Email zu diesem Empfänger senden, bekomme ich nur folgendes Feedback:  
![](/YubiKeyWiki/images/openpgp/thunderbird_beta_e2e_keynottrusted.png)  
  

#### Fazit

(Stand Mai 2020)

Der OpenPGP Support funktioniert derzeit noch nicht hinreichend. Die
folgenden zwei Funktionalitäten sind noch nicht implementiert. Sie sind
aber essenziell um überhaupt mit OpenPGP und dem YubiKey arbeiten zu
können:

  - Signieren von Schlüsseln
  - Smartcard Support

Folgende Komfort-Funktionalität sollte außerdem unbedingt noch ergänzt
werden:

  - Verwendung von Schlüsselservern

Die drei oben genannten Funktionalitäten finden sich auf der
[ToDo-Liste](https://wiki.mozilla.org/Thunderbird:OpenPGP:Status) der
Entwickler. Es bleibt zu hoffen, dass die OpenPGP Implementierung
bereits vor Auslauf des Supports von Thunderbird 68 und Enigmail im
Herbst 2020 die gewünschten Funktionalitäten bieten.  

#### Weitere Infos

  - [Status](https://wiki.mozilla.org/Thunderbird:OpenPGP:Status) der
    aktuellen OpenPGP Integration im Mozilla Wiki.
  - [OpenPGP Hauptseite](https://wiki.mozilla.org/Thunderbird:OpenPGP)
    von Mozilla Thunderbird.
  - [Ursprüngliche
    Ankündigung](https://wiki.mozilla.org/Thunderbird:OpenPGP:2020) vom
    Oktober 2019.
  - [tb-planning](https://mail.mozilla.org/listinfo/tb-planning)
    Mailingliste, wo die Entwickler Designentscheidungen besprechen.
  - [Mailarchiv](https://mail.mozilla.org/pipermail/tb-planning/) der
    tb-planning Mailingliste.

  
  
## FairEmail & OpenKeychain
![](/YubiKeyWiki/images/openpgp/0_fairemail_playstore.jpg)  
FairEmail ist ein open-source Email Client für Android-Geräte. Dieser
unterstützt unter anderem die Ver- und Entschlüsselung von Emails
mittels OpenPGP und S/MIME. Nach der Einrichtungsanleitung der App wird
werden wir auch die Verwendung mit dem YubiKey erklären.

### Installation und generelle Einrichtung

Der FairEmail-Client kann gratis über denn Google Playstore bezogen
werden. Die Einrichtung ist sehr simpel und wird hier in wenigen
Schritten gezeigt.  
Beim ersten Start wird man mit einer Einrichtungsseite begrüßt.  
![](/YubiKeyWiki/images/openpgp/1_fairemail_schnelleinrichtung.jpg)  
Hier empfielt es sich die Schnelleinrichtung zu verwenden. Im
Optimalfall hat man dadurch in nur einem Schritt ein Email-Konto
hinzugefügt:  
![](/YubiKeyWiki/images/openpgp/2_fairemail_einrichtung.jpg)  
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
![](/YubiKeyWiki/images/openpgp/4_openkeychain_playstore.jpg)  
Diese übernimmt die Kommunikation mit dem YubiKey und ermöglicht das
Verschlüsseln von Dateien und der Email-Kommunikation. Nach der
Installation von OpenKeychain trägt FairEmail automatisch im Abschnitt
*OpenPGP-Anbieter* den Schlüsselbund von OpenKeychain ein. Die Option
*Autocrypt verwenden* sollte auf alle Fälle deaktiviert werden\! Infos
dazu siehe auch in den Thunderbird [Konfigurationsempfehlungen](#konfigurationsempfehlungen)  
![](/YubiKeyWiki/images/openpgp/3_fairemail_pgp_einstellungen.jpg)  
Die App kann man natürlich wieder über dem Playstore beziehen. Beim
Start der App wird gleich ein Setup Bildschirm angezeigt. Natürlich
müssen sich erst OpenPGP Schlüssel auf dem Gerät befinden, bevor man
mit ihnen arbeiten kann. Man kann Schlüssel am Smartphone erzeugen, aus
einer Datei importieren oder die Schlüssel auf einem Security Token
nutzen. Letzteres wird für den YubiKey benötigt.  
![](/YubiKeyWiki/images/openpgp/5_openkeychain_start.jpg)  
Im nächsten Schritt wird man aufgefordert, den YubiKey an das Smartphone
zu halten, da die App die NFC-Funktion verwendet.  
![](/YubiKeyWiki/images/openpgp/6_openkeychain_karte_anhalten.jpg)  
Wenn der YubiKey erkannt wird, wird anhand der [hinterlegten
URL](/yubikey4hk/funktionen/openpgp#metadaten_auf_den_yubikey_laden) der
zugehörige öffentlichen Schlüssel importiert. Dies muss noch mit dem
grünen Button *Import* bestätigt werden.  
![](/YubiKeyWiki/images/openpgp/7_openkeychain_key_hinzufuegen.jpg){: width="200px"}  
Der Schlüssel wird nun importiert:  
![](/YubiKeyWiki/images/openpgp/8_openkeychain_key_hinzugefuegt.jpg){: width="200px"}  
Wenn man nun auf *Schlüssel ansehen* klickt, kann man den
Schlüsselstatus überprüfen. Hier sollte stehen, das der Schlüssel
*stripped* ist und zum Signieren und Verschlüsseln geeignet ist.
*Stripped* heißt, dass der Hauptschlüssel fehlt. Dieser befindet sich
nicht am YubiKey, sondern nur die drei Unterschlüssel. Das hat den
Nachteil, dass man fremde öffentliche Schlüssel nicht signieren kann.  
![](/YubiKeyWiki/images/openpgp/9_openkeychain_keystatus.jpg)  
Die generelle Einrichtung der App ist nun abgeschlossen. Nun müssen noch
die öffentlichen Schlüssel der Kommunikationspartner hinzugefügt werden.

### Fremde Schlüssel importieren

Es gibt drei Möglichkeiten einen fremden Schlüssel hinzuzufügen:

  - QR-Code einscannen
  - Schlüssel suchen
  - Aus Datei importieren

![](/YubiKeyWiki/images/openpgp/10_openkeychain_fremden_schluessel_import.jpg){: width="200px"}   
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
![](/YubiKeyWiki/images/openpgp/11_openkeychain_key_suche.jpg)  
Bevor man jedoch Schlüssel finden kann, muss ein Schlüsselserver
eingestellt werden. Dafür navigiert man in den Einstellungen, die oben
rechts mit den drei vertikalen Punkten aufrufbar sind. Hier findet man
folgendes Menü vor:  
![](/YubiKeyWiki/images/openpgp/12_openkeychain_keyserver_menu.jpg)  
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
![](/YubiKeyWiki/images/openpgp/13_openkeychain_keyserver_settings.jpg)  
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
![](/YubiKeyWiki/images/openpgp/14_fairemail_email_senden.jpg)  
Wenn man eine durch OpenPGP geschützte Email versenden möchte, muss man
im oberen Bereich das Schloss-Symbol antippt, bis es grün wird. Dies ist
im vorherigen Screenshot rot umrandet. Das kann auch beim Sende-Symbol
kontrolliert werden, indem darunter *Verschlüsseln* steht. Dieses
"Verschlüsseln" sagt aber nichts darüber aus, ob verschlüsselt und/oder
signiert wird, sondern lediglich, dass OpenPGP zum Einsatz kommt.  
Nun muss man noch einen Empfänger eintragen und einen netten Text
schreiben und man kann die Email versenden. Vor dem Senden, werden zur
Kontrolle noch einmal die Einstellungen ausgegeben::  
![](/YubiKeyWiki/images/openpgp/15_fairemail_email_settings.jpg)  
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
<sup>\[2\]</sup> Ryan Sipes, *Thunderbird, Enigmail and OpenPGP*,
(2019), Letzter Zugriff 12.05.2020, \[Online\], URL:
<https://blog.thunderbird.net/2019/10/thunderbird-enigmail-and-openpgp/>  
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
