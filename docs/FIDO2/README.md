# FIDO2

{% include acronyms.md %}

Passwörter verwenden wir im unseren Alltag seit vielen Jahren. Ob in der
Arbeit oder im Web beim Portal der Bank des Vertrauens, statische
Passwörter werden oft noch zur Authentifizierung verwendet. Dabei gibt
es schon Verfahren, die ein Mehr an Sicherheit und Nutzbarkeit bieten.
Man bewegt sich vom statischen Passwort weg. Nicht nur wegen den
bekannten Schwachstellen des Verfahrens, wie die Anfälligkeit für
Man-in-the-Middle Attacken. Ein Problem ist auch die Tatsache, dass sich
Benutzer selbstständig um das Merken bzw. sichere Verwahren ihrer
Passwörter kümmern müssen. Um die Sicherheit zu erhöhen, verwendet man
beispielsweise OTP-Verfahren als zusätzlichen Faktor. Um die Nutzbarkeit
zu erhöhen gibt es die Möglichkeit der passwortlosen Authentifizierung.
Diese wird beispielsweise mit dem neuen FIDO2 Standard ermöglicht. In
diesem Wiki-Eintrag soll ein Überblick über die FIDO Alliance und deren
Standards zur Authentifizierung gegeben werden.

## Was ist FIDO?

Die FIDO Alliance arbeitet an der Entwicklung von Protokollen zur
Authentifizierung. Das 2012 gegründete Bündnis wurde von PayPal, Lenovo,
Nok Nok Labs, Validity Sensors, Infineon, und Agnitio gegründet, mit dem
Ziel eine Methode zur passwortlosen Authentifizierung zu entwickeln. Ein
Jahr später kamen Google, Yubico und NXP hinzu. Im Jahr 2014 war es dann
soweit: Das erste FIDO-Protokoll(Version 1.0) wurde veröffentlicht.
<sup>[\[1\]](#quellen)</sup>  
Michael Barrett, Präsident der FIDO-Organisation, sieht die
Veröffentlichung von FIDO als Meilenstein, ab der die alte Welt von
Passwörtern und PINs langsam ausstirbt.<sup>[\[2\]](#quellen)</sup>  
Das Protokoll besteht aus zwei Komponenten: FIDO Universal
Authentication Framework(FIDO UAF) und FIDO Universal 2nd Factor(FIDO
U2F)  
Das Ziel des UAF-Frameworks ist, klassische Passwörter durch eine
passwortlose Methode zu ersetzen. Dazu wird ein Gerät (z.B.: Smartphone)
bei einem Service registriert. Die anschließende Authentifizierung kann
dann beispielsweise per Fingerabdruck, Gesichtserkennung oder auch durch
Wischen am Bildschirm durchgeführt werden. Dafür greift der Standard auf
Authentifizierungsmethoden der jeweiligen Systeme zurück.
<sup>[\[1\]](#quellen)[\[3\]](#quellen)</sup>  
Für uns ist das FIDO U2F Protokoll von Interesse. Dieses wird vom
YubiKey unterstützt und soll im Folgenden näher erklärt werden.

### FIDO U2F / CTAP1

FIDO U2F ermöglicht das Verwenden von externen U2F-Geräten zur
Authentifizierung als zweiten Faktor über USB, NFC oder BLE. So kann
beispielsweise der YubiKey bei einer Authentifizierung am Mobiltelefon
über NFC oder am PC über die USB-Schnittstelle genutzt werden. Mit der
Veröffnetlichung von [FIDO2](#FIDO2) wurde FIDO U2F in CTAP1 umbenannt
und kann synonym verwendet werden. Resource-Provider (z.B. Websites)
können mithilfe von U2F ihre bestehende Login-Infrastruktur um einen
starken zweiten Faktor erweitern. Dazu wird der
Authentifizierungsvorgang, abgesehen von Nutzername und Passwort, mit
einem U2F-fähigen Gerät erweitert. Dadurch kann auch die Verwendung
kurzer Passwörter und PINs ermöglicht werden, die für Nutzer leichter zu
merken sind und durch die Verwendung von U2F trotzdem eine hohe
Sicherheit bieten.<sup>[\[4\]](#quellen)</sup>  
Doch nun stellt sich die Frage, wie dieses Protokoll im Hintergrund
funktioniert. U2F baut auf einem Challenge-Response-Verfahren mit
Public-Key-Kryptographie auf. Dabei generiert der Server eine Challenge
und sendet diese an den Client. Der Client wiederrum leitet diese an den
YubiKey weiter. Der YubiKey wartet nun auf den Benutzer, damit dieser
auf den Kontakt drückt und die Authentifizierung fortgeführt werden
kann. Anschließend wird die Challenge mit dem zum Service gehörigen
privaten Schlüssel vom YubiKey signiert und an den Server
zurückgesendet. Der Server hat den passenden öffentlichen Schlüssel
gespeichert und kann somit die Signatur verifizieren. Das ist der sehr
vereinfachte Ablauf des Authentifzierungsvorgangs von U2F und ist hier
schematisch in einem Bild dargestellt.
<sup>[\[5\]](#quellen)[\[6\]](#quellen)</sup>  
![U2F Schematic](/YubiKeyWiki/images/fido2/u2f_schematic.png)  
Bevor wir auf den Ablauf bei der Authentizierung genauer eingehen,
werden wir die Schlüsselerzeugung bzw. den Registrierungsvorgang
erklären.

#### Registrierung

Für den folgenden Abschnitt wurde die Yubico-Developers-Seite als Quelle
verwendet.<sup>[\[7\]](#quellen)</sup>  
Bei einer Registrierung erstellt der YubiKey ein neues
ECC-Schlüsselpaar. Also gibt es für jeden Service bzw. auch für jeden
Account pro Service ein eigenes Schlüsselpaar.

Der private Schlüssel wird mit ein paar Metadaten nun verschlüsselt und
integritätsgesichert mittels Authenticated Encryption. Dies erfolgt mit
AES-256 im CCM-Modus((Counter und CBC-MAC(KGL lässt grüßen :D) )). Dazu
wird ein Hauptschlüssel verwendet, der vom YubiKey beim Initialisieren
der FIDO-Anwendung erzeugt wird. Dieser Schlüssel kann neu erzeugt
werden, wenn ein [Reset der FIDO-Anwendung](#einstellungen-am-yubikey) durchgeführt wird. Das
invalidiert jede, zu diesem Zeitpunkt, bestehende Registrierung.  
Die verschlüsselten Daten sind nun der Keyhandle, der dem Server
geschickt wird\! Bei einer Authentifizierung sendet ein Server den
gespeicherten Keyhandle zurück. Diesen kann der YubiKey mit seinem
Hauptschlüssel entschlüsseln und erhält unter anderem den privaten
Schlüssel zurück, mit dem das Challenge-Response Verfahren abgewickelt
werden kann\! Aufgrund der Authenticated-Encryption kann auch
verifiziert werden, dass der Schlüssel nicht verändert wurde. Der Server
kann dann die Signatur anhand des öffentlichen Schlüssels prüfen. Diesen
erhält er auch bei der Registrierung.  
Diese Vorgehensweise hat nun den Vorteil, dass der YubiKey nur seinen
Hauptschlüssel speichern muss und sich somit theoretisch unendlich viele
Services registrieren lassen.<sup>[\[7\]](#quellen)</sup>  

#### Authentifizierung

Nun wird ein genauerer Blick auf den Ablauf des
FIDO-Authentifzierungsvorgangs geworfen. Im nächsten Bild werden die
Inhalte der einzelnen Übertragungen genauer aufgeschlüsselt:
![U2F Ablauf](/YubiKeyWiki/images/fido2/u2f_ablauf.png)  
Begonnen wird auf der Serverseite. Hier sendet die Relying Party, also
ein Server bei dem ich mich anmelden möchte, eine *Challenge*, ein
*Handle* und eine *AppID*. Die *Challenge* ist ein zufälliger Wert der
signiert zurückgesendet werden soll. Die *AppID* ist ein einzigartiger
Wert des Services, um den *Handle* auf diesen einen Service zu
beschränken.  
Der Client leitet alles weiter und fügt weitere Informationen hinzu.
Dazu zählt der *origin* und die *channel id*. Im *origin*-Feld steht die
URI der Relying Party. Dies beugt Phishing vor (die URI wäre sonst eine
andere). Die *channel id* beinhaltet die ID des TLS Channels und
verhindert MitM-Angriffe, da bei einem Angriff eine andere Channel ID
verwendet wird. Diese Werte werden später signiert und der Relying Party
präsentiert, dass dieser auch sichergehen kann, dass kein Angriff
stattgefunden hat.  
Der YubiKey empfängt nun diese Werte, extrahiert aus dem Handle den
privaten Schlüssel und signiert alle Werte, die er bekommen hat
inklusive einem Zähler, den er um eins erhöht.  
Die Signatur, der Zählerwert und die anderen Werte, wie *Challenge*,
*origin*, *channel id* werden zurück an die Relying Party versendet.  
Der Server überprüft nun die Signatur anhand des öffentlichen
Schlüssels, den er seit der Registrierung gespeichert hat und
verfiziert die Felder *origin, channel id* und *counter*. Wenn
erfolgreich verifiziert wurde, wird der Client
angemeldet.<sup>[\[5\]](#quellen)</sup>  

### FIDO2

Die Fido-Alliance arbeitete an ihrem Protokoll weiter. Im Februar 2016
reicht die Alliance die FIDO2 2.0 Web API beim World Wide Web
Consortium(W3C) ein, mit der Absicht, dass FIDO2 ein Standard auf allen
Web Browsern wird. Im April 2018 wurde FIDO2 offiziell als Standard
empfohlen. Das Protokoll funktioniert in Kombination mit dem neuen
Web-Authenticaiton-Standard (WebAuthn) von W3C. Während es sich bei
WebAuthn um die Standardisierung des Clients (also des Webbrowsers)
handelt, wird das von FIDO entwickelte CTAP-Protokoll für die
Kommunikation zwischen Webbrowser und Authenticator (also z.B. dem
YubiKey) verwendet. Marktführende Webbrowser wie Google Chrome, Mozilla
Firefox, Safari von Apple, oder Microsoft Edge haben diese Standards
bereits implementiert.<sup>[\[1\]](#quellen)</sup>  
FIDO2 unterstützt die U2F-Anwendung und ermöglicht fortan die Nutzung
von FIDO2 als Single-Faktor-Authentifzierung. Das heißt, man kann sich
ohne Passwort bei Online-Services anmelden. Dazu wird nun das neue CTAP2
Protokoll genutzt, das sowohl Zwei- als auch
Single-Factor-Authentifizierung mittels Authenticator ermöglicht.
Natürlich unterstützen FIDO2 bzw. WebAuthn noch die älteren
Security-Devices, die nur U2F verwenden können. Das U2F-Protokoll wurde
in CTAP1 unbenannt. Beide Begriffe können synonym verwendet
werden.<sup>[\[8\]](#quellen)</sup>  
Um die verschiedenen Protokolle, die in FIDO2 verwendet werden,
einordnen zu können, soll folgendes Bild helfen:
![FIDO2 Protocol Stack](/YubiKeyWiki/images/fido2/fido2_protocol_stack.png)

Hier erkennt man die Rückwärts-Kompatibilität, nämlich dass CTAP1/U2F
immer noch unterstützt wird. Dazu hat die FIDO-Alliance CTAP2
hinzugefügt, das unter anderem die Single-Faktor-Authentifzierung
ermöglicht. Die Kommunikation zwischen Browser bzw. Client und dem
Server übernimmt der WebAuthn-Standard. Das hat den Effekt, dass eine
einheitliche Schnittstelle zwischen Browser und Server entsteht,
unabhängig vom darunterliegenden Authenticator des Clients.
Authenticator können zum Beispiel der YubiKey, ein SmartPhone oder auch
Windows Hello sein.<sup>[\[9\]](#quellen)</sup>  
**Wie funktioniert nun die Anmeldung und Registrierung bei FIDO2? Was
hat sich geändert?**  
FIDO2 ermöglicht nun Single-Faktor-Authentifizierung und "Resident
Keys". Das heißt, dass erstellte Schlüsselpaare am Authenticator
(YubiKey) generiert werden und die private Schlüssel diesen nie verlässt
(auch nicht verschlüsselt wie bei U2F). Um die Sicherheit zusätzlich zu
erhöhen, gibt es neben der Nutzeranwesenheitsbestätigung (YubiKey
berühren), die Möglichkeit der Authentifizierung des Nutzers (Eingabe
eines FIDO2 PIN, der durch den YubiKey abgefragt wird). Der Vorteil bei
einem Login-Vorgang ist nun, dass man neben dem Benutzernamen lediglich
den Authenticator (YubiKey) benötigt. Man ersetzt also das Passwort
durch den Authenticator und erhält somit verbesserte Sicherheit.  
Der private Schlüssel muss nun aber, wenn die vorherig genannte
Anmeldemethode verwendet wird, auf dem Gerät gespeichert werden und
liegt nicht mehr in verschlüsselter Form auf dem Server. Der YubiKey
kann 25 verschiedene Schlüssel speichern.<sup>[\[12\]](#quellen)</sup>
Man ist jetzt also begrenzt\!  
Das Verfahren wird im folgenden Bild zusammengefasst:  
![FIDO2 Ablauf](/YubiKeyWiki/images/fido2/fido2_ablauf.png)  
Im Falle, dass man FIDO als zweiten Faktor, neben dem statischen
Passwort verwendet, wird wie vorher erklärt auf das CTAP1/U2F-Protokoll
zurückgegriffen. Hierbei werden wieder non-resident Schlüssel vewendet.
Dazu wird kein Speicherplatz am YubiKey benötigt.
<sup>[\[8\]](#quellen)</sup>

Wenn man sich den Registrierungs- bzw. Authentifikationsablauf genau
ansehen will, können wir folgende
[Seite](https://webauthn.singularkey.com/) empfehlen.

## Einstellungen am YubiKey

Der YubiKey-Manager bietet wieder Einstellungsmöglichkeiten für FIDO.
Diese sind hauptsächlich zum Verwalten der Schlüssel zuständig.  
Der Prefix für die FIDO-Befehle ist immer *ykman fido \[COMMAND\]*.

Um sich Informationen über die FIDO-Applikation auszugeben, verwendet
man den *info*-Befehl. Hier sieht man zum Beispiel, ob der PIN für die
FIDO2-Applikation des YubiKeys gesetzt ist. Man kann diesen zusätzlich
setzen. Der PIN muss dann als weiterer Faktor bei einer
Authentifizierung eingegeben werden. Der PIN kann mit dem Befehl
*set-pin* gesetzt werden. Der Befehl zum Ändern des PINs wäre:

``` bash
ykman fido set-pin --pin 123456 --new-pin 654321
```

Man hat acht Versuche den PIN bei einer Verwendung korrekt einzugeben\!
Nach diesen wird die FIDO-Applikation gesperrt und es muss ein Reset
gemacht werden\! (Das Resultiert in einem Verlust aller gespeicherten
FIDO2 Schlüssel. Zusätzlich kann man auch die U2F-Schlüssel, die auf den
Servern gespeichert werden nicht mehr entschlüsseln, da ein neuer
Hauptschlüssel erstellt wird\!\!)  

```tip
**Sicherheitserwägung**: Das BSI empfiehlt eine PIN-Retry Beschränkung
auf 3 Versuche bei einer PIN-Länge von 6 Ziffern.[\[10, Tabelle 6.2\]](#quellen) Die PIN-Retries für FIDO sind am YubiKey
unveränderlich auf 8 Versuche gesetzt. Ein 6-stelliger, zufällig
gewählter PIN ist unserer Meinung nach aber ausreichend, vor allem wenn
man bei Verlust des YubiKey, diesen unmittelbar bei allen Services als
Authentifizierungsmethode entfernt.
```

Mit dem *list*-Befehl werden Informationen zu den registrieren Services
angezeigt:

``` bash
ykman fido list
Enter your PIN:
max.muster@mann.at (login.microsoft.com)
```

Hier sieht man zum Beispiel, dass ein Eintrag für den Microsoft-Login
besteht. Dieser ist einer der wenigen Services, der FIDO2 bereits
unterstützt. Bei CTAP1/U2F bzw. non-resident Schlüssel sind keine
Einträge vorhanden. Nun gib es noch den *delete*- und den
*reset*-Befehl. Der *delete* ermöglicht das Löschen eines gespeicherten
Credentials, da man ja mit FIDO2 auf 25 Residential Keys begrenzt ist.
Der zuvor angezeigte Microsoft-Eintrag kann mit folgenden Befehl
gelöscht werden, um ein Beispiel zu geben:

``` bash
ykman fido delete login.microsoft.com
Enter your PIN:
Delete credential max.muster@mann.at (login.microsoft.com)? [y/N]:
```

Der *reset*-Befehl löscht alle Credentials inklusive den
U2F-Einstellungen und dessen MasterKey. Der Befehl lautet dazu:

``` bash
ykman fido reset
```

Mehr Einstellungen gibt es dazu nicht. In der graphischen Lösung des
Managers lässt sich der PIN ändern und ein Reset durchführen. Alle
anderen Befehle sind nicht implementiert. <sup>[\[11\]](#quellen)</sup>

## Mögliche Einsatzgebiete

Die Einsätze der FIDO-Applikation liegen klar im Webbereich, da FIDO
wesentliche Verbesserungen zu den weit verbreiteten statischen
Passwörtern bringt. Es werden beispielsweise Attacken wie MitM
(TLS-Channel ID) oder Replay-Attacken (Counter bzw. Challenge)
verhindert. Auch das Vorhandensein des WebAuthn-Standards erleichtert
die Implementierung von FIDO für Webbrowser, Clients und Server.

Im Bereich des Systemlogins mit FIDO gib es auch schon eine Anwendung
für Linux, die in unserem [Systemlogin Kapitel](/YubiKeyWiki/docs/FIDO2/systemlogin)
gezeigt wird. Für den Webbereich haben wir auch eine [Anleitung](/YubiKeyWiki/docs/FIDO2/webanmeldung) erstellt.

```tip
**Sicherheitserwägung**: Eine Empfehlung ist, dass man immer zwei
YubiKeys bei einem Service registriert (falls man einen Zweiten
besitzt). Bei Verlust eines YubiKeys kann man dann immer noch den
zweiten YubiKey nutzen und muss nicht den Recovery-Prozess des
jeweiligen Services durchführen. Dies würden dann einige Zeit in
Anspruch nehmen, da der Prozess bei jedem angemeldeten Service, wo der
verlorene YubiKey registriert ist, durchgeführt werden muss. Außerdem empfiehlt es sich, alle alternativen Anmeldemöglichkeiten zu
deaktivieren (wenn man mehrere YubiKeys registriert hat).
```


## Quellen

\[1\] FIDO Alliance, *History of FIDO Alliance*, Letzter Zugriff
22.06.2020, \[Online\], URL:
<https://fidoalliance.org/overview/history/>
\[2\] FIDO Alliance, *FIDO 1.0 Specifications are Published and Final
Preparing for Broad Industry Adoption of Strong Authentication in 2015*,
Letzter Zugriff 22.06.2020, \[Online\], URL:
<https://fidoalliance.org/fido-1-0-specifications-published-and-final/> 
\[3\] Swaroop Sham, *The Ultimate Guide to FIDO2 and WebAuthn
Terminology*, Letzter Zugriff 22.06.2020, \[Online\], URL:
<https://www.okta.com/blog/2019/04/the-ultimate-guide-to-fido2-and-webauthn-terminology/>  
\[4\] FIDO Alliance, *Specifications Overview*, Letzter Zugriff
22.06.2020, \[Online\], URL: <https://fidoalliance.org/specifications/>  
\[5\] Yubico, *U2F Technical Overview*, Letzter Zugriff 22.06.2020,
\[Online\], URL:
<https://developers.yubico.com/U2F/Protocol\_details/Overview.html>  
\[6\] FIDO Alliance, *Universal 2nd Factor (U2F) Overview*, Letzter
Zugriff 22.06.2020, \[Online\], URL:
<https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html\#authentication-generating-a-signature>  
\[7\] Yubico, *Key generation*, Letzter Zugriff 22.06.2020, \[Online\],
URL:
<https://developers.yubico.com/U2F/Protocol\_details/Key\_generation.html>  
\[8\] Ionos, *FIDO2: Der neue Standard für den sicheren Web-Log-in*,
Letzter Zugriff 22.06.2020, \[Online\], URL:
<https://www.ionos.at/digitalguide/server/sicherheit/was-ist-fido2/>  
\[9\] Yubico, *WebAuthn Introduction*, Letzter Zugriff 22.06.2020,
\[Online\], URL: <https://developers.yubico.com/WebAuthn/>  
\[10\] *BSI TR-02102-1 "Kryptographische Verfahren: Empfehlungen und
Schlüssellängen"*, BSI Technische Richtlinie, Version 2020-01, Stand
24.03.2020, Letzter Zugriff 07.05.2020 \[Online\], URL:
<https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf>  
\[11\] Yubico, *YubiKey Manager CLI User Guide*, Letzter Zugriff
22.06.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide>  
\[12\] Yubico, *YubiKey 5 Series Technical Manual*, Letzter Zugriff
22.06.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual#FIDO2gux61i>
