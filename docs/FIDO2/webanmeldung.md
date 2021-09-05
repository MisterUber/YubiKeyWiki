# Webanmeldung FIDO2 und U2F

{% include acronyms.md %}

Die Nutzung des vollen Funktionsumfanges von FIDO2 ist leider bei fast
keiner Website möglich. Auch wenn man online im
[Works-With-YubiKey-Katalog](https://www.yubico.com/works-with-yubikey/catalog/#protocol=fido2&usecase=all&key=all)
nach *FIDO2* oder *WebAuthn* sucht werden Seiten und Anbieter
aufgelistet, die fast ausschließlich die Verwendung eines Authenticator
als zweiten Faktor ermöglichen. Die Ersetzung des Passworts durch einen
Authenticator (z.B. den YubiKey) ist bei Websites derzeit noch nicht
verbreitet. Diese fehlende Unterstützung liegt bei den
Website-Betreibern, denn WebAuthn ist bei neueren Versionen von Chrome,
Edge, Firefox und Safari bereits integriert. Viele Websiten unterstützen
aber die FIDO U2F Funktionalität.

In diesem Artikel zweigen wir exemplarisch die Verwendung der

  - Zweifaktor-Authentifizierung (FIDO U2F) für
      - [GitHub](#github)
      - [Google](#google-account)
  - und die passwortlose Authentifizierung (FIDO2) für den
      - [Microsoft Account](#microsoft-account)

## GitHub

Bei GitHub lässt sich ein SecurityKey nicht ohne weiteres hinzufügen.
Zuerst muss man Zweifaktorautzentifizierung mittels Authenticator (also
TOTP) aktivieren. Das liegt daran, dass TOTP nicht von der
WebAuthn-Unterstützung des Browsers abhängt. Bei TOTP muss man nur den
kurzen Einmalpin, der auf dem Authenticator (z.B.: Yubico Authenticator
oder Google Authenticator) erzeugt wird, eingeben. GitHub möchte dadurch
sicherstellen, dass sich die Nutzer nicht selber von ihrem Account
aussperren für den Fall, dass sie nur einen SecurityKey mit U2F
hinterlegt haben. Arbeitet man einmal auf einem alten Webbrowser, kann
man sich dort nicht einloggen.

### Registrierung

1\. Wenn man online mit einem beliebigem Browser bei GitHub eingeloggt
ist, kann man über *Settings/Security/Enable two-factor authentication*
in einem ersten Schritt einen Authenticator (TOTP) hinzufügen. Da kann
man bereits den YubiKey verwenden und mit dem Yubico Authenticator
arbeiten. Wir wählen also *Set up using an app* aus. Zuerst bekommen wir
Recovery-Codes angezeigt. Möchte man sich bei GitHub einloggen und hat
den Authenticator nicht zur Hand, kann man zusätzlich zu Nutzername und
Passwort einen dieser Codes eingeben. Jeder dieser Codes ist nur einmal
verwendbar. Man kann sich auch jederzeit neue generieren lassen, dann
werden die Alten ungültig. Diese Codes speichert man sich am besten in
einem Passwortmanager, oder als verschlüsseltes File (z.B. mit GnuPG
verschlüsselt) auf einem externen Datenträger ab.  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_01_recov_codes.png)  
  
2\. Jetzt bekommen wir einen QR-Code angezeigt, den wir mit der
Authenticator-App abfotografieren können. In diesem Code befindet sich
der geheime Schlüssel, der für die Berechnungen der Einmalpins benötigt
wird:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_01_scan_auth.png)  
Hier kann man mit einem beliebigen Authenticator die Registrierung
vornehmen. Ich nehme die Yubico Authenticator-Anwendung am PC, öffne
diese und füge einen neuen Account links oben über das "+"-Symbol hinzu.
Dann gebe ich einen Aussteller und einen Account-Namen ein. Bevor ich
auf *add* drücke, stelle ich sicher, dass der QR-Code von GitHub auf
meinem Bildschirm sichtbar ist.  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_03_scan_yubiauth.png)  
Die Registrierung wäre damit eigentlich schon abgeschlossen. GitHub
verlangt aber gleich eine Authentifizierung (also Generierung und
Eingabe eines TOTP). Dazu drücke ich beim Yubico Authenticator doppelt
auf den Eintrag und lasse mir so (nach Berührung des eingesteckten
Yubikeys) ein TOTP erzeugen. Diesen Code gebe ich dann bei GitHub unter
der Anzeige des QR-Codes ein.  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_04_get_totp.png)  
  
3\. Zweifaktor-Authentifizierung ist ab nun über den Authenticator
möglich, ganz ohne sich auf Funktionalitäten des Browsers verlassen zu
müssen. Leider muss man aber immer noch einen TOTP-Code vom
Authenticator erzeugen lassen und diesen eintippen. Etwas mehr Komfort
bietet jetzt das Hinzufügen eines SecurityKeys beim GitHub Account, um
FIDO U2F zu nutzen. Das geht unter *Settings/Security/Security
keys/Add/Register new security key*. Hier kann ich den Namen meines
Security-Keys eingeben. Der Name ist nur zur Unterscheidung mehrerer
Keys notwendig, um nicht aus Versehen einen falschen wieder zu
entfernen. Hat man mehrere gleiche Modelle, empfiehlt sich bei YubiKeys
beispielsweise die Eingabe der letzten drei Stellen der Seriennummer.
Ich verwende hier einfach die Kennung "YK5NFC":  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_05_add_seckey.png)  
Nach einem Druck auf *Add* beginnt die Kommunikation mit dem YubiKey und
man wird aufgefordert, durch einen Druck auf den YubiKey die
Registrierung zu bestätigen. Was genau hier angezeigt wird ist vom
Browser und dem Betriebssystem abhängig:

#### Firefox auf Linux

Linux unterstützt FIDO2 nicht mit den normalen Bordmitteln, da muss man
schon selber entsprechende Pakete der Distributionen installieren. Das
ist aber überhaupt kein Problem und wird vom WebAuthn Standard auch
bedacht: Wenn das Betriebssystem keinen Dialog oder keine FIDO2-fähigen
Authenticator-Schnittstelle anbietet, so übernimmt die Kommunikation der
Browser. Man sieht im nachstehenden Bild den Dialog, den Firefox uns
anzeigt. Im Hintergrund kommuniziert Firefox über die USB-Schnittelle
direkt mit dem YubiKey.  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_10_firefox_kali.png)  
Sofort nachdem diese Nachricht angezeigt wird, blinkt der YubiKey und
durch eine Berührung des Goldkontaktes ist der YubiKey bei GitHub
registriert.

#### Windows mit aktiviertem Pin

Windows hat FIDO2 (also das CTAP Protokoll) bereits integriert, weshalb
sich auch ein Dialog vom Betriebssystem öffnet. Bei mir am Windows10
Rechner, habe ich zusätzlich den Windows-Hello-PIN aktiviert. Das heißt
ich logge mich auf meinem PC nicht mit meinem Microsoft-Account-Passwort
ein, sondern mit einem PIN, den ich für das System spezifisch gesetzt
habe. Man könnte auch Windows-Hello-Fingerprint oder Windows-Hello-Face
aktiviert haben, wenn man mit einem Laptop arbeitet. All das sind
"Authenticator" im Sinne von WebAuthn und können beim "Hinzufügen von
SecurityKeys" verwendet werden. Wenn ich also einen SecurityKey bei
GitHub hinzufügen möchte, meldet sich zuerst des Setup-Fenster vom
Winows-Hello-PIN.

![]({{ site.baseurl }}{{ page.dir }}img/fido_git_06_win_pin.png)

Nachdem ich aber den YubiKey als Authenticator verwenden möchte, drücke
ich hier auf *Cancel*.  
Als nächstes öffnet sich der Dialog mit dem *Security key setup*. Da
drücke ich jetzt auf *OK* und registriere YubiKey durch Druck auf den
Goldkontakt bei GitHub hinzu.

![]({{ site.baseurl }}{{ page.dir }}img/fido_git_13_chrome_win.png)  

#### Google Chrome

Unterstützt das Betriebssystem FIDO2 nicht, so öffnet sich bei Google
Chrome folgende Anzeige:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_12_chrome.png)  
  

### Authentifizierung

Hat man den YubiKey jetzt registriert, kann man sich beim Einloggen auf
GitHub (nach der Eingabe von Nutzername und Passwort) mithilfe des
YubiKey als zweiten Faktor authentifizieren:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_09_login_2fa.png)  
Durch einen Druck auf *Use security key* beginnt die Kommunikation mit
dem YubiKey. Wie auch bei der Registrierung sind hier die Fenster ganz
verschieden. Im schlimmsten Fall unterstützt der verwendete Browser
WebAuthn nicht:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_13_not_supported.jpg)  
Dann kann man aber immer noch auf TOTP oder die Eingabe eines
Recovery-Codes umsteigen.  

#### Google Chrome auf Android

Auch bei Android wird auf die Implementierung des Browsers
zurückgegriffen. Dort muss man zusätzlich noch auswählen, über welche
Schnittstelle der YubiKey verwendet werden soll:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_git_android.jpeg)  
  
### Anmerkungen

  - Im Sinne der Systemhärtung empfiehlt es sich, nicht verwendete
    Authentifizierungsmethoden und Zugänge zu Systemen zu deaktivieren
      - Warum ermöglicht GitHub das Hinzufügen eines SecurityKey nur
        nach Aktivierung von TOTP oder SMS als zweiten Faktor?  
        GitHub geht es dabei vor allem darum, den Nutzer davor zu
        schützen, dass er sich aus seinem eigenen Account aussperrt.
        Würde man auf einem älteren Browser einen Anmeldeversuch
        starten, der den WebAuthn-Standard noch nicht unterstützt, kann
        man sich nicht einloggen. Grundsätzlich empfiehlt es sich aber,
        den Browser immer auf dem aktuellsten Stand zu halten und dann
        wäre das eigentlich kein Problem. Abgesehen davon muss man
        natürlich seinen YubiKey immer dabei haben - auch deshalb
        möchte GitHub, dass ihre Nutzer verpflichtend auch andere
        Anmeldemöglichkeiten haben.
  - Der große Vorteil bei U2F gegenüber TOTP ist ganz klar die einfache
    Nutzbarkeit. Das ist hier im direkten Vergleich von TOTP zu U2F
    deutlich zu spüren.

  

## Google Account

Google ermöglicht es, als zweiten Faktor ausschließlich einen
SecurityKey zu registrieren.

### Registrierung

Wenn man über einen Webbrowser im Google-Account eingeloggt ist kann man
unter *Google Konto Verwalten/Sicherheit/Bestätigung in zwei Schritten*
in den erweiterten Optionen einen SecurityKey hinzufügen:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_google_02_sec_key.png)  
Dann kommt eine Information, die zur Berührung des SecurityKeys
auffordert. Nach Druck auf den YubiKey und der Vergabe eines Namens ist
die Registrierung abgeschlossen.  
Auch hier gibt es, je nach Browser und Betriebssystem, verschiedene
Fenster. Diese sehen aber genau gleich aus wie schon zuvor bei der
Registrierung im GitHub-Abschnitt und sind deshalb hier nicht mehr
eingefügt.

### Authentifizierung

Beim Einloggen, wird nach Email und Passwort automatisch nach dem
SecurityKey gefragt. Einfach einstecken und durch eine Berührung
einloggen. Unmittelbar nach der Anmeldung kann man außerdem die
Überprüfung des zweiten Faktors (YubiKey) deaktivieren:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_google_03_login.png)  
Das empfiehlt sich bei einem Standrechner zu Hause. Die Herangehensweise
beim Verlust des Schlüssels ist bei Google nämlich wie folgt geregelt:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_google_04_alternatives.png)  
Hat man den SecurityKey verloren, kann man sich alternativ einen
Sicherheitscode auf ein anderes Gerät zukommen lassen, bei dem man
angemeldet ist. Hat man aber kein Gerät, bei dem man bereits angemeldet
ist, und wird überall der SecurityKey erfordert, bleibt nur noch die
[Kontowiederherstellung](https://support.google.com/accounts/answer/7299973?hl=de&ref_topic=3382255).
Das schützt den eigenen Account zwar optimal, ist bei Verlust des
SecurityKey aber umso problematischer. Es empfiehlt sich daher, einem
Gerät zu vertrauen, oder im besten Fall einen zweiten SecurityKey zu
hinterlegen.  
Auch hier gibt es, je nach Browser und Betriebssystem, verschiedene
Fenster. Diese sehen aber genau gleich aus wie schon zuvor bei der
Authentifizierung im GitHub-Abschnitt und sind deshalb hier nicht mehr
eingefügt.  
  

## Microsoft Account

Mittlerweile kann man sich bei <https://account.microsoft.com/> mithilfe
des WebAuthn-Standards und eines FIDO2-Authenticators anmelden. Der
YubiKey ist ein solcher Authenticator und ermöglicht somit einen
Login-Vorgang. Leider ist ein Login mittels SecurityKey aber nur von
einem Windows-Rechner aus möglich, der Windows-Hello unterstützt\! Wenn
man den Sicherheitsschlüssel hier verwendet, handelt es sich außerdem um
eine Alternative zum Passwort\! Eine zweite Anmeldemöglichkeit erhöht
die Sicherheit in der Regel leider nicht. Man kann aber zusätzlich die
Zweifaktor-Authentifizierung für den Microsoft Account aktivieren.
Dieser zweite Faktor wird ausschließlich bei einer Anmeldung mittels
Nutzername und Passwort oder beim Windows Hello PIN abgefragt, nicht
jedoch beim Login mit Windows Hello SecurityKey. Man kann also mit der
Zweifaktor-Authentifizierung das Einloggen mittels Passwort sicherer
machen, und nebenbei zur Verbesserung der Usability mittels Windows
Hello SecurityKey den YubiKey als FIDO2-Device nutzen --\> was wir auch
empfehlen.

Zuerst erklären wir das Hinzufügen des YubiKey als Alternative zum
Passwort, und anschließend die Möglichkeit der
Zweifaktor-Authentifizierung mittels OATH-Authenticator[^1] zur
Absicherung des Passwort-Logins:

### Registrierung

Um einen Security-Key hinzuzufügen, kann man nach der Anmeldung beim
Microsoft-Konto mit dem Webbrowser über die Reiter
*Sicherheit/Zusätzliche Sicherheitsoptionen/Sicherheitsschlüssel
einrichten* zur Einrichtung navigieren. Hier kann man dann auswählen, ob
man die USB- oder NFC-Schnittstelle nutzen möchte.  
![]({{ site.baseurl }}{{ page.dir }}img/fido_microsoft_1.png)  
Ich stecke meinen YubiKey mittels USB am Computer an und klicke auf
"Weiter". Bei der menügeführten Registrierung werde ich aufgefordert den
gesetzten FIDO-PIN einzugeben, oder einen neuen FIDO-PIN zu setzen,
falls dies noch nicht geschehen ist. Nach einer Berührung auf den
YubiKey ist die Registrierung abgeschlossen. Man kann auch selbst den
PIN setzen oder verändern. Das haben wir [hier](/YubiKeyWiki/docs/FIDO2#einstellungen-am-yubikey)
erklärt.

**Sicherheitserwägung**: Das BSI empfiehlt eine PIN-Retry Beschränkung
auf 3 Versuche bei einer PIN-Länge von 6 Ziffern.<sup>[\[1, Tabelle
6.2\]](#quellen)</sup> Die PIN-Retries für FIDO sind am YubiKey
unveränderlich auf 8 Versuche gesetzt. Ein 6-stelliger, zufällig
gewählter PIN ist unserer Meinung nach aber ausreichend, vor allem wenn
man bei Verlust des YubiKey, diesen unmittelbar bei allen Services als
Authentifizierungsmethode entfernt. Damit das möglich ist, muss
natürlich eine zweite Anmeldemöglichkeit neben dem verlorenen YubiKey
gegeben sein\! Das ist beim Microsoft Account aber kein Problem, da der
SecurityKey das Passwort nicht ersetzt sondern ergänzt. Nachdem das
Passwort nun das "schwächste Glied" der Kette wäre, empfehlen wir
zusätzlich die [Nutzung eines zweiten Faktors](#microsoft-zweiter-faktor-für-passwort)
bei der Anmeldung mit Passwort.  
  
### Authentifizierung

Die Authentifizierung ist ganz einfach. Beim Login braucht man die
Email-Adresse gar nicht eingeben sondern wählt gleich den Login über den
SecurityKey aus:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_microsoft_2.png)  
Nach Eingabe des Passworts ist man angemeldet:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_microsoft_3.png)  
  
  
### Microsoft Zweiter Faktor für Passwort
Wir empfehlen wir das
Absichern des Passwort-Logins und des Windows Hello PINs mit einem
zweiten Faktor. Der Login mittels Windows Hello SecurityKey ist vom
zweiten Faktor nicht betroffen. Mögliche zweite Faktoren sind eine SMS,
E-Mail oder ein OATH-Authenticator, nicht aber FIDO2. Wir beschreiben
nun das Einrichten des Yubico-Authenticators als zweiten Faktor.  
Um einen zweiten Faktor hinzuzufügen, navigiert man nach der Anmeldung
beim Microsoft-Konto mit dem Webbrowser auf die Option
*Sicherheit/Zusätzliche Sicherheitsoptionen/Sicherheitsschlüssel
einrichten*. Wir wählen eine Identitätsprüfung mittels "App" aus und
klicken auf "eine andere Authentitifikator-App einrichten":  
![]({{ site.baseurl }}{{ page.dir }}img/fido_microsoft_4.png)  
Wir bekommen nun einen Barcode angezeigt. Wir öffnen den
Yubico-Authenticator und fügen recht oben mit dem "+"-Symbol einen neuen
Account hinzu. Nachdem der Barcode schon sichtbar war, hat der
Authenticator bereits alle Informationen gefunden:  
![]({{ site.baseurl }}{{ page.dir }}img/fido_microsoft_5.png)  
Mit einem Klick auf "Add" ist die Registrierung bereits abgeschlossen.
Microsoft möchte aber noch eine Test-Authentifizierung und fordert uns
auf ein OTP vom Authenticator einzugeben. Diesen "Code der App", wie er
im obigen Bild von Microsoft genannt wird, müssen wir ins vorgesehene
Feld eingeben. Zum Generieren des OTP drücken wir doppelt auf den gerade
hinzugefügten Account im Authenticator. Nach einer Berührung des YubiKey
erhalten wir das OTP (dieses liegt unmittelbar in der Zwischenablage,
und muss nicht händisch kopiert werden\!) und fügen es in das dafür
vorgesehene Feld ein. Zum Schluss erhält man noch einen Recovery-Code.
Dieser ist sicher aufzubewahren (Aufschreiben auf einem Zettel,
Speichern im Passwortmanager) und dient zum Einloggen, falls die
Verwendung des Yubico Authenticator nicht mehr möglich ist, zum Beispiel
aufgrund eines Verlustes des YubiKey. Die Eingabe eines OTP vom
Authenticator ist ab jetzt bei jedem Login beim Microsoft Account
mittels Passwort oder Windows Hello PIN erforderlich. Deutlich bequemer
ist natürlich unser zuvor hinzugefügter Security-Key.

# Quellen

<sup>\[1\]</sup> *BSI TR-02102-1 "Kryptographische Verfahren:
Empfehlungen und Schlüssellängen"*, BSI Technische Richtlinie, Version
2020-01, Stand 24.03.2020, Letzter Zugriff 07.05.2020 \[Online\], URL:
<https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf>  

**Fußnoten**:

[^1]: Als OATH-Authenticator nehmen wir den Yubico Authenticator in Kombination mit dem YubiKey
