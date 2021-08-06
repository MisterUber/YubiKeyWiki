# Kurzbeschreibung

{% include acronyms.md %}

Der YubiKey ist ein kleiner Security Token mit verschiedenen
Schnittstellen. Dieser wird seit 2011 aktiv entwickelt und von der Firma
[Yubico](https://www.yubico.com/) hergestellt.  
Dieser Abschnitt soll einen generellen Einblick in das Thema YubiKey und
dessen Funktionen geben. In diesem Wiki wird ausschließlich auf die
Funktionen der [YubiKey 5
Serie](https://www.yubico.com/products/compare-yubikey-5-series/)
eingegangen. Die YubiKeys der YubiKey 5 Serie unterscheiden sich
lediglich in ihrem Aussehen und den Kommunikationsschnittstellen NFC,
USB-A, USB-C oder Lightning. <sup>[\[1\]](#quellen)</sup>  
Der YubiKey unterstützt,<sup>[\[2\]](#quellen)</sup>

  - die Generierung von Einmalpasswörtern (OTP),
  - die Ausgabe von einem statischen Passwort,
  - die Beantwortung von Challenge-Response-Anfragen,
  - Zweifaktor-Authentifizierung mittels FIDO U2F / FIDO2,
  - den [OpenPGP](/YubiKeyWiki/docs/OpenPGP) Standard
  - und kann auch als Smartcard funktionieren (PIV).

Der YubiKey ist plug-and-play, da für einige Funktionen nur USB HID
Treiber benutzt werden, die auf allen gängigen Betriebssysteme verfügbar
sind. <sup>[\[2\]](#quellen)</sup>

Jeder YubiKey der [YubiKey 5
Serie](https://www.yubico.com/products/compare-yubikey-5-series/) ist
mit einem Button (Goldkontakt) und einer LED ausgestattet, um mit dem
Benutzer zu kommunizieren. Auf den Bildern unten sieht man einen YubiKey
5 NFC mit rundem Goldkontakt in der Mitte und der LED - versteckt hinter
dem Yubico "y".

![YubiKey 5 NFC](/YubiKeyWiki/images/yubikey5nfc.jpg){:width="250px"} ![YubiKey 5 NFC LED](/YubiKeyWiki/images/yubikey5nfc_led.jpg){:width="256px"}

Der Button aktiviert schon bei leichten Druck und hat drei Funktionen:
<sup>[\[2\]](#quellen)</sup>

  - Er kann eine Funktion triggern. (z.B.: Ausgeben des statischen
    Passworts)
  - Er kann eine Funktion erlauben. (z.B.: Generierung einer Response,
    wenn eine Anwendung durch einen API-Call eine Challenge stellt)
  - Er kann eine Smartcard einlegen oder auswerfen. (Umschalten des
    Kartenstatus zwischen Gesteckt oder
    Entfernt)<sup>[\[2\]](#quellen)</sup>

Bei der Verwendung von OTP wird zwischen kurzem und langem Druck
unterschieden. <sup>[\[2\]](#quellen)</sup>

Der YubiKey erkennt folgenden Input: Kurzen und langen Knopfdruck und
auch API Calls via dem USB Interface.<sup>[\[2\]](#quellen)</sup>

Als Output gibt es die Textform, die vom statischen Passwort und dem OTP
verwendet wird und eine Antwort nach einer Anfrage über eine API.
Zweiteres wird bei Challenge-Response, FIDO2, und der CCID Smartcard
Funktion (PIV, OpenPGP, OATH) verwendet. Wenn man im Textmodus ist,
simuliert der YubiKey eine Tastatur um das Passwort zu senden. In diesem
Modus ist man anfällig auf Key Logger, was vor allem für die Verwendung
des statischen Passworts problematisch ist.<sup>[\[2\]](#quellen)</sup>

Wie schon vorher genannt, ist der YubiKey ein Multifunktionsgerät. Die
verschiedenen Funktionen nutzen drei unterschiedliche USB
Interfaces:<sup>[\[2\]](#quellen)</sup>

| Funktionen                                | USB Interface | Link zum Interface Standard                                                                                                            |
| ----------------------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| OTP                                       | Keyboard HID  | [Device Class Definition for HID 1.11](https://www.usb.org/document-library/device-class-definition-hid-111)                           |
| [FIDO2](/YubiKeyWiki/docs/FIDO2)     | FIDO HID      | [FIDO U2F HID Protocol Specification](https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-hid-protocol-ps-20141009.html) |
| PIV                                       | CCID          | [Smart Card CCID version 1.1](https://www.usb.org/document-library/smart-card-ccid-version-11)                                         |
| [OpenPGP](/YubiKeyWiki/docs/OpenPGP) | CCID          | [Smart Card CCID version 1.1](https://www.usb.org/document-library/smart-card-ccid-version-11)                                         |
| OATH                                      | CCID          | [Smart Card CCID version 1.1](https://www.usb.org/document-library/smart-card-ccid-version-11)                                         |

## Slots

Der YubiKey bietet viele Speichermöglichkeiten für Keys, Zertifikate
oder generell Credentials. Diese Speichermöglichkeiten nennt man Slots.
Die Slots haben bestimmte Anwendungsgebiete. Zum Beispiel wird der Slot
9c im Zusammenhang mit der Smart Card Anwendung nur für digitale
Signaturen verwendet.<sup>[\[3\]](#quellen)</sup>

## Funktionen

Um einen kleinen Einblick in die möglichen Anwendungsgebiete des YubiKey
zu gewähren, werden die Funktionen hier kurz erklärt.

**OTP Anwendungen**  
Bei OTP handelt es sich um ein Passwort, das für jeden
Authentifizierungsvorgang wechselt. Wenn auf der Yubico Seite von
OTP-Anwendungen oder OTP-Funktionen gesprochen wird, sind nachstehende
Standards bzw. Authentifizierungsmethoden gemeint. Für all diese
OTP-Anwendungen sind zwei Speicherplätze - Slot 1 und Slot 2 - am
YubiKey vorgesehen. Man kann also nur zwei dieser Anwendungen
gleichzeitig am YubiKey verwenden.

  - **Yubico OTP**:  
    Ein von Yubico selbst für den YubiKey entwickeltes OTP-Verfahen.
    Hierbei wird eine 32 Zeichen lange Sequenz zur Authentifizierung an
    einem Server erzeugt. Diese Methode funktioniert out-of-the-box, da
    Yubico auf Slot 1 des YubiKey diese Funktionalität bereits
    voreingestellt und das benötigte Secret (einen symmetrischen
    Schlüssel) auf der YubiCloud hinterlegt hat. Das Yubico OTP kann
    anstelle eines Passwortes oder für 2-Faktor Authentifizierung
    verwendet werden. Das nachstehende Bild zeigt wie einfach man sich
    bei einem Service das diese Authentifizierungsmöglichkeit bietet
    einloggen kann. Man gibt wie gewohnt die Zugangsdaten (Benutzername
    und Passwort) ein, welche, wie sonst auch, auf der Website gegen
    deren Datenbank geprüft werden. Zusätzlich setzt man dann den Cursor
    ins Yubico-Feld und drückt den Button am YubiKey kurz, damit dieser
    das Yubico OTP eingibt. Im Hintergrund leitet die Anwendung das
    generierte Einmalpasswort an die YubiCloud weiter, welche das
    generierte OTP überprüft und den Nutzer zusätzlich authentifiziert.
    Man muss die YubiCloud nicht nutzen und kann auch seinen eigenen
    Validierungsserver bereitstellen - Yubico stellt hierfür unter der
    [BSD-Lizenz](https://github.com/Yubico/yubikey-val/blob/master/COPYING)
    die [yubikey-val
    Software](https://developers.yubico.com/yubikey-val/) zur Verfügung.
    <sup>[\[4\]](#quellen)</sup>  
    ![https://developers.yubico.com/OTP/otp\_login\_form.png](https://developers.yubico.com/OTP/otp_login_form.png)

<!-- end list -->

  - **OATH-HOTP**:  
    HOTP ist ein offener Standard, der von der OATH erarbeitet wurde
    ([RFC4226](https://tools.ietf.org/html/rfc4226)). Hierbei tauschen
    Server und Client bei der erstmaligen Registrierung einen geheimen
    Schlüssel aus. Unter Verwendung des Schlüssels und einem
    Counter-Wert (dieser macht die Passwörter "one time") wird mittels
    HMAC eine Zahlenfolge abgeleitet. Leiten Client und Server die
    gleiche Zahlenfolge ab, ist man authentifiziert.
    <sup>[\[5\]](#quellen)</sup>

<!-- end list -->

  - **Challenge-Response:**  
    Unter Challenge-Response versteht Yubico
    Authentifizierungsverfahren, bei denen Programme selbstständig mit
    dem YubiKey kommunizieren. Hierfür kann einerseits wieder das
    **Yubico OTP**<sup>[\[6, Sec. 4.3\]](#quellen)</sup> verwendet
    werden, für das jedoch ein Authentifizierungsserver notwendig ist.  
    Als zweite Möglichkeit gibt es den universell einsetzbaren
    **HMAC-SHA-1**-Modus<sup>[\[6, Sec. 4.4\]](#quellen)</sup> nach den
    HMAC-Standards [RFC2104](https://tools.ietf.org/html/rfc2104) und
    [FIPS
    PUB 198](https://csrc.nist.gov/csrc/media/publications/fips/198/archive/2002-03-06/documents/fips-198a.pdf).
    Dieses Verfahren wird in der offline Authentifizierung verwendet, da
    es keinen Server benötigt, der für die Validierung kontaktiert
    werden muss. Vor der ersten Verwendung zur Authentifizierung, muss
    der YubiKey beim jeweiligen Computersystem registriert werden. Dazu
    sendet der Computer eine zufällige Zeichenfolge (Challenge) an den
    YubiKey. Der YubiKey leitet davon, unter Verwendung von HMAC-SHA-1
    und einem geheimen Schlüssel, eine Response ab. Solch eine
    Challenge-Response-Kombination, wird am Computer gespeichert. Möchte
    man sich mit dem YubiKey anschließend Authentifizieren, schickt der
    Computer die Challenge, auf die er bereits die Response kennt, und
    authentifiziert so den Nutzer. Gleich darauf wird für den nächsten
    Authentifizierungsvorgang eine Challenge an den YubiKey gesandt und
    die zugehörige Response gespeichert. Der geheime Schlüssel verlässt
    somit nie den YubiKey. Der genaue Ablauf von Registrierung und
    Authentifizierung ist im Sourcecode <sup>[\[7\]](#quellen)</sup>
    ersichtlich. 

**Static Password:**  
Das Static Password ist mit einem normalen Passwort gleich zu stellen
und kann somit bei einfachen Username/Passwort Lösungen verwendet
werden. Das Static Password kann bis zu 65 Zeichen lang sein, wenn der
Advanced Mode und der Prefix eingeschaltet worden sind. Die Verwendung
eines Static Password belegt ebenfalls einen der zwei Slots 1 und 2.
Abgesehen von der Länge ist das Static Password nicht besser wie ein
normales Passwort. Die Nutzung dieser Funktion ist daher zu
hinterfragen. Passwörter sind bei Bekanntwerden bis zum Passwortwechsel
kompromittiert. Dieses Problem wird bei OTP-Verfahren abgeschwächt, da
jedes Passwort nur einmal verwendet werden kann.
<sup>[\[8\]](#quellen)</sup>**Die Verwendung der Static Password
Funktion sollten nur dann eingesetzt werden, wenn sonst keine andere
Authentifizierungsmethode verwendet werden kann.**

**FIDO2** und **FIDO U2F:**  
[FIDO2](/YubiKeyWiki/docs/FIDO2) wurde von der FIDO Alliance
standardisiert. Bei FIDO2 handelt es sich um eine Sammlung von
[Spezifikationen](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.pdf)
von 2019, die sowohl passwortlose, als auch Zwei- oder Mehrfaktor
Authentifizierungen bei Web Services ermöglichen. Hierfür können am
YubiKey 25 Anmeldeinformationen gespeichert werden. Der YubiKey
unterstützt außerdem die [FIDO U2F
Spezifikationen](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/)
aus dem Jahr 2017, für die Möglichkeit der Zweifaktor Authentifizierung.
Mit dieser Authentifizierungsmöglichkeit kann man sich bei beliebig
vielen Web Services registrieren. Der große Vorteil gegenüber OTP liegt
darin, dass kein symmetrischer Schlüssel verwendet wird, der initial
zwischen Client und Server verschickt werden muss. Beide Verfahren
verwenden nämlich Public-Key Kryptografie. Man-in-the-Middle Attacken,
bei denen der symmetrische Schlüssel beim initialen Austausch
kompromittiert wird, sind daher kein
Problem.<sup>[\[2\]](#quellen)[\[9\]](#quellen)</sup>

**OATH:**  
Die OATH hat die zwei OTP Standards TOTP
([RFC6238](https://tools.ietf.org/html/rfc6238)) und HOTP
([RFC4226](https://tools.ietf.org/html/rfc4226)) spezifiziert. HOTP
kennen wir schon: Eine der OTP Anwendungen, welche in den Slots 1 und 2
des YubiKey verwendet werden können. Mit der OATH-Funktionalität des
YubiKey können zusätzlich noch einmal 32 OATH-Credentials (HOTP oder
TOTP) gespeichert werden. Beim TOTP wird im Gegensatz zum HOTP kein
Counter, sondern die aktuelle Zeit verwendet. Das von der aktuellen Zeit
abgeleitete OTP ist immer nur für eine gewisse Zeitspanne (z.B. 30
Sekunden) gültig. Damit das funktioniert muss der YubiKey natürlich die
aktuelle Zeit kennen. Zur Verwendung und Verwaltung von OATH gibt es
deshalb den [Yubico Authenticator](/YubiKeyWiki/docs/verwaltung).
<sup>[\[2\]](#quellen)</sup> Weitere Informationen gibt es auf der
Website von Yubico. <sup>[\[10\]](#quellen)</sup>

**PIV:**  
Der YubiKey liefert auch eine PIV-kompatible Smart-Card-Applikation. PIV
ist ein US Standard
([FIPS-201-2](https://csrc.nist.gov/csrc/media/publications/fips/201/2/final/documents/draft_nist-fips-201-2.pdf)),
der es ermöglicht, RSA oder ECC Signier- und Verschlüsselungsoperationen
auf Smart Cards über standardisierte Schnittstellen wie PKCS\#11
durchzuführen. Die dafür verwendeten Schlüssel werden in eigenen Slots
gespeichert. Windows unterstützt diese PIV Smartcard-Funktion
out-of-the-box. Hierzu gibt es auch noch einen YubiKey Minidriver, der
das managen von Zertifikaten zulässt. <sup>[\[2\]](#quellen)</sup>
Weitere Informationen gibt es auf der Website von Yubico.
<sup>[\[11\]](#quellen)</sup>

**OpenPGP**  
[OpenPGP](/YubiKeyWiki/docs/OpenPGP) ist ein Standard
([RFC4880](https://tools.ietf.org/html/rfc4880)), der ein
Nachrichtenformat zur Email-Verschlüsselung und Schlüsselspeicherung auf
Basis von Asymmetrischer Kryptografie spezifiziert. Der große Vorteil
laut Yubico ist dessen weite Verbreitung im Gnu/Linux Umfeld. Am YubiKey
werden vier Slots für Schlüssel bereitgestellt. Je ein Schlüssel zur
Authentifizierung, zum Verschlüsseln \[1\] und zum Signieren und ein
Platz für einen Beglaubigungsschlüssel (Attestation-Key). Wenn Yubico
davon spricht "OpenPGP" als Funktionalität zu bieten, ist damit eine
Implementierung der "OpenPGP Smart Card Application" Spezifikation
gemeint. Also eine Spezifikation, wie genau man den OpenPGP Standard
([RFC4880](https://tools.ietf.org/html/rfc4880)) auf eine Smart Card
(nach [ISO/IEC 7816](https://en.wikipedia.org/wiki/ISO/IEC_7816))
bekommt. In unserem Fall ist die Smart Card der YubiKey, der die
Funktionalität als CCID zur Verfügung stellt. Die jeweils aktuellste
Version der "OpenPGP Smart Card Application" gibt es auf der Seite von
[GnuPG](https://gnupg.org/ftp/specs/). Mit der derzeitigen
Firmwareversion 5.2.4 implementiert der YubiKey Version
[3.4](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.0.pdf).
<sup>[\[12\]](#quellen)</sup> Genauere Informationen gibt es in unserem
Wiki unter [OpenPGP](/YubiKeyWiki/docs/OpenPGP).

## Personalisierung

Um den YubiKey für die gewünschte Verwendung einzurichten, stellt Yubico
drei verschiedene Tools zur Verfügung.<sup>[\[13\]](#quellen)</sup>
Genaue Informationen zur Installation und Funktionsweise dieser Tools
gibt es in unserem [Artikel](/YubiKeyWiki/docs/verwaltung) zur
Yubikey-Verwaltung. Nachfolgend nun ein paar Informationen für eine
erste Übersicht:

**YubiKey Manager**  
Der [YubiKey
Manager](https://www.yubico.com/products/services-software/download/yubikey-manager/)
ist das Haupttool. Hier können alle Einstellungen für den YubiKey
getätigt werden. Es gibt ihn in einer grafischen oder in einer
Kommandozeilen Variante. Zweiteres ist auf jeden Fall zu bevorzugen, da
in der grafischen Version nicht alle Einstellungsmöglichkeiten verfügbar
sind. Yubico stellt online eine
[Befehlsübersicht](https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide)
für das CLI zur Verfügung.

**Personalization Tool**  
Das [Personalization
Tool](https://www.yubico.com/products/services-software/personalization-tools/use/)
dient zum Einstellen der OTP-Funktionen und des Static Password - also
der Konfiguration der Slots 1 und 2 des YubiKey. Es integriert außerdem
ganz bequem Zufallszahlgeneratoren zur Erstellung neuer
Secrets/Credentials für OTP-Funktionen und Number Converter. Der YubiKey
lässt sich mit dem Personalization Tool für Einsteiger schnell
aufsetzen, da das Programm Quick-Setup Optionen besitzt. Auch bietet es
einen groben Überblick über die eingestellten Settings und erlaubten
Interfaces. Mit dem Tool kann man außerdem schnell mehrere YubiKeys
aufsetzen. (diese Funktion ist für Privatpersonen eher nebensächlich)

**YubiKey Authenticator**  
Der [Yubico
Authenticator](https://www.yubico.com/products/services-software/download/yubico-authenticator/)
bietet eine komfortable Übersicht über alle OATH Credentials und deren
momentan validen Einmalpasswörtern. Es leitet dafür zur Nutzung von TOTP
die Systemzeit an den YubiKey weiter und liest die aktuellen
Einmalpasswörter aus. (vergleichbar zu Google Authenticator). Das
Programm dient also zur Nutzung von HOTP und TOTP und ist auf allen
gängigen Betriebssystemen verfügbar.

## Quellen

<sup>\[1\]</sup> Yubico, *Compare YubiKey 5 Series*, (2020), Letzter
Zugriff 21.04.2020, \[Online\], URL:
<https://www.yubico.com/products/compare-yubikey-5-series/>  
<sup>\[2\]</sup> Yubico, *YubiKey 5 Series Technical Manual*, (2020),
Letzter Zugriff 21.04.2020, \[Online\], URL:
<https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual>  
<sup>\[3\]</sup> Yubico, *PIV certificate slots*, Letzter Zugriff
23.04.2020. \[Online\], URL:
<https://developers.yubico.com/PIV/Introduction/Certificate_slots.html>  
<sup>\[4\]</sup> Yubico, *What is Yubico OTP?*, Letzter Zugriff
21.04.2020. \[Online\], URL: <https://developers.yubico.com/OTP/>  
<sup>\[5\]</sup> Yubico, *What is OATH?*, Letzter Zugriff 21.04.2020.
\[Online\], URL: <https://developers.yubico.com/OATH/>  
<sup>\[6\]</sup> Yubico, *Yubikey Client COM API V1.1*, (2012), Letzer
Zugriff 24.04.2020, \[Online\], URL:
<https://developers.yubico.com/windows-apis/Releases/yubikey-client-API-1.1.pdf>  
<sup>\[7\]</sup> Yubico, *Github Sourcecode ykpamcfg.c*, (2019), Letzter
Zugriff 24.04.2020, \[Online\], URL:
<https://github.com/Yubico/yubico-pam/blob/master/ykpamcfg.c>  
<sup>\[8\]</sup> Yubico, *Touch triggered OTP*, Letzter Zugriff
24.04.2020, \[Online\], URL:
<https://developers.yubico.com/Developer_Program/Guides/Touch_triggered_OTP.html>  
<sup>\[9\]</sup> FIDO Alliance, *Specification Overview*, Letzter
Zugriff 24.04.2020, \[Online\], URL:
<https://fidoalliance.org/specifications/>  
<sup>\[10\]</sup> Yubico, *What is OATH?*, Letzter Zugriff 25.04.2020,
\[Online\], URL: <https://developers.yubico.com/OATH/>  
<sup>\[11\]</sup> Yubico, *What is PIV?*, Letzter Zugriff 25.04.2020,
\[Online\], URL: <https://developers.yubico.com/PIV/>  
<sup>\[12\]</sup> Yubico, *What is PGP?*, Letzter Zugriff 25.04.2020,
\[Online\], URL: <https://developers.yubico.com/PGP/>  
<sup>\[13\]</sup> Yubico, *YubiKey Device Configuration*, Letzter
Zugriff 25.04.2020, \[Online\], URL:
<https://developers.yubico.com/Software_Projects/YubiKey_Device_Configuration/>  

1.  der hierfür gespeicherte Private-Key wird eigentlich zum
    Entschlüsseln verwendet, obwohl er Encryption-Key
    ("Verschlüsselungs-Schlüssel") heißt
