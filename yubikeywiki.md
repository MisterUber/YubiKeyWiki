# YubiKey 4 HK

## Das Projekt

Beim "YubiKey4HK" handelt es sich um ein Semsterprojekt im Rahmen des
Studiums für Sichere Informationssysteme an der FH-Hagenberg. Das
Projekt wurde von Alexander Hamann, Kristoffer Dorfmayr und Mathias
Huber bearbeitet und hatte das Ziel, ein möglichst umfangreichen Wiki
rund um den YubiKey Security Token zu erstellen. Das Wiki soll als
Anlaufstelle für YubiKey-Einsteiger dienen und bietet neben der
generellen Funktionsbeschreibung auch konkrete Einsatzbeispiele mit
Anwendungsanleitungen und Sicherheitsempfehlungen.

## Wiki-Struktur

Das Wiki hat zwei Hauptartikel die für das Verständnis wichtig sind und
auf die später referenziert wird:

``` 
  * [[yubikey4hk:yubikey_kurzbeschreibung|YubiKey Kurzbeschreibung]]
  * [[yubikey4hk:yubikey_verwaltung|YubiKey Verwaltungstools]]
```

Abgesehen von den zwei Hauptartikeln gibt es noch
Funktionsbeschreibungen \[1\] unter denen konkrete Anwendungsbeispiele
\[2\] zur jeweiligen Funktionalität zu finden sind:

  - [OpenPGP](/yubikey4hk/funktionen/openpgp)
      - [E-Mail
        Verschlüsselung](/yubikey4hk/funktionen/openpgp/e-mail_verschluesselung)
        (Thunderbird, FairEmail)
      - [SSH-Authentifizierung](/yubikey4hk/funktionen/openpgp/ssh_authentifizierung)
  - [FIDO2](/yubikey4hk/funktionen/fido2)
      - [Anmeldung am
        Computersystem](/yubikey4hk/funktionen/fido2/systemlogin)
        (=Systemlogin)
      - [Weblogin bei
        Onlineaccounts](/yubikey4hk/funktionen/fido2/webanmeldung)
        (Exemplarisch GitHub, Google und Microsoft)

Wir empfehlen folgende Vorgehensweise für einen raschen Einstieg in die
Welt der YubiKeys:

1.  Zum allgemeinen Verständnis durchlesen der [YubiKey
    Kurzbeschreibung](/yubikey4hk/start#Der%20YubiKey).
2.  Zu dieser Übersicht zurückkehren und sich bei den obigen Links ein
    Anwendungsbeispiel heraussuchen das man umsetzten möchte.
3.  YubiKey im täglichen Gebrauch einsetzen

Viel Spaß beim Arbeiten mit dem YubiKey\!  
  
  

## Funktionsempfehlung

Der YubiKey bietet eine Vielzahl an möglichen Funktionen. Hier möchten
wir die einzelnen Verfahren etwas vergleichen und eine
Verwendungsempfehlung aussprechen. Wenn man noch keinen Überblick über
die Funktionalitäten hat empfehlen wir unsere [YubiKey
Kurzbeschreibung](/yubikey4hk/yubikey_kurzbeschreibung).

### 1\. Authentifizierung

<table>
<tbody>
<tr class="odd">
<td></td>
<td>Vorteile</td>
<td>Nachteile</td>
</tr>
<tr class="even">
<td>FIDO</td>
<td>Kein statisches Passwort nötig --&gt; man muss sich nichts selber merken<br />
Anmeldung nur durch Druck auf den YubiKey<br />
Keine Replay-Attacken und MitM-Angriffe möglich<br />
Verwendet Public-Key-Krypthographie --&gt; Kein Shared-Secret</td>
<td>Man muss den YubiKey immer mitführen<br />
Webbrowser bzw. Betriebssystem muss FIDO unterstützen</td>
</tr>
<tr class="odd">
<td>OATH</td>
<td>Passwörter sind nur einmal für geringen Zeitraum gültig --&gt; Replay nicht möglich<br />
Browser und Betriebssystem muss OATH nicht untersützen</td>
<td>Zusätzliche App bzw. Programm muss installiert werden<br />
OTP muss händisch eingegeben werden</td>
</tr>
<tr class="even">
<td>Static Password</td>
<td>Easy-to-Implement --&gt; Funktioniert überall<br />
</td>
<td>Shared-Secret --&gt; MitM und Replay ist möglich<br />
Man kann aufgrund der 2 verfügbaren Slots am YubiKey nur 2 Passwörter speichern</td>
</tr>
</tbody>
</table>

FIDO bietet hohe Sicherheit gegen bekannte Angriffe bei vergleichsweise
einfacher Handhabung. Der seit 2018 von der FIDO-Alliance
veröffentlichte FIDO2-Standard ist dazu sehr aktuell und ermöglicht
passwortloses Anmelden. Aufgrund dessen haben wir uns dazu entschlossen
FIDO in unserem Wiki genauer zu bearbeiten, und empfehlen die Verwendung
von FIDO wenn die Möglichkeit besteht. Ist die Verwendung von FIDO aus
Kompatibilitätsgründen nicht möglich, kann man auch mit OATH eine starke
Zweifaktor-Authentifizierung etablieren. Der Einsatz von Statische
Passwörtern am YubiKey hat auch seine Berechtigung. Vor allem dann,
wenn kein anderes Login-Verfahren unterstützt wird und wenn man das
gespeicherte Passwort vom YubiKey oft auf verschiedenen Geräten
einsetzen muss. Beispielsweise wenn der Einsatz eines Passwortmanagers
nicht möglich ist, weil ich das Passwort zum Einloggen beim Rechner
benötige und da noch keinen Passwortmanager zur Verfügung habe, oder
weil ich mich auf einem fremden System befinde (z.B.: FH-Rechner).

**Empfehlung**:  
Bei der Verwendung als zweiten Faktor:

1.  FIDO U2F
2.  OATH

Bei der Verwendung als einzelner Faktor:

1.  FIDO2
2.  statisches Passwort

### 2\. E-Mail-Sicherheit

<table>
<tbody>
<tr class="odd">
<td></td>
<td>Vorteile</td>
<td>Nachteile</td>
</tr>
<tr class="even">
<td>OpenPGP</td>
<td>Authentizität selbst festgelegt durch Signieren<br />
Verbreitet im GNU-Linux Umfeld</td>
<td>Umfangreiches Schlüsselmanagement notwendig<br />
Vertraulichkeitsproblem <a href="https://efail.de/">EFAIL</a>?</td>
</tr>
<tr class="odd">
<td>PIV</td>
<td>Weniger Aufwand da Signieren von Schlüsseln entfällt</td>
<td>Authentizität durch Certificate Authority vorgegeben<br />
Vertraulichkeitsproblem <a href="https://efail.de/">EFAIL</a>?<br />
Zertifikate meist kostenpflichtig</td>
</tr>
</tbody>
</table>

**Empfehlung**:  
Bei der Email-Verschlüsselung:

1.  OpenPGP
2.  PIV

Der PIV Standard wurde von der NIST zum Einsatz in der öffentlichen
Verwaltung geschaffen. PIV findet daher auch eher in Unternehmen
Verwendung, da jedes Unternehmen selbst eine Certificate Authority
betreibt. Nur im Unternehmensumfeld ist so eine Authentizität der
Schlüssel gesichert. Im Privaten Umfeld kann man kostenlosen
Zertifizierungen von verschiedensten Certificate Authorities nicht
grundlegend vertrauen, weshalb die Authentizität nicht gegeben ist.
Außerdem ist es immer schwieriger als Privatperson ein kostenloses
X.509-Zertifikat zu bekommen, das für PIV notwendig ist. Bei OpenPGP
hingegen hat man alles selbst in der Hand. Wenn man das Überprüfen von
Schlüsseln vor dem Signieren sorgfältig betreibt, kann man sich der
Authentizität von Schlüsseln sicher sein.

1.  Beschreibungen der Standards und Funktionalitäten die der YubiKey
    unterstützt

2.  Anleitungen wie man den YubiKey sicher einrichtet und verwendet um
    beispielsweise seine E-Mails zu verschlüsseln
