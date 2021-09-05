# SSH-Public-Key-Authentication

{% include acronyms.md %}

Schnell zu deinem Rechner ohne physischen Zugang eine Verbindung
aufzubauen, um das System zu updaten oder neue Funktionen hinzuzufügen,
funktioniert heutzutage sehr einfach. Dazu verwenden die meisten, die
Secure Shell, kurz SSH. Diese ermöglicht das sichere Verbinden zu einem
entfernten Computer. Um das eigene System vor unerlaubten Zugriffen zu
schützen, ist eine Authentisierung am System von Nöten. Diese kann
klassisch in Form von Username und Passwort oder mittels
Public-Key-Kryptographie durchgeführt werden. Zweiteres wird in diesem
Wiki-Eintrag behandelt.  

## Ausgangssituation

Diese Anleitung baut auf die OpenPGP-Funktionalität des YubiKeys auf.
Für die folgende Erklärung wird also vorausgesetzt, dass sich am
YubiKey bereits ein OpenPGP-Schlüssel zur Authentifizierung befindet.
Ist dies nicht der Fall, kann man eine entsprechende Anleitung auf
unserer [OpenPGP](/YubiKeyWiki/docs/OpenPGP)-Seite
finden.  
Nach erfolgreicher Konfiguration sollte die Smartcard Statusausgabe so
ähnlich aussehen (zumindest ein Authentication Key muss eingetragen
sein):

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

## Client-Side Konfiguration

Die Konfiguration des Clients ist notwendig, damit die Programme, die
die SSH-Verbindung zum Server aufbauen, von der Smartcard (also dem
YubiKey) lesen können. Dies ist mit kleinen Aufwand für jedes hier
beschriebene Betriebssystem schnell getan.

Die nächsten Schritte sind für Windows und Linux notwendig. Bei Android
reicht es wenn das Metadaten-Feld *URL of public Key* gesetzt wird. Über
dieses Feld importieren Apps meistens den öffentlichen Schlüssel
automatisch. Das Setzen des Feldes wird
[hier](/YubiKeyWiki/docs/OpenPGP#metadaten-auf-den-yubikey-laden)
erklärt.  
Der erste Schritt der Konfiguration ist das Importieren des eigenen
öffentlichen Schlüssels. Beim Client bräuchte man eigentlich nur den
privaten Schlüssel zum Authentisieren. Dennoch benötigen wir den
öffentlichen Hauptschlüssel. Ohne den öffentlichen Hauptschlüssel kann
sonst die Struktur der privaten Schlüssel nicht erkannt werden\!: Wenn
man auf einem frisch installierten System arbeitet, kann GPG die am
YubiKey gespeicherten Subschlüssel nicht verwenden, da sie vom
Hauptschlüssel abhängen. Die benötigte Struktur des Schlüssels erhält
GPG über den dazugehörigen Public-Key.  
Die gespeicherten öffentlichen Schlüssel können mit dem Befehl *gpg -k*
eingesehen werden. Wenn hier die Ausgabe leer ist, muss der öffentliche
Schlüssel importiert werden. Hier gibt es zwei Möglichkeiten. Diese sind
abhängig, wie dieser gespeichert wurde<sup>[\[1\]](#quellen)</sup>:

1.  Fall: Der öffentliche Schlüssel befindet sich in einem File. Dann
    kann mit dem Befehl *gpg --import file* der Schlüssel importiert
    werden.
2.  Fall: Der öffentliche Schlüssel befindet sich auf einem Keyserver.
    Dabei hat man einen Link erhalten, wo man den Schlüssel
    herunterladen kann. Diesen kann man in das *URL of public key*-Feld
    des YubiKeys eintragen, was in der vorherigen Ausgabe des
    Kartenstatus zu sehen ist. Um den Schlüssel zu erhalten muss der
    Befehl *gpg --card-edit* ausgeführt werden. Anschließend befindet
    man sich in einer eigenen interaktiven Befehlseingabeaufforderung
    von GPG. In dieser ruft man den *fetch*-Befehl auf. Dieser Befehl
    bewirkt das Herunterladen des öffentlichen Schlüssels. Wenn der Link
    nicht eingetragen ist, kann ein anderer Befehl zum Ziel führen.
    Dieser lautet: *gpg --keyserver KEYSERVER-URL --recv-key ID*. Der
    Keyserver kann zum Beispiel
    [keys.openpgp.org](https://keys.openpgp.org/) sein. Mit der ID ist
    der Fingerprint des Schlüssels gemeint. Dieser ist zum Beispiel
    842C9402A84CFFD2344AF38204D2E3D3F71DBECC. Den Fingerprint sieht man
    mit dem Kommando *gpg -k*. Die Short Key ID kann dafür auch
    angegeben werden.

Nun sollte GPG den öffentlichen und den privaten Schlüssel anzeigen
können (Kontrolle mit *gpg -k* und *gpg -K*).  
Nun kann mit der betriebssystemspezifischen Konfiguration fortgesetzt
werden.

### Windows

In Windows wird das Programm [GPG4WIN](https://www.gpg4win.de/)
verwendet. Als SSH-Client kommt in Windows
[Putty](https://www.putty.org/) in Frage, das auch hier verwendet
wird.  
GPG hat die SSH-Authentifizierung bereits eingebaut. Diese Funktion ist
mit dem Pageant-Protokoll von Putty kompatibel und muss nur aktiviert
werden. Dazu muss im Ordner *%APPDATA%\\gnupg* die Datei
*gpg-agent.conf* mit dem Inhalt *enable-putty-support* erstellt werden.
Danach muss der gpg-agent neu gestartet werden, um die neue Konfig zu
laden. Dazu die nachstehenden Befehle ausühren:
<sup>[\[2\]](#quellen)</sup>

``` bash
gpg-connect-agent killagent /bye
gpg-connect-agent /bye
```

Mehr muss nicht eingestellt werden. Es empfiehlt sich noch den
gpg-connect-agent in den Autostart hinzuzufügen. Dazu Win + R drücken
und den Befehl *shell:startup* ausführen. Das öffnet den Startup-Ordner.
Als Nächstes wird ein Link(New -\> Shortcut) mit folgenden Inhalt
erzeugt:  
![Autostart Link]({{ site.baseurl }}{{ page.dir }}img/win_autostart_link.png)

Nun wird nach jedem Login des Benutzers der gpg-connect-agent gestartet,
damit die SSH-Authentifizierung immer funktioniert.  
Die Client-Seite ist fertig konfiguriert. Es wird beim [SSH-Public-Key extrahieren](#ssh-public-key-extrahieren) fortgesetzt.

### Linux

Unter Linux muss auch die SSH-Unterstützung von GPG aktiviert werden.
Hier sind folgende Befehle zu verwenden<sup>[\[3\]](#quellen)</sup>:

``` bash
root@debain:/home/debian# gpgconf --kill gpg-agent
root@debain:/home/debian# gpg-agent --daemon --enable-ssh-support
SSH_AUTH_SOCK=/root/.gnupg/S.gpg-agent.ssh; export SSH_AUTH_SOCK;
root@debain:/home/debian# SSH_AUTH_SOCK=/root/.gnupg/S.gpg-agent.ssh; export SSH_AUTH_SOCK;
```

Zur Erklärung der Befehlskette:

1.  Ein laufender gpg-agent wird beendet.
2.  Der gpg-agent wird als Daemon mit eingeschalteter SSH-Unterstützung
    gestartet.
3.  Beim Start des Agents werden zwei Befehle für das Setzen der
    *SSH\_AUTH\_SOCK*-Variable ausgegeben. Diese müssen ebenfalls
    ausgeführt werden. Diese Variable gibt einen Pfad zu einem
    Unix-File-Socket an, den der ssh-agent benutzt. Dieser wickelt die
    SSH-Authentifizierung für uns ab. In dem wir nun diese Variable
    geändert haben, kommuniziert der SSH-Agent nun mit dem GPG-Agent,
    der auf unseren YubiKey zugreifen kann. Somit kann nun der YubiKey
    für die SSH-Authentifizierung verwendet
    werden<sup>[\[4\]](#quellen)</sup>\!

Es wird beim [SSH-Public-Key extrahieren](#ssh-public-key-extrahieren) fortgesetzt.

### Android

Wer ein Android-Handy besitzt kann die App *Termbot* verwenden\! Diese
App unterstützt SSH-Funktionen, sowie die Kommunikation mit dem YubiKey
via NFC oder auch USB\! Wenn man die App startet, kommt man direkt auf
eine Übersicht von den hinzugefügten Hosts.  
![Hosts]({{ site.baseurl }}{{ page.dir }}img/termbot_hosts.jpg)  
Bevor man einen Host hinzufügt, sollte man zuerst den öffentlichen
Schlüssel einfügen. Dies geschieht, oben rechts im vorherigen
Screenshot unter *Pubkeys verwalten*. Folgende Seite sollte nun zu sehen
sein:  
![PubKeys]({{ site.baseurl }}{{ page.dir }}img/termbot_public_key.jpg)  
Hier sieht man im oberen Bereich drei Optionen:

  - Einen neuen Schlüssel in der App erzeugen.
  - Einen Schlüssel von einer Datei importieren.
  - Den Schlüssel von einem Security-Schlüssel beziehen.

Die dritte Option ist die komfortabelste. Hierzu kann man die
NFC-Funktion des YubiKeys benutzen und der Schlüssel wird importiert,
dann über das *URL of public Key*-Feld heruntergeladen. Dies sollte nun
ähnlich zum vorherigen Screenshot aussehen. Nun kann man zur Host-Seite
zurückkehren und den Host hinzufügen. Hier ist wichtig, dass bei der
Option *Verwende pubkey Authentisierung* der YubiKey ausgewählt wird.  
Nachdem der Host hinzugefügt wurde, kann man mit einem Druck auf den
Eintrag die Verbindung aufbauen. Da muss anschließend jedes Mal der
YubiKey verwendet werden.  

## SSH-Public-Key extrahieren

Den Public-Key im SSH-Format zu extrahieren ist sehr einfach. Dazu muss
man nur den Fingerprint des Keys wissen, zu dem man den Public-Key
extrahieren möchte. Der Fingerprint kann mit der Option "-k" in gpg
angezeigt werden:

``` bash
gpg -k
C:/Users/Mathias/AppData/Roaming/gnupg/pubring.kbx
--------------------------------------------------
pub   rsa4096 2020-04-24 [C] [verfällt: 2025-04-23]
      842C9402A84CFFD2344AF38204D2E3D3F71DBECC
uid        [ ultimativ ] Max Muster <ubke4@tWin.at>
sub   rsa4096 2020-04-24 [E] [verfällt: 2025-04-23]
sub   rsa4096 2020-05-04 [S] [verfällt: 2025-05-03]
sub   rsa4096 2020-05-04 [A] [verfällt: 2025-05-03]
```

Den Fingerprint muss im nächsten Befehl angegeben werden, damit der
richtige SSH-Public-Key extrahiert wird:

``` bash
kali@kali:~$ gpg --export-ssh-key 842C9402A84CFFD2344AF38204D2E3D3F71DBECC 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDOhxbjCWmhXTedbocCuy5ujpNnu8OiwBbHhk22Ooc0uZf/RSNN4D10VA3njHmFQKmlHvFJZyQAERyJETCMrSoNhDzYkWPV0PRa/bmj7npSS3a1PCFoAyz5oSvyEOHAaW
/7Bz4JOgzWiKg83Bg1vzy79sH7z675LPYwB6rxfzvEKI7MKuENAmIjWdzCGjrTkK7DhDcOcQAOfboyRUCtsDIEre2kHd3gus5+4y51y1POlENR9nNjZIJUp4CWgguNhTUtMtHSAvN6jgxb2lZwwOp76x0yA8M+YHapfCkvgMUoON5dOL5Us4HXMHvxxR3N
PoD/O884TtFkAloiDOzYyM3AAkAKGGVG074Du/05Rmly+mNZ1j3BP3dtBoyGRqGCNizc6F1tmheAmQoDuXfkPLOqiVHU/Yim4+cyyHT3wIgJ0i/7jYZkJ4tFYgDQ4ILO8ULupSnumk8ruDzq2OV7l7GJd7fZyUL4ynIiKeSe
/6LiGjUn5hWsi1eZj+r270Xbqs8G4DpsSGJjDJOHXvd+3fkR4CGT64Nv0KNroZR+UgHoRMpSk39i6r7x+0a7keyrV2UKqSson8NhxE3jUtZz8JTk/zr6Dc/UglQNXeFXHvFCBksEpSukDIuk7zLGrKg3AOM12FfroyuYpS1QFlxR
/vDE4uwwpmMI7nIL6YyS0o710Q== openpgp:0x4266D204
```

Das Ergebnis ist nun der gewünschte SSH-Key\! Dieser wird im nächsten
Kapitel für die Server-Konfiguration benötigt.

## SSH-Server konfigurieren

Da nun der Client mit dem YubiKey funktioniert, muss noch der Server
darauf vorbereitet werden eingehende Verbindungen anzunehmen. Es sind
zwei Schritte von Nöten. Der erste ist das Einfügen des öffentlichen
Schlüssels, damit sich der Client mit dem YubiKey gegenüber dem Server
authentifizieren kann. Der zweite Schritt ist das Ändern der
*sshd\_config*.

### Einfügen des öffentlichen Schlüssels

Der öffentliche Schlüssel, der im vorherigen Kapitel extrahiert wurde,
muss nun am Server hinterlegt werden. Dazu ist die Datei
*authorized\_keys* in *\~/.ssh*/ vorgesehen. Die Datei muss eventuell
erst erstellt werden. Dann fügt man einfach den Schlüssel in die Datei
ein.  
Das kann folgendermaßen aussehen:

``` bash
kali@kali:~$ cat .ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDOhxbjCWmhXTedbocCuy5ujpNnu8OiwBbHhk22Ooc0uZf/RSNN4D10VA3njHmFQKmlHvFJZyQAERyJETCMrSoNhDzYkWPV0PRa/bmj7npSS3a1PCFoAyz5oSvyEOHAaW/7Bz4JOgzWiKg83Bg1vzy79sH7z675LPYwB6rxfzvEKI7MKuENAmIjWdzCGjrTkK7DhDcOcQAOfboyRUCtsDIEre2kHd3gus5+4y51y1POlENR9nNjZIJUp4CWgguNhTUtMtHSAvN6jgxb2lZwwOp76x0yA8M+YHapfCkvgMUoON5dOL5Us4HXMHvxxR3NPoD/O884TtFkAloiDOzYyM3AAkAKGGVG074Du/05Rmly+mNZ1j3BP3dtBoyGRqGCNizc6F1tmheAmQoDuXfkPLOqiVHU/Yim4+cyyHT3wIgJ0i/7jYZkJ4tFYgDQ4ILO8ULupSnumk8ruDzq2OV7l7GJd7fZyUL4ynIiKeSe/6LiGjUn5hWsi1eZj+r270Xbqs8G4DpsSGJjDJOHXvd+3fkR4CGT64Nv0KNroZR+UgHoRMpSk39i6r7x+0a7keyrV2UKqSson8NhxE3jUtZz8JTk/zr6Dc/UglQNXeFXHvFCBksEpSukDIuk7zLGrKg3AOM12FfroyuYpS1QFlxR/vDE4uwwpmMI7nIL6YyS0o710Q== 
```

### Server-Konfiguration anpassen

Jetzt muss noch die Server-Konfiguration angepasst werden, damit sich
ein Benutzer mit dem öffentlichen Schlüssel authentisieren kann. Dazu
gibt es den Ordner */etc/ssh/sshd\_config.d*. In diesem kann eine eigene
Konfigurationsdatei abgelegt werden. Diese wird selbstständig vom
SSH-Service eingelesen.  
Die Konfiguration sieht folgendermaßen aus:

``` bash
kali@kali:~$ cat /etc/ssh/sshd_config.d/sshd_config_yubikey.conf 
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
```
```tip
**Sicherheitserwägung**: Die obigen Einstellungen in der
Konfigurationsdatei stellen sicher, dass eine Authentifizierung nur mit
hinterlegten SSH-Schlüsseln möglich ist. Die Passwort-,
ChallengeResponse- und Host-Authentifizierung sollen deaktiviert werden, wenn sie nicht genutzt werden\!
```
 
Man kann natürlich die Konfiguration auch ändern. Die vorhandenen
Möglichkeiten sind in der Manpage der *sshd\_config* detailliert
beschrieben.  
Falls der SSH-Service schon vor der neuen Konfiguration läuft, ist ein
erneutes Laden der Konfiguration erforderlich:

``` bash
service ssh reload
```

Oder, wenn der Server noch nicht läuft, wird er mit folgendem Befehl
gestartet:

``` bash
service ssh start
```

An diesem Punkt ist alles Nötige konfiguriert\! Der YubiKey kann nun mit
SSH verwendet werden\!

## Test

Wenn alles richtig konfiguriert wurde, muss man nur den
Hostnamen/IP-Adresse des SSH-Servers wissen und man kann sich
erfolgreich verbinden. Das sieht mit Putty, in der Kommandozeile in
Linux und mit Termbot folgendermaßen aus:

![Windows\_Putty]({{ site.baseurl }}{{ page.dir }}img/putty_successful_login.png)
![Android\_Termbot]({{ site.baseurl }}{{ page.dir }}img/termbot_successful_login.jpg)
![Linux]({{ site.baseurl }}{{ page.dir }}img/linux_successful_login.png)

## Quellen

\[1\] die.net, gpg2(1) - Linux man page, Letzter Zugriff 16.05.2020,
\[Online\], URL: <https://linux.die.net/man/1/gpg2>  
\[2\] Yubico, SSH authentication using a YubiKey on Windows, Letzter
Zugriff 16.05.2020, \[Online\], URL:
<https://developers.yubico.com/PGP/SSH_authentication/Windows.html>  
\[3\] Eric Severance, PGP and SSH keys on a Yubikey NEO, Letzter Zugriff
16.05.2020, \[Online\], URL:
<https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/>  
\[4\] OpenBSD, ssh-agent, Letzter Zugriff 16.05.2020, \[Online\], URL:
<https://man.openbsd.org/ssh-agent.1>
