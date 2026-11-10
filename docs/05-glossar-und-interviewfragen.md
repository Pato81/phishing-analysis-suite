# Glossar & Interviewfragen

Alles, was in dieser Analyse vorkommt, in eigenen Worten erklärt – und die Fragen, die dazu im Vorstellungsgespräch kommen können.

---

## Teil A – Glossar

### E-Mail-Grundlagen

| Begriff | Erklärung |
|---|---|
| **Envelope-From / Return-Path** | Die Absenderadresse auf dem „Briefumschlag“ (SMTP `MAIL FROM`). Dorthin gehen Bounces. Wird für **SPF** geprüft. Der Mensch sieht sie normalerweise nicht. |
| **Header-From** | Die Absenderadresse, die im Mailclient **angezeigt** wird. Kann völlig anders lauten als der Envelope-From. Wird für **DMARC** geprüft. |
| **Received-Header** | Jeder Server, den die Mail durchläuft, setzt **oben** einen Eintrag. Man liest sie **von unten nach oben**. Nur der Eintrag des eigenen Servers ist sicher vertrauenswürdig. |
| **Message-ID** | Eindeutige Kennung, vom absendenden System erzeugt. Ihr Format verrät oft das Mailprogramm oder Kit. |
| **MTA** | Mail Transfer Agent – Server-Software, die Mails weiterleitet (Postfix, Exim, Sendmail). |
| **Quoted-Printable** | Kodierung für 8-Bit-Zeichen in 7-Bit-Mails: `=C3=BC` = `ü`, `=3D` = `=`, `=` am Zeilenende = Zeilenumbruch ignorieren. |
| **RFC 2047 (Encoded Word)** | Kodierung für Sonderzeichen in Headern: `=?UTF-8?Q?...?=` (Quoted-Printable) oder `=?UTF-8?B?...?=` (Base64). |
| **MIME / multipart** | Struktur, um mehrere Teile (Text, HTML, Anhänge) in einer Mail zu transportieren. |

### Authentifizierung

| Begriff | Erklärung |
|---|---|
| **SPF** | Sender Policy Framework. DNS-Eintrag der Domain listet, **welche Server** für sie senden dürfen. Prüft den **Envelope-From**. `-all` = Hardfail, `~all` = Softfail. |
| **DKIM** | DomainKeys Identified Mail. Der Absender **signiert** Header und Body kryptografisch, der Empfänger prüft mit dem Public Key aus dem DNS (`selector._domainkey.domain`). Beweist: unverändert und von dieser Domain autorisiert. |
| **DMARC** | Verknüpft SPF/DKIM mit der **sichtbaren From-Domain** („Alignment“) und legt fest, was bei Fehlschlag passiert (`none`, `quarantine`, `reject`). Liefert Reports. |
| **Alignment** | Die von SPF bzw. DKIM geprüfte Domain muss zur Header-From-Domain passen. Ohne Alignment nützt ein `spf=pass` nichts gegen Täuschung. |
| **iprev** | Reverse-DNS-Prüfung: Zeigt die IP per PTR auf einen Namen, der wieder auf dieselbe IP zeigt? |
| **permerror / softfail / none** | permerror = Prüfung technisch unmöglich (z. B. Key fehlt); softfail = „eigentlich nicht erlaubt, aber nur markieren“; none = keine Policy vorhanden. |

### Täuschungstechniken

| Begriff | Erklärung |
|---|---|
| **Homoglyph** | Zeichen, das einem anderen zum Verwechseln ähnlich sieht: kyrillisch `е` (U+0435) vs. lateinisch `e` (U+0065). |
| **IDN-Homograph-Angriff** | Registrierung einer Domain mit Homoglyphen (`iοnos` mit griech. Omikron). |
| **Punycode** | ASCII-Darstellung internationaler Domainnamen: `xn--inos-0nd` = `iοnos`. Browser und Mailclients zeigen je nach Einstellung die eine oder andere Form. |
| **Zero-Width-Zeichen** | Unsichtbare Unicode-Zeichen (U+200B, U+200C, U+200D, U+2060, U+FEFF). Machen Texte maschinell einzigartig, ohne dass ein Mensch es sieht. |
| **Hidden Text Salting** | Unsichtbarer Text im HTML (`font-size:0`, `color:transparent`), der Filter verwirrt, für Menschen aber nicht existiert. |
| **Bayesian Poisoning** | Harmlose Wörter einstreuen, um statistische Spamfilter Richtung „kein Spam“ zu drücken. |
| **Hash-Busting** | Zufällige Elemente (Kommentare, Attribute, Bilder), damit jede Mail einen anderen Hash hat und Hash-Blocklisten ins Leere laufen. |
| **Open Redirect** | Eine Seite einer seriösen Domain, die auf beliebige Ziele weiterleitet. Wird missbraucht, damit Links „sauber“ aussehen. |
| **Living off Trusted Sites (LOTS)** | Angriffsinfrastruktur auf vertrauenswürdigen Plattformen (AWS, Google, Microsoft) statt auf eigenen Servern. |
| **Lookalike-Domain** | Domain, die einer echten ähnelt (Tippfehler, Homoglyphen, andere TLD). |

### Analyse & Threat Intelligence

| Begriff | Erklärung |
|---|---|
| **IOC** | Indicator of Compromise – konkretes Artefakt (IP, Domain, Hash, URL), das auf einen Angriff hinweist. |
| **Defanging** | IOCs „entschärfen“, damit sie nicht anklickbar sind: `hxxps://`, `evil[.]com`. |
| **TTP** | Tactics, Techniques and Procedures – das *Wie* eines Angreifers. Schwerer zu ändern als IOCs. |
| **Pyramid of Pain** | Modell von David Bianco: Je höher in der Pyramide (Hashes → IPs → Domains → Artefakte → Tools → TTPs) man erkennt, desto teurer ist es für den Angreifer, sich anzupassen. |
| **MITRE ATT&CK** | Öffentliche Wissensdatenbank über Angreifer-Techniken mit IDs (z. B. T1566.002). Gemeinsame Sprache für Red und Blue Team. |
| **Chain of Custody** | Lückenlose Dokumentation, wie Beweise gesichert wurden (Hash, schreibgeschützt, Arbeit nur an Kopien). |
| **YARA** | Regelsprache zum Erkennen von Mustern in Dateien. Standard in Malware-Analyse und Threat Hunting. |
| **Phishing-Kit** | Fertiges Paket aus Mail-Templates, Mailer-Skript und Phishing-Seite, oft als Dienstleistung verkauft (Phishing-as-a-Service). |

---

## Teil B – Interviewfragen mit Antworten aus diesem Fall

**1. „Eine Mail hat `spf=pass`. Ist sie damit legitim?“**
Nein. In Mail 2 war SPF `pass`, weil der Angreifer einen **kompromittierten, legitimen Server** genutzt hat. SPF prüft nur den Envelope-From, nicht die angezeigte Absenderdomain. Erst DMARC mit Alignment schließt diese Lücke – und der Angreifer hat eine eigene Lookalike-Domain ohne DMARC gewählt.

**2. „Wie lesen Sie Received-Header?“**
Von unten nach oben. Vertrauenswürdig ist nur der Eintrag, den mein eigener Mailserver geschrieben hat – dort steht die echte IP des einliefernden Servers. Alles darunter kann gefälscht sein. Zusätzlich vergleiche ich Zeitstempel und Zeitzonen.

**3. „Warum hilft DMARC nicht gegen diese Mails?“**
Weil die Angreifer nicht `ionos.com` gefälscht haben, sondern `iοnos.čom` – eine fremde Domain. DMARC schützt nur die Domain, die es konfiguriert hat. Gegen Lookalikes braucht es Inhaltsanalyse, Domain-Monitoring und Awareness.

**4. „Was ist der wertvollste IOC in diesem Fall und warum?“**
`45.89.60[.]94` aus dem Header `X-PHP-Script` in Mail 2. Er zeigt, wer das Mailer-Skript auf dem kompromittierten Server aufgerufen hat – das ist die Infrastruktur des Angreifers selbst, nicht nur ein missbrauchter Server. Gleichzeitig erkläre ich, dass das wahrscheinlich ein VPS oder Proxy ist und nicht zur Person führt.

**5. „Die IOCs zwischen den Mails sind verschieden. Woher wissen Sie, dass es dieselbe Kampagne ist?“**
Über Kit-Fingerabdrücke: identischer Hidden-Span-Style, identisches Message-ID-Format, identisches Punycode-Schema `xn--inos-0nd`, Zero-Width-Zeichen im Betreff, Zufalls-Envelope-Absender. Die Infrastruktur rotiert, der Code bleibt. Das ist die Pyramid of Pain in der Praxis.

**6. „Wie würden Sie das automatisiert erkennen?“**
Mit Regeln auf Kit-Ebene statt auf IOC-Ebene. Ich habe eine YARA-Regel geschrieben, die beide Mails erkennt – auch dann noch, wenn die Lookalike-Domain wechselt – und bei einer harmlosen Mail nicht anschlägt. Zusätzlich Heuristiken wie Schriftsystem-Mischung in einem Wort.

**7. „Wie gehen Sie sicher mit einem Phishing-Link um?“**
Nie im normalen Browser öffnen. Tracking-Parameter entfernen (in Mail 1 stand die Opfer-Adresse Base64-kodiert im Link). Erst passiv mit urlscan.io (privat) oder VirusTotal, dann isoliert in einer VM über VPN mit `curl`, ohne JavaScript-Ausführung.

**8. „Was raten Sie einem KMU nach diesem Vorfall?“**
SPF mit `-all`, DKIM und DMARC bis `p=reject`; 2FA für alle Provider-Konten; Mitarbeitende schulen, Absenderadressen auszuklappen und sich nie über Mail-Links einzuloggen; Abwesenheitsnotizen nur intern. Und für eigene Websites: PHP/CMS aktuell halten, sonst wird man selbst – wie `organicaf.com.ar` – zur Versandplattform für Phishing.

**9. „Was ist der Unterschied zwischen IOC und TTP?“**
IOC = konkretes Artefakt (IP `159.89.53[.]82`). TTP = Verhalten (Versand über kompromittierte Webserver per PHP-Skript, Hidden Text Salting). IOCs veralten in Tagen, TTPs bleiben über Kampagnen hinweg stabil.

**10. „Welche MITRE-Techniken haben Sie gesehen?“**
T1566.002 (Phishing-Link), T1598.003 (Phishing for Information), T1036 (Masquerading), T1027 (Obfuscation), T1583.006 (Web Services – AWS S3), T1584 (Compromise Infrastructure – gehackte Website).
