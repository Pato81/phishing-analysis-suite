# Infrastruktur-Analyse

Passive Threat Intelligence zu den IPs und Domains beider Mails.

**Leitfrage:** Wem gehört die Infrastruktur, über die die Angriffe liefen, und was verrät das über den Angreifer?

**Regeln dieser Phase:**
- Nur **öffentliche Register** abfragen (whois/RIPE/ARIN, DNS). Diese Daten liegen bei den Registries, nicht beim Angreifer.
- **Kein Kontakt** mit der Angreifer-Infrastruktur: kein Ping, kein Portscan, kein Aufruf der Links.
- Jeder Befund wird mit Befehl, Rohdaten-Auszug und Interpretation dokumentiert, damit er reproduzierbar ist.

Analyse-Workstation: Kali Linux („Gaia“), Lookups am 2026-10-19.

> In Befehlen stehen IPs unverändert, damit sie reproduzierbar sind. Im Fließtext sind sie entschärft (`[.]`). Die Hoster und Website-Betreiber sind überwiegend selbst Opfer (missbrauchte VPS, gehackte Sites).

---

## 0. Werkzeuge und Syntax

### 0.1 `whois` – wem gehört eine IP?

```bash
whois <IP-Adresse>
```

**Was passiert dabei:** Jede öffentliche IP-Adresse ist von einer der fünf **Regional Internet Registries (RIRs)** an eine Organisation vergeben:

| RIR | Region | Im Fall |
|---|---|---|
| **RIPE NCC** | Europa, Naher Osten, Zentralasien | `217.154.61.83`, `45.89.60.94` |
| **ARIN** | Nordamerika | `159.89.53.82` |
| APNIC | Asien-Pazifik | – |
| LACNIC | Lateinamerika | – |
| AFRINIC | Afrika | – |

Der `whois`-Client erkennt anhand der IP, welche RIR zuständig ist, und fragt deren Datenbank ab (Port 43/TCP). Man sieht das am Kopf der Ausgabe: `% This is the RIPE Database query service` bzw. `# ARIN WHOIS data`.

**Nützliche Optionen:**

| Option | Wirkung |
|---|---|
| `whois -B <IP>` | RIPE: ungefilterte Ausgabe (inkl. Kontaktdaten, die sonst ausgeblendet werden – „this output has been filtered“) |
| `whois -h whois.ripe.net <IP>` | eine bestimmte Datenbank direkt abfragen |
| `whois AS<Nummer>` | Informationen zu einem Autonomen System (wer routet den Netzblock?) |
| `whois <IP> \| grep -Ei 'netname\|org\|country\|abuse\|origin\|created'` | nur die Kernfelder herausfiltern |

**Die wichtigsten Felder:**

| RIPE | ARIN | Bedeutung |
|---|---|---|
| `inetnum` | `NetRange` / `CIDR` | der zugewiesene IP-Bereich |
| `netname` | `NetName` | interner Name des Netzes, oft mit Hinweis auf Standort/Zweck |
| `descr` / `org` | `Organization` | Eigentümer bzw. Inhaber des Bereichs |
| `country` | `Country` | Land laut Registrierung (≠ zwingend physischer Standort!) |
| `abuse-c` / `abuse-mailbox` | `OrgAbuseEmail` | **wohin Missbrauch gemeldet wird** |
| `origin` (im `route`-Objekt) | `OriginAS` | das **Autonome System (ASN)**, das den Bereich im Internet ankündigt |
| `created` | `RegDate` | seit wann es den Eintrag gibt |
| `mnt-by` | – | „Maintainer“: wer den Eintrag pflegen darf, oft der tatsächliche Betreiber |
| `status: ASSIGNED PA` | `NetType` | PA = „Provider Aggregatable“: Teil eines größeren Blocks, an einen Kunden weitergegeben |

### 0.2 `dig -x` – Reverse DNS (PTR)

```bash
dig -x <IP-Adresse> +short
```

| Teil | Bedeutung |
|---|---|
| `dig` | DNS-Abfragewerkzeug (Domain Information Groper) |
| `-x` | **Reverse Lookup:** dreht die IP um und fragt den PTR-Record ab. Aus `217.154.61.83` wird intern die Abfrage `83.61.154.217.in-addr.arpa PTR` |
| `+short` | nur das Ergebnis ausgeben, ohne Header, Question- und Authority-Section |

**Warum das wichtig ist:** Der PTR ist der „Name“, den der Betreiber der IP gegeben hat. Er verrät oft Hoster, Servertyp oder Kunden (`web04.dinardi...` = Webserver Nr. 4). **Kein PTR** ist ebenfalls ein Befund: Mailserver und Firmennetze haben fast immer einen, Wegwerf-VPS und Proxy-Netze oft nicht.

Ausführliche Variante ohne `+short`, wenn man den antwortenden Nameserver und die TTL sehen will:
```bash
dig -x 217.154.61.83
```

### 0.3 Reihenfolge pro Indikator

```
1. whois <IP>          → Eigentümer, Netzblock, Land, ASN, Abuse-Kontakt
2. dig -x <IP> +short  → PTR (vergleichen mit dem Hostnamen aus dem Mail-Header!)
3. whois AS<ASN>       → wer routet den Block tatsächlich?
4. Abgleich mit der Mail-Analyse und Interpretation
```

---

## 1. Versand-IP Mail 1 — `217.154.61[.]83`

**Herkunft im Fall:** Erster vertrauenswürdiger `Received`-Header von Mail 1. Dieser Server hat die Mail an IONOS eingeliefert. Hostname laut Header: `brave-ganguly.217-154-61-83.plesk.page` (Postfix, Plesk-Systemuser `10003`).

### Befehle
```bash
whois 217.154.61.83
dig -x 217.154.61.83 +short
```

### Rohdaten (Auszug)
```
% Information related to '217.154.56.0 - 217.154.63.255'
% Abuse contact for '217.154.56.0 - 217.154.63.255' is 'abuse@ionos.com'

inetnum:        217.154.56.0 - 217.154.63.255
netname:        gb-wtr-ionos-cloud-bhx1
descr:          IONOS SE
country:        GB
status:         ASSIGNED PA
mnt-by:         AS8560-MNT
created:        2025-02-10T17:20:00Z

route:          217.154.56.0/21
descr:          IONOS SE
origin:         AS8560

--- dig -x ---
ip217-154-61-83.pbiaas.com.
```

### Befund

| Feld | Wert |
|---|---|
| Netzblock | `217.154.56.0/21` (2.048 Adressen) |
| netname | `gb-wtr-ionos-cloud-bhx1` |
| Eigentümer | IONOS SE |
| Land | GB |
| ASN | `AS8560` (IONOS) |
| Abuse-Kontakt | `abuse@ionos.com` |
| Netzblock erstellt | 2025-02-10 |
| PTR heute | `ip217-154-61-83.pbiaas.com` |
| Hostname im Mail-Header | `brave-ganguly.217-154-61-83.plesk.page` |

### Interpretation
- **`netname` entschlüsselt:** `gb` = Großbritannien, `ionos-cloud` = IONOS-Cloud-Produkt, `bhx1` = Rechenzentrum mit IATA-Code **BHX** (Birmingham). Die Mail kam also von einem **IONOS-Cloud-VPS in Birmingham**.
- **Die Ironie:** Das Phishing gibt sich als IONOS aus und wurde über **IONOS-eigene Cloud-Infrastruktur** verschickt. Der Angreifer hat dort einen VPS gemietet (möglicherweise mit gestohlenen Zahlungsdaten) oder einen bestehenden übernommen. Aus den Registerdaten lässt sich das nicht unterscheiden.
- **PTR-Wechsel:** Zum Versandzeitpunkt hieß der Host `brave-ganguly...plesk.page` (automatisch generierter Plesk-Name, Muster `<adjektiv>-<nachname>`). Heute löst die IP auf den generischen IONOS-Namen `ip217-154-61-83.pbiaas.com` auf. **Der VPS wurde seit dem 21.09. gelöscht oder neu vergeben.** Das ist typisch für Wegwerf-Infrastruktur: Server mieten, eine Kampagne fahren, wegwerfen.
- **Meldeweg:** `abuse@ionos.com`, mit IP, Zeitstempel (21.09.2026 14:25 UTC) und vollständigen Headern.

---

## 2. Versand-IP Mail 2 — `159.89.53[.]82`

**Herkunft im Fall:** Erster vertrauenswürdiger `Received`-Header von Mail 2. Hostname laut Header: `web04.dinardi.com.ar` (Exim, cPanel-User `organica`, Zeitzone `-0300`).

### Befehle
```bash
whois 159.89.53.82
dig -x 159.89.53.82 +short
```

### Rohdaten (Auszug)
```
NetRange:       159.89.0.0 - 159.89.255.255
CIDR:           159.89.0.0/16
NetName:        DIGITALOCEAN-159-89-0-0
NetType:        Direct Allocation
Organization:   DigitalOcean, LLC (DO-13)
RegDate:        2017-07-07
Comment:        Routing and Peering Policy can be found at https://www.as14061.net
Comment:        Please submit abuse reports at https://www.digitalocean.com/company/contact/#abuse

OrgName:        DigitalOcean, LLC
Country:        US
OrgAbuseEmail:  abuse@digitalocean.com

--- dig -x ---
web04.dinardi.com.ar.
```

### Befund

| Feld | Wert |
|---|---|
| Netzblock | `159.89.0.0/16` (65.536 Adressen) |
| NetName | `DIGITALOCEAN-159-89-0-0` |
| Eigentümer | DigitalOcean, LLC |
| Land | US (Firmensitz; das Rechenzentrum kann woanders stehen) |
| ASN | `AS14061` (aus dem Kommentarfeld, `OriginAS` leer) |
| Abuse-Kontakt | `abuse@digitalocean.com` bzw. Webformular |
| PTR heute | `web04.dinardi.com.ar` |
| Hostname im Mail-Header | `web04.dinardi.com.ar` |

### Interpretation
- **ARIN statt RIPE:** DigitalOcean ist ein US-Unternehmen, die Adressen kommen von ARIN. Achtung: `OriginAS` ist leer. Die ASN `AS14061` steht nur im Kommentar. Bei ARIN muss man solche Felder mitlesen.
- **Die Schichten:** DigitalOcean vermietet ein Droplet (VPS) an einen **argentinischen Hosting-Reseller** (`dinardi.com.ar`). Der betreibt darauf einen **cPanel-Shared-Hosting-Server**. Einer seiner Kunden ist `organicaf[.]com[.]ar`, dessen Webspace gehackt wurde.
- **`web04` = Webserver Nr. 4** einer Shared-Hosting-Flotte. Auf so einer Maschine liegen meist Dutzende bis Hunderte Kundensites. Eine veraltete Site (hier PHP 7.2, EOL) reicht, um den ganzen Server zur Versandplattform zu machen.
- **PTR unverändert:** Anders als bei Mail 1 ist das kein Wegwerf-Server, sondern ein **legitimer, langlebiger Server**, der missbraucht wurde. Genau deshalb hatte Mail 2 `spf=pass`.
- **Meldewege (zwei):** `abuse@digitalocean.com` (Infrastruktur) **und** der Reseller `dinardi.com.ar`, der den kompromittierten cPanel-Account `organica` bereinigen und das Skript `/public_html/e556b83c/m340d483a.php` entfernen muss.

---

## 3. Angreifer-IP — `45.89.60[.]94`

**Herkunft im Fall:** Nicht aus einem `Received`-Header, sondern aus dem cPanel-Header von Mail 2:

```
X-PHP-Script: organicaf.com.ar/e556b83c/m340d483a.php for 45.89.60.94
```

cPanel schreibt diesen Header automatisch, um nachvollziehbar zu machen, **welches PHP-Skript** eine Mail erzeugt hat und **welche Client-IP** dieses Skript per HTTP aufgerufen hat. `45.89.60[.]94` ist also die Verbindung, **von der aus der Angreifer den Versand ausgelöst hat**. Damit ist sie der einzige Indikator im ganzen Fall, der zur Infrastruktur des Angreifers selbst gehört und nicht zu einem Opfer.

### Befehle
```bash
whois 45.89.60.94
dig -x 45.89.60.94 +short
```

### Rohdaten (Auszug)
```
% Abuse contact for '45.89.60.0 - 45.89.60.255' is 'abuse@globconnex.com'

inetnum:        45.89.60.0 - 45.89.60.255
netname:        GCS_SER-NET
country:        AL
org:            ORG-GCSL7-RIPE
status:         ASSIGNED PA
mnt-by:         MNT-DGTL
mnt-by:         inettech-mnt
created:        2026-02-27T12:06:33Z

organisation:   ORG-GCSL7-RIPE
descr:          Global Connectivity Solutions
org-name:       GLOBAL CONNECTIVITY SOLUTIONS LLP
country:        GB
reg-nr:         OC450701
address:        Suite 310, 21 Hill Street, Haverfordwest, Pembrokeshire, SA61 1QQ
remarks:        -----CUSTOMERS-----
mnt-ref:        AM-VDS
mnt-ref:        proxy-six-mnt
mnt-ref:        VPSVILLE-mnt
mnt-ref:        IPMAGNAT-MNT
mnt-ref:        interlir-mnt
mnt-ref:        sc-rapidseedbox-1-mnt
  ... (über 50 Kunden-Maintainer, gekürzt)
created:        2024-01-25T10:49:19Z

route:          45.89.60.0/24
origin:         AS215540
created:        2026-02-27T14:12:54Z
mnt-by:         INETTECH-MNT

--- dig -x ---
(keine Ausgabe – kein PTR-Record)
```

### Befund

| Feld | Wert |
|---|---|
| Netzblock | `45.89.60.0/24` (256 Adressen) |
| netname | `GCS_SER-NET` |
| Land des Netzblocks | **AL** (Albanien) |
| Inhaber-Organisation | Global Connectivity Solutions LLP |
| Land der Organisation | **GB** (Registrierungsnummer `OC…` = britische LLP) |
| Netzblock erstellt | **2026-02-27** |
| Route / ASN | `45.89.60.0/24`, `AS215540`, gepflegt von `INETTECH-MNT` |
| Maintainer | `MNT-DGTL`, `inettech-mnt` |
| Abuse-Kontakt | `abuse@globconnex.com` |
| PTR | **keiner** |

### Interpretation

**Ein Muster aus drei Ländern.** Inhaber in Großbritannien, Netzblock auf Albanien registriert, geroutet von einem weiteren Betreiber (`AS215540` / `INETTECH-MNT`). So eine Diskrepanz ist typisch für **IP-Leasing**: Eine Firma hält IPv4-Bestände und vermietet sie blockweise an Kunden weiter, die sie dann über ihr eigenes AS ankündigen.

**Die Kundenliste ist das Aufschlussreichste.** Unter `-----CUSTOMERS-----` stehen über 50 Maintainer, darunter Namen, die auf **VPS-Anbieter** (`AM-VDS`, `VPSVILLE`), **Proxy-Dienste** (`proxy-six`), **Seedboxen** (`rapidseedbox`) und **IP-Broker** (`IPMAGNAT`, `interlir`) hindeuten. IP-Leasing ist ein legales Geschäftsmodell. Netze dieser Art sind aber häufig die Grundlage für günstige VPS und Proxys, die Angreifer bevorzugen, weil sie schnell, anonym und billig sind.

**Kein PTR.** Ein Privatanschluss oder Firmennetz hätte fast immer einen Reverse-DNS-Namen. Das Fehlen passt zu einem **gemieteten VPS oder Proxy-Endpunkt**.

**Der Block ist neu.** Erstellt am 27.02.2026, also rund **sieben Monate vor dem Angriff**. Junge Netzblöcke stehen noch auf wenigen Reputationslisten. Für Detection-Teams ist „Alter des Netzblocks“ deshalb ein nützliches Signal.

**Was das heißt – und was nicht:**

| Aussage | Bewertung |
|---|---|
| Der Angreifer hat den Mailer von gemieteter Infrastruktur aus aufgerufen, nicht von seinem Heimanschluss | **wahrscheinlich** (kein PTR, Leasing-Netz, VPS/Proxy-Kunden) |
| Die IP führt zur Person des Angreifers | **nein**, ohne Daten des Endkunden (die nur der Betreiber bzw. Strafverfolgung bekommt) |
| Global Connectivity Solutions oder der Routing-Betreiber sind beteiligt | **kein Hinweis**. Sie sind Vermieter, wahrscheinlich ohne Kenntnis |
| Weitere Aktivität aus `45.89.60.0/24` ist verdächtig | **begründet**, als Hunting-Ansatz für Logs |

**Interview-Kernsatz:** *„Die IP aus `X-PHP-Script` ist der wertvollste Indikator, weil sie die Angreiferseite zeigt. Die whois-Daten zeigen aber ein IP-Leasing-Netz ohne PTR. Der Angreifer hat also selbst eine Zwischenschicht benutzt. Attribution endet hier, der Nutzen liegt in Blocking, Hunting und der Abuse-Meldung.“*

**Meldeweg:** `abuse@globconnex.com` mit IP, Zeitstempel (01.10.2026 10:18 UTC) und dem `X-PHP-Script`-Header. Der Vermieter kann den zugehörigen Endkunden identifizieren, wir nicht.

### 3.1 Routing-Ebene — `AS215540`

**Befehl:**
```bash
whois AS215540
```
Wir fragen hier ein **Autonomes System** ab (ein `aut-num`-Objekt) statt einer IP. Ein AS ist eine Verwaltungseinheit im Internet-Routing, die über BGP ihre Netzblöcke ankündigt. Die `import:`/`export:`-Zeilen zeigen die **Routing-Beziehungen**: von wem das AS Routen annimmt (Upstreams/Peers) und an wen es seine eigenen ankündigt.

**Rohdaten (Auszug):**
```
aut-num:        AS215540
as-name:        GCS-AS
org:            ORG-GCSL7-RIPE          (Global Connectivity Solutions LLP, GB)
sponsoring-org: ORG-LT104-RIPE          (sponsernder LIR, Litauen)
import: from AS174    accept ANY        export: to AS174    announce AS215540
import: from AS207713 accept ANY        export: to AS207713 announce AS215540
import: from AS44222  accept ANY        export: to AS44222  announce AS215540
import: from AS49542  accept ANY        ...
import: from AS48014  accept ANY        ...
import: from AS209847 accept ANY        ...
import: from AS39900  accept <AS39900>  export: to AS39900  announce ANY
import: from AS26383  accept <AS26383>  export: to AS26383  announce ANY
created:        2024-02-09
mnt-by:         RIPE-NCC-END-MNT, GCS-MNT
```

**Befund und Interpretation:**

| Beobachtung | Bedeutung |
|---|---|
| `org` = dieselbe wie beim Netzblock | GCS besitzt **sowohl den IP-Block als auch das AS** und kündigt ihn selbst an. Meine frühere Vermutung „dritter Routing-Betreiber“ war falsch — `INETTECH-MNT` pflegt nur das `route:`-Objekt des `/24`, der Ursprung ist GCS. |
| `sponsoring-org: ORG-LT104-RIPE` | Die ASN-Registrierung wird von einem **litauischen LIR** gesponsert. Noch ein Land in der Kette (GB Inhaber, AL Netzblock, LT Sponsor). |
| `import: from AS174 accept ANY` | **AS174 = Cogent**, ein globaler Tier-1-Transitprovider. GCS kauft dort Transit ein. Das ist der Weg, über den der Verkehr ins „große“ Internet kommt. |
| `export: to AS39900 / AS26383 announce ANY` | GCS ist für diese beiden AS selbst **Upstream**, gibt ihnen also Vollroute. GCS betreibt somit eine kleine Transit-Hierarchie, kein reines Endkundennetz. |
| `created: 2024-02-09` | Das AS ist jung (gut zwei Jahre). |

**Gesamtbild der Angreifer-IP:** `45.89.60[.]94` liegt in einem **selbst-gerouteten Leasing-Netz** (GCS, Transit via Cogent), ohne PTR, in einem jungen `/24`, umgeben von VPS- und Proxy-Kunden. Für einen Angreifer ist so ein Netz attraktiv: schnell buchbar, wenig Reputationshistorie, mehrere Jurisdiktionen in der Kette erschweren Auskunftsersuchen. Die Attribution bleibt bei „gemietete Zwischenschicht“ stehen — was aus Verteidigersicht völlig ausreicht.

---

## Zwischenstand

| IP | Rolle | Betreiber | Land | Typ | Abuse |
|---|---|---|---|---|---|
| `217.154.61[.]83` | Versand Mail 1 | IONOS SE (AS8560) | GB | Cloud-VPS, inzwischen neu vergeben | `abuse@ionos.com` |
| `159.89.53[.]82` | Versand Mail 2 | DigitalOcean (AS14061) → Reseller `dinardi.com.ar` | US / AR | Shared-Hosting, kompromittiert | `abuse@digitalocean.com` + Reseller |
| `45.89.60[.]94` | **Auslöser Mail 2 (Angreifer)** | Global Connectivity Solutions LLP, Route AS215540 | AL / GB | Leasing-Netz, kein PTR, wahrscheinlich VPS/Proxy | `abuse@globconnex.com` |

**Muster:** Drei IPs, drei Betreiber, vier Länder. Der Angreifer hat **keinen einzigen eigenen Server mit seinem Namen** benutzt: einen Cloud-VPS bei der imitierten Marke selbst, einen fremden gehackten Webserver und ein gemietetes Leasing-Netz als Steuerpunkt.
