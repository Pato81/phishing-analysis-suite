# Kampagnen-Vergleich: Mail 1 vs. Mail 2

**Frage:** Sind die beiden Mails Zufall – oder stammen sie vom selben Angreifer bzw. demselben Phishing-Kit?

**Antwort:** Mit hoher Wahrscheinlichkeit **dasselbe Kit / derselbe Akteur**, mit **wechselnder Infrastruktur**. Die Belege sind technische Fingerabdrücke, die zu spezifisch für einen Zufall sind.

---

## 1. Gegenüberstellung

| Merkmal | Mail 1 – „Sicherheitsinformation“ | Mail 2 – „Rechnung bereit“ | Gleich? |
|---|---|---|---|
| Datum | 21.09.2026 | 01.10.2026 (10 Tage später) | – |
| Köder | Sicherheitsticket (Angst) | Rechnung 148 € (Irritation) | ✗ |
| From-Domain | `xn--inos-0nd.xn--om-dma` → `iοnos.čom` | `xn--inos-0nd.xn--om-ula` → `iοnos.ćom` | **Schema ✓** |
| Second-Level-Teil | `iοnos` mit griech. Omikron | **identisch** | **✓** |
| TLD-Trick | `č` (Hatschek) | `ć` (Akut) | Variation |
| Anzeigename | `l O N Ο S Kundenservice` | `Kundenservice l O N O S #f5648779 ✔️` | Schema ✓ |
| Zero-Width-Zeichen im Betreff | ✓ (6) | ✓ (8) | **✓** |
| Hidden-Text-Style | `font-size:0; line-height:0; max-height:0; max-width:0; overflow:hidden; color:transparent; display:inline; mso-hide:all` | **zeichengenau dieselben Eigenschaften** | **✓** |
| Menge Hidden Text | 4 Fragmente | 439 Füllwörter | Ausbaustufe |
| Homoglyphen im Text | Kyrillisch `е`, `с` | Kyrillisch `е`, `о`, `р`, `с` + Griechisch | **✓** |
| Message-ID-Format | `<Unix-ts>.<32 hex>@campaign` | `<Unix-ts>.<32 hex>@organicaf.com.ar` | **✓** |
| Envelope-Local-Part | `bvacanhshbfhjjv` (Zufall) | `jzwnzojirosrshrjcyp` (Zufall) | **✓** |
| Envelope-Domain | `theprintfranchise.com` | `organicaf.com.ar` | ✗ (rotiert) |
| Versand | Plesk-VPS, Postfix | cPanel-Shared-Hosting, Exim + PHP | ✗ (rotiert) |
| Nur HTML, kein Text-Teil | ✓ | ✓ | **✓** |
| Link-Hosting | AWS S3 (Seoul) | Google-Redirect | ✗ (rotiert) |
| Tracking im Link | Opfer-Adresse Base64 sichtbar | verschlüsselt/unklar | – |
| Template | minimal, selbst geschrieben | geklontes Original-Template | ✗ |

## 2. Interpretation

**Was gleich bleibt, ist der Code des Kits:** die Funktion, die Absender und Betreffe mit Homoglyphen und Zero-Width-Zeichen versieht, die Funktion, die Text mit versteckten `<span>`s zerstückelt (gleicher Style-String), und der Generator für Message-IDs und Zufalls-Absender.

**Was wechselt, ist alles, was blockiert werden kann:** Versandserver, Envelope-Domains, Link-Ziele, Lookalike-TLD. Das ist **bewusstes Infrastruktur-Rotieren**: Sobald eine Domain oder IP auf einer Blocklist steht, wird die nächste genutzt.

**Folge für die Abwehr:** IOC-Blocklisten (IP, Domain, URL) helfen nur kurzfristig. Langfristig wirksam ist die Erkennung der **Verhaltensmerkmale** (Kit-Fingerprint), siehe [04-detection-abwehr.md](04-detection-abwehr.md). Das ist der Kern der **„Pyramid of Pain“** (David Bianco):

```
              ▲  TTPs                  ← schwer zu ändern für den Angreifer
             ▲▲  Tools (Kit-Code)      ← Style-String, Message-ID-Format
            ▲▲▲  Netzwerk-/Host-Artefakte
           ▲▲▲▲  Domains               ← rotiert zwischen Mail 1 und 2
          ▲▲▲▲▲  IP-Adressen           ← rotiert
         ▲▲▲▲▲▲  Hashes                ← durch Hash-Busting nutzlos gemacht
```

Je weiter oben wir erkennen, desto mehr „Schmerz“ verursachen wir dem Angreifer, weil er sein Werkzeug umbauen muss statt nur einen neuen Server zu mieten.

## 3. Entwicklung zwischen den Mails

Mail 2 wirkt wie eine **ausgereiftere Version**: geklontes Original-Layout statt Minimal-HTML, 100-mal mehr Fülltext, eingebettete Bilder, Buttons als Bild, Link hinter Google statt direkt auf S3. Ob das eine Weiterentwicklung desselben Akteurs ist oder zwei Kunden desselben Phishing-as-a-Service-Kits mit unterschiedlichen Templates, lässt sich aus zwei Mails nicht sicher sagen.

## 4. Zeitachse

| Datum (UTC) | Ereignis |
|---|---|
| 18.09.2026 10:51 | Erstellungszeit in der Message-ID von Mail 1 (Kampagne vorbereitet) |
| 21.09.2026 14:25 | **Mail 1** von `217.154.61[.]83` versendet, IONOS → Spam |
| 01.10.2026 10:18 | **Mail 2**: `45.89.60[.]94` ruft PHP-Mailer auf `organicaf[.]com[.]ar` auf, Versand über `159.89.53[.]82`, IONOS → Spam |
| 19.10.2026 | Analyse beider Mails (dieses Repository) |
