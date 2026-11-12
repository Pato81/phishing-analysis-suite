# Testkorpus — ein Fall je Heuristik (+ Realfälle)

Synthetische `.eml`-Dateien zur Funktionsbestätigung von PhishScan (H1–H11).
**Alle Werte sind harmlos:** Dokumentationsdomains (`example`, `example.com`,
`example.net/org`) und als „öffentliche" Absender-IPs nur bekannte
Public-Resolver (`8.8.8.8`, `1.1.1.1`, `2606:4700:4700::1111`). In Realfällen
sind personenbezogene Daten geschwärzt. Nichts kontaktiert irgendetwas.

Soll-Ergebnisse (PhishScan **1.2.0**):

| Datei | Urteil | Score | Bestätigt |
|---|---|---|---|
| `h1-sender-punycode.eml` | SUSPICIOUS | 4 | H1 Punycode/IDN im Absender (HIGH) |
| `h2-display-mismatch.eml` | SUSPICIOUS | 4 | H2 Marke im Anzeigenamen, Domain fremd (HIGH) |
| `h3-replyto-mismatch.eml` | SUSPICIOUS | 5 | H3 Reply-To **und** Return-Path fremd |
| `h4-auth-fail.eml` | SUSPICIOUS | 7 | H4 DMARC fail (HIGH) + DKIM/SPF fail; schlechtester Wert schlägt gefälschten `pass`-Zusatzheader |
| `h5-url-tricks.eml` | HIGH RISK | 10 | H5 Punycode-Link, IP-Host, Shortener, Anchor≠Href |
| `h5b-userinfo.eml` | SUSPICIOUS | 5 | H5 URL mit eingebettetem `@` (Userinfo-Trick, HIGH) |
| `h6-hidden-text.eml` | LOW RISK | 2 | H6 versteckter Text ohne Link → LOW |
| `h7-urgency.eml` | LOW RISK | 3 | H7 Dringlichkeits-/Credential-Sprache |
| `h8-attachments.eml` | HIGH RISK | 13 | H8 RTLO, Doppelendung, `.exe`, `.zip` — ein Finding je Anhang |
| `h9-origin-ips.eml` | LOW RISK | 3 | H9 öffentliche IPv4+IPv6 + `X-PHP-Script` |
| `h10-html-base64.eml` | LOW RISK | 3 | H10 nur HTML + base64-HTML-Body |
| `h11-brand-text.eml` | SUSPICIOUS | 4 | H11 Marke **im Betreff** bei fremder Domain |
| `clean-reference.eml` | CLEAN | 0 | Referenz: keine Phishing-Merkmale |
| `flixbus-benign.eml` | LOW RISK | 1 | **Realfall** (legitimer Newsletter, Empfänger geschwärzt): darf NICHT als SUSPICIOUS gelten |

## Nutzung

```bash
python3 phishscan.py samples/*.eml          # alle auf einmal
python3 phishscan.py --selftest             # 48 interne Kernfunktions-Checks
```

## Beispiel-Galerie

Alle 14 Fälle als „Postfach-Ansicht" mit Erklärung und Urteil: [`BEISPIELE.html`](BEISPIELE.html) (im Browser öffnen bzw. als PDF drucken).
