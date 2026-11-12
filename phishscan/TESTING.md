# PhishScan — Testdokumentation

Diese Datei dokumentiert, wie PhishScan getestet und validiert wurde. Sie
begleitet die Version **1.2.0**.

## 1. Teststrategie

Drei Ebenen, die sich ergänzen:

1. **Selftest (Unit-Ebene)** — `--selftest` prüft die Kernfunktionen einzeln,
   ohne Mails: IP-Validierung (IPv4/IPv6, privat/CGNAT/reserved), Punycode-
   Dekodierung, Confusable-Erkennung, Anhang-Klassifizierung, Auth-Auswertung,
   Host-/Domain-Hilfen, Score/Urteil-Logik sowie die FP-Fixes aus 1.2.0.
   **Stand: 48/48 bestanden.**
2. **Heuristik-Korpus (Funktions-Ebene)** — je eine synthetische `.eml` pro
   Heuristik H1–H11 (plus Userinfo-Variante und ein CLEAN-Referenzfall). Jede
   Datei belegt, dass der zugehörige Detektor auslöst. Siehe `samples/README.md`.
3. **Realfall (Falsch-Positiv-Ebene)** — eine echte, legitime Marketing-Mail
   (`flixbus-benign.eml`, Empfänger geschwärzt) prüft, ob das Tool bei seriöser
   Massenpost ruhig bleibt.

Alle Testdaten sind harmlos: Dokumentationsdomains und bekannte Public-Resolver-
IPs; keine Datei kontaktiert irgendetwas, das Tool arbeitet rein offline.

## 2. Selftest ausführen

```bash
python3 phishscan.py --selftest
# -> 48/48 Pruefungen bestanden. Selftest OK.
```

## 3. Heuristik-Korpus

```bash
python3 phishscan.py samples/*.eml
```

Ergebnis (Soll = Ist, PhishScan 1.2.0):

| Heuristik | Datei | Urteil | belegt |
|---|---|---|---|
| H1 | `h1-sender-punycode.eml` | SUSPICIOUS | Punycode/IDN im Absender |
| H2 | `h2-display-mismatch.eml` | SUSPICIOUS | Marke im Anzeigenamen, Domain fremd |
| H3 | `h3-replyto-mismatch.eml` | SUSPICIOUS | Reply-To & Return-Path fremd |
| H4 | `h4-auth-fail.eml` | SUSPICIOUS | SPF/DKIM/DMARC fail, schlechtester Wert gewinnt |
| H5 | `h5-url-tricks.eml`, `h5b-userinfo.eml` | HIGH / SUSPICIOUS | Punycode, IP-Host, Shortener, Anchor≠Href, Userinfo-@ |
| H6 | `h6-hidden-text.eml` | LOW | versteckter Text (ohne Link → LOW) |
| H7 | `h7-urgency.eml` | LOW | Dringlichkeits-/Credential-Sprache |
| H8 | `h8-attachments.eml` | HIGH | RTLO, Doppelendung, `.exe`, `.zip` |
| H9 | `h9-origin-ips.eml` | LOW | öffentliche IPv4+IPv6, `X-PHP-Script` |
| H10 | `h10-html-base64.eml` | LOW | nur HTML + base64-HTML |
| H11 | `h11-brand-text.eml` | SUSPICIOUS | Marke im Betreff bei fremder Domain |
| — | `clean-reference.eml` | CLEAN | Negativtest |

## 4. Fallstudie: Falsch-Positiv gefunden und behoben

**Befund.** Eine legitime FlixBus-Newsletter-Mail wurde von Version 1.1.0 als
`SUSPICIOUS` (Score 4) eingestuft — zwei Fehlalarme:

- **H6** feuerte auf ~30.000 Zeichen „versteckten Text". Ursache: der
  **Preheader** (Vorschautext) und responsives Mobil/Desktop-Umschalten per
  `display:none` — Standard in *jeder* seriösen Marketing-Mail.
- **H11** feuerte auf das Wort „apple". Ursache: ein legitimer **App-Store-
  Downloadlink** und Apple-typische CSS-Hacks (`a[x-apple-data-detectors]`).

**Fix (1.2.0).**

- **H6** wertet versteckten Text nur noch als MEDIUM, wenn dieser **selbst
  Link(s) oder ≥2 Dringlichkeitsbegriffe** enthält (echtes Salting). Reiner
  Vorschautext fällt auf LOW.
- **H11** feuert nur noch, wenn die Marke im **Betreff** steht (prominente
  Impersonation). Der Anzeigename gehört zu H2 — das vermeidet außerdem eine
  Doppelzählung desselben Signals.

**Ergebnis.**

| | 1.1.0 | 1.2.0 |
|---|---|---|
| `flixbus-benign.eml` | SUSPICIOUS (Score 4) | **LOW RISK (Score 1)** |
| alle 11 Phishing-Fixtures | erkannt | **weiterhin erkannt** |
| Selftest | 44/44 | **48/48** (inkl. Regressionstests für beide Fixes) |

Die Verbesserung reduziert Fehlalarme bei legitimer Massenpost, ohne die
Erkennung echter Phishing-Merkmale zu schwächen.

## 5. Reproduzierbarkeit

```bash
python3 phishscan.py --version      # PhishScan 1.2.0
python3 phishscan.py --selftest     # 48/48
python3 phishscan.py samples/*.eml  # Urteile wie in Abschnitt 3 / samples/README.md
```
