# PhishScan

> ⚠️ **Passives Analyse-Tool.** PhishScan liest `.eml`-Dateien nur ein und bewertet sie.
> Es stellt **keine Netzwerkverbindungen** her, ruft **keine Links auf** und verändert die
> Eingabedateien nicht. Zur Analyse eigener oder autorisiert erhaltener Mails.

Ein **passiver Phishing-Analyzer** für `.eml`-Dateien als **Python-CLI** (nur Standardbibliothek,
keine Abhängigkeiten). PhishScan prüft eine Mail entlang von **11 Heuristiken (H1–H11)**, die aus
meiner Blue-Team-Fallstudie zur [**IONOS-Homoglyph-Kampagne**](../README.md)
(siehe Repo-Wurzel) abgeleitet sind, vergibt einen Risiko-Score und gibt einen
nachvollziehbaren Report aus.

---

## Warum ich es gebaut habe
Nach der manuellen Analyse zweier echter Phishing-Mails wollte ich die dort erarbeitete Methodik
in ein **wiederholbares, reproduzierbares Werkzeug** gießen – damit sich verdächtige Mails
strukturiert und immer gleich prüfen lassen, statt jedes Mal von vorn.

## Die Heuristiken H1–H11
| ID | Prüfung |
|----|---------|
| **H1** | Homoglyphen / Punycode (IDN) in der **Absenderdomain** |
| **H2** | **Anzeigename nennt eine Marke**, die Absenderdomain passt nicht |
| **H3** | **Reply-To / Return-Path** weicht von der Absenderdomain ab |
| **H4** | **SPF / DKIM / DMARC** nicht bestanden (aus `Authentication-Results`) |
| **H5** | Verdächtige **Links**: Punycode, Homoglyphen, IP-Host, `@`-Userinfo-Trick, Shortener, Text-vs-Ziel-Mismatch |
| **H6** | **Versteckter Text** im HTML (`display:none`, `font-size:0` …) – Filter-/Hash-Busting |
| **H7** | **Dringlichkeits- und Credential-Sprache** (Keyword-Heuristik) |
| **H8** | **Gefährliche Anhänge** und doppelte Dateiendungen |
| **H9** | **Ursprungs-IP(s)** extrahiert + Hinweis auf **PHP-/Skript-Versand** |
| **H10** | **MIME-Auffälligkeiten** (nur HTML ohne Text-Teil, base64-HTML) |
| **H11** | **Markenimitation** im Text bei fremder Absenderdomain |

## Nutzung
```bash
# eine Datei
python3 Phishscan_Pato_v2.0.py verdaechtig.eml

# mehrere Dateien oder ein ganzer Ordner
python3 Phishscan_Pato_v2.0.py mails/

# maschinenlesbar
python3 Phishscan_Pato_v2.0.py verdaechtig.eml --json

# ohne Farben (für Logs/Pipes)
python3 Phishscan_Pato_v2.0.py verdaechtig.eml --no-color

# nur Findings ab einer Stufe anzeigen (Score/Urteil bleiben unberührt)
python3 Phishscan_Pato_v2.0.py verdaechtig.eml --min-severity high

# Integritäts-Selbsttest der Kernfunktionen (ohne Datei-/Netzzugriff)
python3 Phishscan_Pato_v2.0.py --selftest

# Größen-Guard je .eml konfigurieren (Default 25 MB, 0 = aus)
python3 Phishscan_Pato_v2.0.py mails/ --max-size-mb 50
```

Ausgabe je Mail: **Urteil** (`CLEAN` · `LOW RISK` · `SUSPICIOUS` · `HIGH RISK`), Score und die
einzelnen Findings mit Schweregrad. Der **Exit-Code** ist `1`, wenn mindestens eine Mail als
`SUSPICIOUS`/`HIGH RISK` eingestuft wird – praktisch für Skripte.

## Beispiel
```
$ python3 Phishscan_Pato_v2.0.py samples/phish-example.eml
================================================================
PhishScan-Report: samples/phish-example.eml
================================================================
Betreff : Dringend: Ihr Konto wird gesperrt - bitte verifizieren
Von     : IONOS Support <service@iонos-sicherheit.example>
Urteil  : HIGH RISK  (Score 30, 13 Finding(s))
----------------------------------------------------------------
[H1] HIGH    Homoglyphen in Absenderdomain
[H2] HIGH    Anzeigename nennt Marke, Domain passt nicht
[H4] HIGH    DMARC-Pruefung nicht bestanden
[H5] HIGH    Punycode-Domain in Link
[H5] HIGH    Link-Text zeigt andere Domain als das Ziel
...
```
Die mitgelieferten Beispiele liegen unter [`samples/`](samples/) (fiktive Domains und
Doku-IP-Adressen, enthalten keine echten Indikatoren).

## Anforderungen
- **Python 3.9+** – nur Standardbibliothek, **keine Installation von Paketen nötig**.

## Engineering-Highlights
- **Dispatch über 11 eigenständige Heuristik-Funktionen** – jede klar abgegrenzt, einzeln gekapselt (eine kaputte Mail stoppt die Analyse nicht)
- **Rein offline** – keinerlei Netzwerkcode, nachprüfbar im Quelltext
- **Robustes Parsing** über die `email`-Standardbibliothek, mit `policy.compat32`-Fallback bei defekten Mails
- **Unicode-Confusable-Erkennung** für Homoglyph-Domains (H1/H5) inkl. **Punycode-Dekodierung** des Lookalikes
- **Korrekte IP-Herkunft (H9)** via `ipaddress` – nur global routbare **IPv4/IPv6**, private/CGNAT/Loopback/Doku-Präfixe raus
- **RTLO-/Bidi-Erkennung** in Anhangsnamen (H8), Steuerzeichen in der Ausgabe sichtbar gemacht
- **DoS-Guard** (Größen-/Part-/Text-Limits) + **`--selftest`** (44 In-Memory-Prüfungen)
- **JSON-Ausgabe** und sprechender **Exit-Code** für die Einbindung in Pipelines

## Changelog
- **1.1.0** – H9 über `ipaddress` korrigiert (172.16.0.0/12-Bug behoben) + IPv6; H8 keine Doppel-Findings mehr + RTLO-Erkennung; H4 wertet alle Auth-Header aus (schlechtester Wert zählt); DoS-Guards; Punycode-Dekodierung; neue Flags `--selftest` / `--min-severity` / `--max-size-mb`; Sammel-Übersicht bei mehreren Mails.
- **1.0.0** – Erstveröffentlichung (H1–H11).

## Rechtliches & Scope
Nur zur Analyse von Mails, die dir gehören oder die du autorisiert erhalten hast. PhishScan
verarbeitet alles lokal; es werden keine Daten übertragen. Siehe [LICENSE](LICENSE).

---
**Patrick May** · angehender Junior Penetration Tester
[LinkedIn](https://www.linkedin.com/in/patrick-may-664867367) · p.may.1981@web.de
<sub>Teil meines Security-Portfolios · <a href="https://github.com/Pato81">github.com/Pato81</a> · operatives Werkzeug zur <a href="../README.md">Fallstudie in der Repo-Wurzel</a></sub>
