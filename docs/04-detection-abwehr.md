# Detection & Abwehr

Aus der Analyse leiten wir drei Ebenen der Verteidigung ab: **technische Erkennung**, **Härtung der eigenen Domain** und **den Menschen**.

---

## 1. Erkennungsregeln

### 1.1 YARA-Regel für das Phishing-Kit

YARA wird klassisch für Malware genutzt, eignet sich aber genauso, um `.eml`-Dateien nach Mustern zu durchsuchen. Die Regel zielt nicht auf IPs oder Domains (die rotieren), sondern auf den **Fingerabdruck des Kits** (siehe Kampagnen-Vergleich).

Datei: [`../detection/ionos_homoglyph_kit.yar`](../detection/ionos_homoglyph_kit.yar)

```yara
rule Phish_IONOS_Homoglyph_Kit
{
    meta:
        description = "IONOS-Phishing-Kit: Punycode-Lookalike, Hidden-Span-Salting, Message-ID-Muster"
        author      = "Pato81"
        date        = "2026-10-19"
        reference   = "phishing-analysis/docs/03-kampagnen-vergleich.md"

    strings:
        // From-Domain: "iοnos" mit griechischem Omikron als Punycode
        $from_puny   = "@xn--inos-0nd." ascii
        // Hidden-Span-Style (Kernstück des Salting); Mail 1 mit, Mail 2 ohne Leerzeichen
        $hide_a      = "font-size:0; line-height:0; max-height:0; max-width:0;" ascii
        $hide_b      = "font-size:0;line-height:0;max-height:0;max-width:0;" ascii
        $mso_hide    = "mso-hide:all" ascii
        // Message-ID: <10-stelliger Timestamp>.<32 hex>@
        $msgid       = /Message-ID: <1[0-9]{9}\.[0-9a-f]{32}@/ ascii
        // Zero-Width-Zeichen im Betreff (quoted-printable kodiert)
        $zw_200b     = "=E2=80=8B" ascii
        $zw_200c     = "=E2=80=8C" ascii
        $zw_200d     = "=E2=80=8D" ascii
        $zw_2060     = "=E2=81=A0" ascii
        $zw_feff     = "=EF=BB=BF" ascii
        // Griechisches Omikron (U+039F) quoted-printable – "lΟNΟS"
        $omikron     = "=CE=9F" ascii

    condition:
        $from_puny
        or ( $msgid and ($hide_a or $hide_b) and $mso_hide )
        or ( ($hide_a or $hide_b) and $omikron and 2 of ($zw_*) )
}
```

**Testlauf gegen beide Mails:**
```bash
yara -s detection/ionos_homoglyph_kit.yar mail1.eml mail2.eml
```

### 1.2 Allgemeine Heuristiken (kitunabhängig)

Diese Signale sind auch bei anderen Kampagnen nützlich. Einzeln sind sie schwach, **in Kombination stark**:

| # | Signal | Gewicht | Fehlalarm-Risiko |
|---|---|---|---|
| H1 | From-Domain enthält Punycode (`xn--`) | hoch | gering im DACH-Raum, Umlaut-Domains (`xn--`) existieren aber |
| H2 | Anzeigename enthält Markennamen, From-Domain gehört nicht der Marke | hoch | gering |
| H3 | Ein Wort mischt Schriftsysteme (Latein + Kyrillisch/Griechisch) | hoch | sehr gering |
| H4 | Zero-Width-Zeichen in Betreff oder Absendername | hoch | gering |
| H5 | Elemente mit `font-size:0` + `color:transparent`, die **Text enthalten** | hoch | mittel (manche Newsletter nutzen Preheader-Tricks) |
| H6 | Nur `text/html`, kein `text/plain` | niedrig | mittel |
| H7 | Envelope-Domain ≠ From-Domain | niedrig | hoch (Newsletter-Dienste) |
| H8 | Link auf bekannte Redirect-/Hosting-Dienste (`google.com/goto`, `*.s3.*.amazonaws.com`, `*.web.app` …) | mittel | mittel |
| H9 | Link-Parameter enthält Base64 der Empfängeradresse | hoch | gering |
| H10 | Header `X-PHP-Script` vorhanden (Mail aus Website-Skript) | mittel | mittel |
| H11 | Linktext/Button ist ein Bild ohne Text | niedrig | hoch |

Genau diese Heuristiken werden später das **Bewertungsmodul unseres Analyse-Tools**.

### 1.3 Python-Beispiel: Schriftsystem-Mischung erkennen (H3)

```python
import unicodedata, re

def mixed_script_words(text: str) -> list[str]:
    """Findet Wörter, die lateinische mit kyrillischen/griechischen Zeichen mischen."""
    hits = []
    for word in re.findall(r"\w+", text):
        scripts = set()
        for ch in word:
            if ch.isalpha():
                name = unicodedata.name(ch, "")
                scripts.add(name.split()[0])   # LATIN, CYRILLIC, GREEK ...
        if len(scripts) > 1:
            hits.append(word)
    return hits

print(mixed_script_words("Sehr geehrtе Kundin, Ihr lΟNΟS-Team"))
# ['geehrtе', 'lΟNΟS']
```

### 1.4 Testergebnis

| Datei | Treffer | Gefundene Strings |
|---|---|---|
| Mail 1 | ✅ `Phish_IONOS_Homoglyph_Kit` | `$from_puny`, `$hide_a`, `$msgid`, `$mso_hide`, `$omikron`, 3× Zero-Width |
| Mail 2 | ✅ `Phish_IONOS_Homoglyph_Kit` | `$from_puny`, `$hide_b`, `$msgid`, `$mso_hide`, `$omikron`, 4× Zero-Width |
| Harmlose Test-Mail | ❌ kein Treffer | – |

Wichtig: Beide Mails würden auch **ohne** die Punycode-Domain erkannt (Bedingungen 2 und 3). Wechselt der Angreifer also die Lookalike-Domain, greift die Regel trotzdem, solange er das Kit nicht umschreibt.

---

## 2. Härtung der eigenen Domain

Die Angreifer haben **nicht** versucht, IONOS direkt zu spoofen, weil `ionos.com` mit DMARC geschützt ist. Genau diesen Schutz sollte **jede eigene Domain** haben, sonst kann ein Angreifer im Namen der eigenen Firma an Kunden schreiben.

### 2.1 SPF – wer darf für meine Domain senden?
```
example.de.  TXT  "v=spf1 include:_spf-eu.ionos.com -all"
```
- `include:` erlaubt die Server des Mail-Providers (Wert beim Provider nachschlagen)
- **`-all`** (Hardfail) statt `~all` (Softfail): Alle anderen Server sind ausdrücklich verboten. In Mail 1 hat `~all` dazu geführt, dass die Mail nur „softfail“ bekam.

### 2.2 DKIM – kryptografische Signatur
Im Provider aktivieren, Public Key als TXT-Record unter `<selector>._domainkey.example.de` veröffentlichen.

### 2.3 DMARC – was passiert, wenn SPF/DKIM fehlschlagen?
Schrittweise einführen:
```
_dmarc.example.de.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.de"        # 1. Nur beobachten
_dmarc.example.de.  TXT  "v=DMARC1; p=quarantine; pct=100; rua=mailto:..."     # 2. In Spam
_dmarc.example.de.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.de"      # 3. Ablehnen
```

### 2.4 Prüfen
```bash
dig +short TXT example.de
dig +short TXT _dmarc.example.de
dig +short TXT <selector>._domainkey.example.de
```

> **Wichtig:** SPF, DKIM und DMARC schützen nur vor **Spoofing der eigenen Domain**. Gegen **Lookalike-Domains** wie `iοnos.čom` helfen sie nicht. Dagegen helfen nur Erkennung (Abschnitt 1) und geschulte Menschen (Abschnitt 3).

---

## 3. Der Mensch – Awareness-Checkliste

Für Mitarbeitende in KMU, auf einer Seite:

1. **Absenderadresse ausklappen**, nicht nur den Namen lesen. `iοnos.čom` ≠ `ionos.com`.
2. **Mit der Maus über Links fahren** (nicht klicken) und das Ziel lesen. `google.com/goto…` oder `amazonaws.com` haben in einer IONOS-Rechnung nichts zu suchen.
3. **Nie über Links in Mails einloggen.** Kundenportal immer selbst über Lesezeichen oder die getippte Adresse aufrufen.
4. **Unerwartete Rechnung oder Sicherheitswarnung?** Im echten Konto nachsehen, nicht in der Mail.
5. **Im Zweifel melden**, nicht löschen – die IT kann nur warnen, wovon sie weiß.
6. **Abwesenheitsnotizen** nur an interne oder bekannte Kontakte schicken lassen.

---

## 4. Reaktion, falls doch geklickt wurde

| Situation | Sofortmaßnahme |
|---|---|
| Nur geklickt, nichts eingegeben | Seite schließen, Browser-Cache leeren, IT informieren (Adresse ist jetzt als aktiv bestätigt) |
| Passwort eingegeben | **Sofort** Passwort ändern (von einem sauberen Gerät), 2FA aktivieren, aktive Sitzungen beenden |
| Danach prüfen | Weiterleitungsregeln und Filter im Postfach (Angreifer legen gern heimliche Weiterleitungen an), Login-Historie, gesendete Mails |
| Gleiches Passwort woanders genutzt | Dort ebenfalls ändern |
