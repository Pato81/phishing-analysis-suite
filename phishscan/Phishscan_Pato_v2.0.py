#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhishScan - passiver .eml-Phishing-Analyzer
===========================================
Analysiert eine oder mehrere .eml-Dateien OFFLINE anhand von 11 Heuristiken
(H1-H11), die aus der Blue-Team-Fallstudie "IONOS-Homoglyph-Kampagne"
abgeleitet sind. Das Tool stellt KEINE Netzwerkverbindungen her, ruft keine
Links auf und verändert die Eingabedateien nicht - es liest nur und bewertet.

Autor:  Patrick May (Pato81)
Lizenz: MIT
Nutzung ausschliesslich zur Analyse eigener oder autorisiert erhaltener Mails.

Changelog
---------
1.2.0
  * FP-FIX H6: Versteckter Text wird nur noch dann als MEDIUM gewertet, wenn er
    selbst Link(s) oder >=2 Dringlichkeitsbegriffe enthaelt (echtes Salting).
    Reiner Vorschautext (Preheader), wie ihn jede legitime Marketing-Mail nutzt,
    faellt auf LOW. Verhindert Falsch-Positive bei serioeser Massenpost.
  * FP-FIX H11: Markenimitation feuert nur noch, wenn die Marke im BETREFF oder
    ANZEIGENAMEN steht (prominente Impersonation) - nicht mehr bei blosser
    Erwaehnung im Fliesstext (z. B. "Apple Store"-Downloadlink in einer
    legitimen Newsletter-Mail).
1.1.0
  * BUGFIX H9: Private-/Sonder-Adressbereiche werden jetzt ueber das
    stdlib-Modul `ipaddress` korrekt aussortiert (vorher nur "172.16.",
    statt 172.16.0.0/12). Es werden ausschliesslich global routbare
    Adressen gemeldet; ungueltige Oktette ("999.1.1.1") fallen raus.
  * NEU H9: IPv6-Adressen aus Received-Headern werden ebenfalls erkannt
    und ueber `ipaddress` validiert.
  * BUGFIX H8: Pro Anhang wird nur noch EIN Finding erzeugt (keine
    Doppelmeldung "gefaehrlicher Anhang" + "Doppelendung" mehr), damit der
    Score nicht verzerrt wird. Zusaetzlich RTLO-Erkennung im Dateinamen.
  * BUGFIX H4: SPF/DKIM/DMARC werden aus ALLEN Authentication-Results- und
    ARC-Authentication-Results-Headern ermittelt; bei Widerspruch zaehlt das
    schlechteste Ergebnis (gefaelschte Zusatz-Header koennen das Urteil nicht
    mehr schoenen). Keine Treffer mehr durch Teilstring-Matches.
  * ROBUSTHEIT: Groessen-Guard (Default 25 MB), Part-/Text-Limits,
    Kapselung jeder Heuristik gegen eigene Exceptions, Fallback-Parser,
    korrigierter Hidden-Text-Stack im HTML-Extractor.
  * NEU: Punycode-Domains werden in H1/H5 zusaetzlich dekodiert angezeigt.
  * NEU: --min-severity (filtert nur die ANZEIGE, nicht Score/Urteil),
    --selftest (Integritaetspruefung der Kernfunktionen),
    --max-size-mb (Groessen-Guard konfigurierbar).
  * NEU: Sammel-Uebersicht (Anzahl je Urteil) bei mehreren Mails.
1.0.0
  * Erstveroeffentlichung (H1-H11).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

VERSION = "1.2.0"

# --------------------------------------------------------------------------
# Harte Limits (DoS-Schutz gegen bewusst praeparierte Eingaben)
# --------------------------------------------------------------------------

MAX_EML_BYTES = 25 * 1024 * 1024    # .eml groesser -> ueberspringen
MAX_PARTS = 500                     # max. MIME-Parts, die betrachtet werden
MAX_TEXT_CHARS = 1_000_000          # max. Zeichen Textkoerper gesamt
MAX_HTML_CHARS = 1_000_000          # max. Zeichen HTML pro Part
MAX_URLS = 2_000                    # max. gesammelte URLs
MAX_LINKS = 2_000                   # max. gesammelte <a>-Elemente
MAX_RECEIVED = 100                  # max. ausgewertete Received-Header
MAX_IPS_REPORTED = 25               # max. IPs im H9-Detail
MAX_HOSTS_CHECKED = 100             # max. unterschiedliche Link-Hosts in H5
MAX_FILENAME_LEN = 300              # Dateinamen defensiv kappen


class EmlTooLargeError(Exception):
    """Eingabedatei ueberschreitet den konfigurierten Groessen-Guard."""


# --------------------------------------------------------------------------
# Datenstrukturen
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    hid: str            # z.B. "H1"
    title: str
    severity: str       # info | low | medium | high
    detail: str


@dataclass
class Report:
    source: str
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(SEVERITY_ORDER.get(f.severity, 0) for f in self.findings)

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= 8:
            return "HIGH RISK"
        if s >= 4:
            return "SUSPICIOUS"
        if s >= 1:
            return "LOW RISK"
        return "CLEAN"


# --------------------------------------------------------------------------
# Muster, Wortlisten, Tabellen
# --------------------------------------------------------------------------

URL_RE = re.compile(r"""https?://[^\s"'<>)\]]+""", re.IGNORECASE)

# IPv4-Kandidat: strikt abgegrenzt, damit "1.2.3.4.5" oder "v1.2.3.4" nicht
# faelschlich greifen. Die eigentliche Validierung macht `ipaddress`.
IPV4_CAND_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")

# IPv6-Kandidat: grob vorfiltern, danach strikt ueber `ipaddress` validieren.
IPV6_CAND_RE = re.compile(
    r"(?<![0-9A-Za-z:.])(?:IPv6:)?"
    r"([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_.-]+)?"
    r"(?:\.\d{1,3}){0,3})"
    r"(?![0-9A-Za-z:])"
)

# Mechanismus=Ergebnis in Authentication-Results; Lookbehind verhindert
# Teilstring-Treffer wie "x-spf=" oder "dkim-atps=".
AUTH_RE = re.compile(r"(?<![\w.\-])(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)", re.IGNORECASE)

# Schlechtester Wert gewinnt (hoeherer Rang = schlechter).
AUTH_RANK = {
    "pass": 0,
    "neutral": 1,
    "none": 2,
    "policy": 2,
    "temperror": 3,
    "permerror": 4,
    "softfail": 5,
    "fail": 6,
}
AUTH_BAD = {"none", "temperror", "permerror", "softfail", "fail"}

# Hostname-aehnlicher Anchor-Text (ohne Schema) - streng, um Fehlalarme zu
# vermeiden (kein Leerzeichen, kein "@", gueltige TLD-Laenge).
BARE_HOST_RE = re.compile(
    r"^(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\.?$",
    re.IGNORECASE,
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "s.id",
}

# Ausfuehrbares / direkt gefaehrliches Material -> high
HIGH_RISK_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".com",
    ".pif", ".hta", ".jar", ".ps1", ".psm1", ".msi", ".msc", ".cpl", ".reg",
    ".iso", ".img", ".vhd", ".lnk", ".wsf", ".wsh", ".scf", ".dll",
}
# Container / aktive Dokumente -> medium (haeufig legitim, aber beobachtenswert)
MEDIUM_RISK_EXT = {
    ".html", ".htm", ".shtml", ".svg", ".zip", ".rar", ".7z", ".ace", ".cab",
    ".gz", ".tgz", ".xz", ".docm", ".xlsm", ".pptm", ".dotm", ".xlsb", ".one",
    ".mht", ".mhtml",
}
# Kompatibel zur 1.0.0-Semantik: Vereinigung aller "gefaehrlichen" Endungen.
DANGEROUS_EXT = HIGH_RISK_EXT | MEDIUM_RISK_EXT

# Harmlos aussehende "Tarn-Endung" vor der eigentlichen Endung.
DECOY_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".csv", ".odt",
    ".ods", ".odp", ".eml", ".msg", ".mp3", ".mp4", ".avi", ".xml", ".json",
}

# Unicode-Richtungssteuerzeichen (RTLO & Co.) - klassischer Dateinamen-Trick.
BIDI_CONTROLS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f",
}

URGENCY_WORDS = [
    "sofort", "umgehend", "dringend", "verifizieren", "verifizierung",
    "bestätigen", "bestatigen", "gesperrt", "sperrung", "deaktiviert",
    "letzte warnung", "innerhalb von 24", "ihr konto", "zahlungs", "rechnung",
    "aktualisieren sie", "klicken sie", "urgent", "verify", "suspended",
    "password", "passwort", "login", "anmeldedaten", "kreditkarte",
]
BRANDS = [
    "ionos", "1&1", "paypal", "amazon", "microsoft", "office365", "apple",
    "dhl", "dpd", "postbank", "sparkasse", "commerzbank", "telekom",
    "netflix", "google", "outlook", "web.de", "gmx",
]

# Kleine Auswahl haeufiger Confusables (Nicht-ASCII -> ASCII-Aussehen)
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v",
    "α": "a", "ρ": "p", "τ": "t", "ⅼ": "l", "ｏ": "o", "０": "0", "１": "1",
    "ɑ": "a", "ɪ": "i", "ʏ": "y", "ʙ": "b", "ᴄ": "c", "ᴇ": "e", "ᴏ": "o",
    "ṃ": "m", "ḷ": "l", "ṛ": "r", "ѡ": "w", "ԝ": "w", "ӏ": "l", "ʟ": "l",
    "ɐ": "a", "ƅ": "b", "ϲ": "c", "ԛ": "q", "ѵ": "v", "ҽ": "e", "ӽ": "x",
}

# Mehrstufige Public Suffixes (kleine, pragmatische Auswahl - rein offline).
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "com.br", "com.mx", "com.ar", "com.co", "com.pe",
    "co.za", "org.za", "com.tr", "co.in", "net.in", "org.in",
    "com.cn", "net.cn", "org.cn", "com.hk", "com.sg", "co.kr", "or.kr",
    "co.il", "com.es", "com.pl", "com.ua", "com.ru",
}

# HTML-Tags ohne Endtag (duerfen den Hidden-Stack nicht verschieben).
VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}


# --------------------------------------------------------------------------
# HTML-Extraktion (rein lokal, kein Netzwerk, keine externen Ressourcen)
# --------------------------------------------------------------------------

class _TextExtractor(HTMLParser):
    """Zieht sichtbaren Text + versteckte Bereiche aus HTML (rein lokal)."""

    HIDDEN_RE = re.compile(
        r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
        r"|opacity\s*:\s*0|max-height\s*:\s*0|width\s*:\s*0|height\s*:\s*0"
        r"|text-indent\s*:\s*-\d{3,}|left\s*:\s*-\d{3,})",
        re.IGNORECASE,
    )
    SKIP_TAGS = {"script", "style", "head", "title", "noscript"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.hidden_parts: list[str] = []
        self.links: list[tuple[str, str]] = []  # (href, anchor_text)
        self._stack: list[tuple[str, bool, bool]] = []  # (tag, hidden, skip)
        self._hidden_depth = 0
        self._skip_depth = 0
        self._cur_href: str | None = None
        self._cur_anchor: list[str] = []

    # -- Hilfen ---------------------------------------------------------
    @classmethod
    def _is_hidden(cls, attrs: dict) -> bool:
        style = attrs.get("style") or ""
        if cls.HIDDEN_RE.search(style):
            return True
        if "hidden" in attrs:
            return True
        if (attrs.get("aria-hidden") or "").lower() == "true":
            return True
        return False

    def _flush_anchor(self):
        if self._cur_href is not None and len(self.links) < MAX_LINKS:
            self.links.append(
                (self._cur_href, "".join(self._cur_anchor).strip()[:300])
            )
        self._cur_href = None
        self._cur_anchor = []

    # -- HTMLParser-Callbacks -------------------------------------------
    def handle_starttag(self, tag, attrs):
        tag = (tag or "").lower()
        try:
            a = {(k or "").lower(): (v or "") for k, v in attrs}
        except Exception:  # noqa: BLE001 - defensiv gegen kaputtes Markup
            a = {}
        hidden = self._is_hidden(a)
        skip = tag in self.SKIP_TAGS

        if tag == "a":
            # Verschachtelte <a> sind invalides HTML - vorheriges sauber schliessen.
            if self._cur_href is not None:
                self._flush_anchor()
            self._cur_href = a.get("href")
            self._cur_anchor = []

        if tag in VOID_TAGS:
            return
        if len(self._stack) < 200:
            self._stack.append((tag, hidden, skip))
            if hidden:
                self._hidden_depth += 1
            if skip:
                self._skip_depth += 1

    def handle_startendtag(self, tag, attrs):
        # Self-closing Tag: niemals auf den Stack legen.
        tag = (tag or "").lower()
        if tag == "a":
            try:
                a = {(k or "").lower(): (v or "") for k, v in attrs}
            except Exception:  # noqa: BLE001
                a = {}
            href = a.get("href")
            if href and len(self.links) < MAX_LINKS:
                self.links.append((href, ""))

    def handle_endtag(self, tag):
        tag = (tag or "").lower()
        if tag == "a":
            self._flush_anchor()
        # Bis zum passenden Starttag zurueckrollen (robust bei unbalanciertem HTML).
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                for _t, hidden, skip in self._stack[i:]:
                    if hidden and self._hidden_depth > 0:
                        self._hidden_depth -= 1
                    if skip and self._skip_depth > 0:
                        self._skip_depth -= 1
                del self._stack[i:]
                break

    def handle_data(self, data):
        if not data:
            return
        if self._cur_href is not None and len(self._cur_anchor) < 50:
            self._cur_anchor.append(data)
        if self._skip_depth > 0:
            return
        if self._hidden_depth > 0:
            if len(self.hidden_parts) < 5000:
                self.hidden_parts.append(data)
        else:
            if len(self.text_parts) < 20000:
                self.text_parts.append(data)

    def close(self):  # noqa: D102 - uebernimmt nur das Anchor-Flushing
        try:
            super().close()
        finally:
            if self._cur_href is not None:
                self._flush_anchor()


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------

def _safe_header(msg, name: str, default: str = "") -> str:
    """Header defensiv als str lesen (kaputte Header duerfen nicht crashen)."""
    try:
        val = msg.get(name)
    except Exception:  # noqa: BLE001
        return default
    if val is None:
        return default
    try:
        return str(val)
    except Exception:  # noqa: BLE001
        try:
            return repr(val)
        except Exception:  # noqa: BLE001
            return default


def _safe_headers(msg, name: str) -> list[str]:
    """Alle Vorkommen eines Headers defensiv als str-Liste lesen."""
    out: list[str] = []
    try:
        vals = msg.get_all(name, [])
    except Exception:  # noqa: BLE001
        return out
    for val in vals or []:
        try:
            out.append(str(val))
        except Exception:  # noqa: BLE001
            continue
    return out


def _iter_parts(msg, limit: int = MAX_PARTS):
    """MIME-Parts mit hartem Limit und Exception-Schutz durchlaufen."""
    try:
        walker = msg.walk()
    except Exception:  # noqa: BLE001
        return
    count = 0
    while count < limit:
        try:
            part = next(walker)
        except StopIteration:
            return
        except Exception:  # noqa: BLE001 - defekter Part beendet nur den Walk
            return
        count += 1
        yield part


def _decode_part(part) -> str:
    """Payload eines Parts als Text zurueckgeben (nie werfend)."""
    try:
        payload = part.get_content()
        if isinstance(payload, bytes):
            return payload.decode(part.get_content_charset() or "utf-8", "replace")
        return str(payload)
    except Exception:  # noqa: BLE001
        try:
            raw = part.get_payload(decode=True)
        except Exception:  # noqa: BLE001
            raw = None
        if raw:
            try:
                return raw.decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                return ""
        try:
            payload = part.get_payload()
            return payload if isinstance(payload, str) else ""
        except Exception:  # noqa: BLE001
            return ""


def _registrable(host: str) -> str:
    """Grobe, offline nutzbare 'registrable domain' (eTLD+1-Naeherung)."""
    if not host:
        return ""
    host = host.lower().strip().strip(".")
    # IP-Literale haben keine registrierbare Domain.
    if host.startswith("[") and host.endswith("]"):
        return host
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _host_of(url: str) -> str:
    """Hostname aus einer URL ziehen (inkl. IPv6-Literal in eckigen Klammern)."""
    if not url:
        return ""
    m = re.match(r"https?://(?:[^/\\?#@]*@)?(\[[0-9A-Fa-f:.]+\]|[^/\\:?#]+)",
                 url.strip(), re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _userinfo_in_url(url: str) -> bool:
    """True, wenn die Authority einen Userinfo-Teil ('@') enthaelt."""
    m = re.match(r"https?://([^/\\?#]*)", url.strip(), re.IGNORECASE)
    if not m:
        return False
    return "@" in m.group(1)


def _has_confusable(s: str) -> list[str]:
    """Liefert die in `s` gefundenen konfusablen/nicht-lateinischen Zeichen."""
    hits: list[str] = []
    if not s:
        return hits
    for ch in s[:512]:
        if ch in CONFUSABLES:
            if ch not in hits:
                hits.append(ch)
            continue
        if ord(ch) > 127 and ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = ""
            if "LATIN" not in name and ch not in hits:
                hits.append(ch)
    return hits


def _idna_decode(host: str) -> str:
    """Punycode-Host labelweise nach Unicode dekodieren ('' bei Fehlschlag)."""
    if not host:
        return ""
    out: list[str] = []
    changed = False
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                dec = label.encode("ascii", "strict").decode("idna")
            except Exception:  # noqa: BLE001 - ungueltiges Punycode
                dec = label
            if dec and dec != label:
                changed = True
            out.append(dec)
        else:
            out.append(label)
    return ".".join(out) if changed else ""


def _punycode_hint(host: str) -> str:
    """Zusatztext mit dekodierter Unicode-Form + Confusable-Hinweis."""
    decoded = _idna_decode(host)
    if not decoded:
        return ""
    conf = _has_confusable(decoded)
    hint = f" -> dekodiert: {decoded}"
    if conf:
        hint += f" (konfusable Zeichen: {', '.join(conf)})"
    return hint


def _is_public_ip(text: str) -> bool:
    """True nur fuer global routbare, gueltige IPv4/IPv6-Adressen."""
    value = (text or "").strip()
    if not value:
        return False
    if value.lower().startswith("ipv6:"):
        value = value[5:]
    value = value.strip("[]")
    if "%" in value:  # Zone-ID abschneiden (fe80::1%eth0)
        value = value.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    try:
        if not ip.is_global:
            return False
    except Exception:  # noqa: BLE001 - sehr alte Python-Versionen
        return False
    # Zusaetzliche Sicherheitsnetze (CGNAT/Reserved sind in is_global bereits
    # abgedeckt, hier nur explizit dokumentiert).
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_reserved or ip.is_unspecified:
        return False
    return True


def _extract_public_ips(received_headers: list[str]) -> list[str]:
    """Oeffentliche IPv4/IPv6 aus Received-Headern (Reihenfolge erhalten)."""
    found: list[str] = []
    seen: set[str] = set()
    for raw in received_headers[:MAX_RECEIVED]:
        line = raw[:4000]
        for m in IPV4_CAND_RE.finditer(line):
            cand = m.group(1)
            if cand in seen:
                continue
            if _is_public_ip(cand):
                seen.add(cand)
                found.append(cand)
        for m in IPV6_CAND_RE.finditer(line):
            cand = m.group(1)
            if cand in seen or cand.count(":") < 2:
                continue
            if _is_public_ip(cand):
                try:
                    norm = str(ipaddress.ip_address(cand.split("%", 1)[0]))
                except ValueError:
                    norm = cand
                if norm in seen:
                    continue
                seen.add(cand)
                seen.add(norm)
                found.append(norm)
    return found


def _split_ext(filename: str) -> list[str]:
    """Endungs-Liste eines Dateinamens (klein, mit fuehrendem Punkt)."""
    low = (filename or "").strip().lower()
    parts = [p for p in low.split(".")]
    if len(parts) < 2:
        return []
    return ["." + p for p in parts[1:] if p]


def _classify_attachment(filename: str) -> tuple[str, str, str] | None:
    """
    Klassifiziert einen Anhang - genau EIN Ergebnis pro Anhang.

    Rueckgabe: (kind, severity, detail-suffix) oder None.
    kind: "rtlo" | "double_ext" | "dangerous" | "risky"
    """
    if not filename:
        return None
    name = filename[:MAX_FILENAME_LEN]

    # 1) Richtungssteuerzeichen (RTLO-Tarnung) - hoechste Prioritaet.
    bidi = sorted({ch for ch in name if ch in BIDI_CONTROLS})
    if bidi:
        codes = ", ".join("U+%04X" % ord(ch) for ch in bidi)
        return ("rtlo", "high", f"Unicode-Richtungssteuerzeichen ({codes})")

    exts = _split_ext(name)
    if not exts:
        return None
    last = exts[-1]

    # 2) Doppelendung: harmlos aussehende Tarn-Endung vor gefaehrlicher Endung.
    if len(exts) >= 2:
        prev = exts[-2]
        if prev in DECOY_EXT and last in DANGEROUS_EXT:
            return ("double_ext", "high", f"Tarn-Endung '{prev}' vor '{last}'")

    # 3) Direkt gefaehrliche Endung.
    if last in HIGH_RISK_EXT:
        return ("dangerous", "high", f"Endung '{last}'")
    if last in MEDIUM_RISK_EXT:
        return ("risky", "medium", f"Endung '{last}'")
    return None


def _parse_auth_results(blobs: list[str]) -> dict[str, dict]:
    """
    Wertet ALLE Authentication-Results/ARC-Header aus.

    Rueckgabe je Mechanismus:
        {"worst": <ergebnis>, "all": [<ergebnisse sortiert>]}
    Bei widerspruechlichen Angaben gewinnt das schlechteste Ergebnis - ein
    nachtraeglich eingefuegter "pass"-Header darf das Urteil nicht schoenen.
    """
    collected: dict[str, set[str]] = {"spf": set(), "dkim": set(), "dmarc": set()}
    for blob in blobs:
        for m in AUTH_RE.finditer(blob[:8000]):
            mech = m.group(1).lower()
            result = m.group(2).lower()
            if mech in collected:
                collected[mech].add(result)

    out: dict[str, dict] = {}
    for mech, results in collected.items():
        if not results:
            continue
        known = [r for r in results if r in AUTH_RANK]
        if known:
            worst = max(known, key=lambda r: (AUTH_RANK[r], r))
        else:
            worst = sorted(results)[0]
        out[mech] = {"worst": worst, "all": sorted(results)}
    return out


def _brand_in_text(text: str, brand: str) -> bool:
    """Marke mit Wortgrenzen suchen (reduziert Fehlalarme deutlich)."""
    pattern = r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])"
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return brand in text


# --------------------------------------------------------------------------
# Heuristiken H1 - H11
# --------------------------------------------------------------------------

def h1_sender_homoglyph(msg, rep: Report):
    """H1: Punycode/Homoglyphen in der Absenderdomain."""
    domain = rep.from_addr.split("@")[-1].lower() if "@" in rep.from_addr else ""
    domain = domain.strip().strip("[]")
    if not domain:
        return
    if domain.startswith("xn--") or ".xn--" in domain:
        rep.findings.append(Finding(
            "H1", "Punycode/IDN in Absenderdomain", "high",
            f"Absenderdomain nutzt Punycode: {domain}{_punycode_hint(domain)}"))
    conf = _has_confusable(domain)
    if conf:
        rep.findings.append(Finding(
            "H1", "Homoglyphen in Absenderdomain", "high",
            f"Nicht-lateinische/konfusable Zeichen: {', '.join(conf)} in {domain}"))


def h2_display_mismatch(msg, rep: Report):
    """H2: Anzeigename behauptet etwas anderes als die Absenderdomain."""
    disp = (rep.from_display or "").lower()
    domain = _registrable(rep.from_addr.split("@")[-1]) if "@" in rep.from_addr else ""
    if not disp:
        return
    for brand in BRANDS:
        if _brand_in_text(disp, brand) and domain and brand not in domain:
            rep.findings.append(Finding(
                "H2", "Anzeigename nennt Marke, Domain passt nicht", "high",
                f"Anzeigename enthaelt '{brand}', Domain ist '{domain}'"))
            break
    if "@" in disp:
        d2 = disp.split("@")[-1].strip(" >\"'\t")
        d2 = re.split(r"[\s,;<>()]", d2)[0] if d2 else ""
        if d2 and domain and _registrable(d2) != domain:
            rep.findings.append(Finding(
                "H2", "E-Mail im Anzeigenamen weicht von Absender ab", "medium",
                f"Anzeigename-Domain '{_registrable(d2)}' != Absender '{domain}'"))


def h3_replyto_returnpath(msg, rep: Report):
    """H3: Reply-To/Return-Path zeigen auf eine fremde Domain."""
    from_dom = _registrable(rep.from_addr.split("@")[-1]) if "@" in rep.from_addr else ""
    if not from_dom:
        return
    for header in ("Reply-To", "Return-Path"):
        val = _safe_header(msg, header)
        if not val:
            continue
        addr = parseaddr(val)[1]
        dom = _registrable(addr.split("@")[-1]) if "@" in addr else ""
        if dom and dom != from_dom:
            rep.findings.append(Finding(
                "H3", f"{header} weicht von Absenderdomain ab", "medium",
                f"{header}: {addr[:120]} (Domain {dom}) != From {from_dom}"))


def h4_authentication(msg, rep: Report):
    """H4: SPF/DKIM/DMARC aus ALLEN Auth-Headern - schlechtester Wert zaehlt."""
    blobs = (_safe_headers(msg, "Authentication-Results")
             + _safe_headers(msg, "ARC-Authentication-Results")
             + _safe_headers(msg, "X-Authentication-Results"))
    blobs = [b for b in blobs if b and b.strip()]
    if not blobs:
        rep.findings.append(Finding(
            "H4", "Keine Authentication-Results vorhanden", "low",
            "Mail enthaelt keinen Authentifizierungs-Header "
            "(SPF/DKIM/DMARC nicht pruefbar)."))
        return

    results = _parse_auth_results(blobs)
    if not results:
        rep.findings.append(Finding(
            "H4", "Authentication-Results ohne auswertbares Ergebnis", "low",
            f"{len(blobs)} Auth-Header vorhanden, aber kein spf=/dkim=/dmarc= "
            "Ergebnis erkennbar."))
        return

    for mech in ("spf", "dkim", "dmarc"):
        info = results.get(mech)
        if not info:
            continue
        worst = info["worst"]
        if worst not in AUTH_BAD:
            continue
        sev = "high" if (mech == "dmarc" and worst == "fail") else "medium"
        detail = f"{mech}={worst}"
        if len(info["all"]) > 1:
            detail += (f" (widerspruechliche Angaben in {len(blobs)} Auth-Header(n): "
                       + ", ".join(info["all"]) + " - schlechtester Wert gewertet)")
        rep.findings.append(Finding(
            "H4", f"{mech.upper()}-Pruefung nicht bestanden", sev, detail))


def h5_urls(bodies, rep: Report, links):
    """H5: Verdaechtige URLs (Userinfo, Punycode, Homoglyphen, IP, Shortener)."""
    seen_hosts: set[str] = set()
    checked = 0
    for url in sorted(bodies.get("urls", set())):
        if checked >= MAX_HOSTS_CHECKED:
            break
        host = _host_of(url)
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        checked += 1

        if _userinfo_in_url(url):
            rep.findings.append(Finding(
                "H5", "URL mit eingebettetem @ (Userinfo-Trick)", "high", url[:120]))
        if host.startswith("xn--") or ".xn--" in host:
            rep.findings.append(Finding(
                "H5", "Punycode-Domain in Link", "high",
                f"{host}{_punycode_hint(host)}"))
        conf = _has_confusable(host)
        if conf:
            rep.findings.append(Finding(
                "H5", "Homoglyphen in Link-Domain", "high",
                f"{host} (konfusable Zeichen: {', '.join(conf)})"))
        bare = host.strip("[]")
        if _is_public_ip(bare) or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", bare):
            rep.findings.append(Finding(
                "H5", "IP-Adresse statt Domain im Link", "medium", host))
        elif host.startswith("[") and ":" in host:
            rep.findings.append(Finding(
                "H5", "IP-Adresse statt Domain im Link", "medium", host))
        if _registrable(host) in SHORTENERS:
            rep.findings.append(Finding(
                "H5", "URL-Shortener verschleiert Ziel", "medium", host))

    # Anchor-vs-Href-Mismatch (klassische Sichttaeuschung im HTML)
    reported_pairs: set[tuple[str, str]] = set()
    for href, anchor in links[:MAX_LINKS]:
        if not href or not anchor:
            continue
        if not href.lower().startswith(("http://", "https://")):
            continue
        atext = " ".join(anchor.split())
        hh = _registrable(_host_of(href))
        if not hh:
            continue

        if re.search(r"https?://", atext, re.IGNORECASE):
            m = URL_RE.search(atext)
            ah = _registrable(_host_of(m.group(0))) if m else ""
            if ah and ah != hh and (ah, hh) not in reported_pairs:
                reported_pairs.add((ah, hh))
                rep.findings.append(Finding(
                    "H5", "Link-Text zeigt andere Domain als das Ziel", "high",
                    f"Text: {ah}  ->  Ziel: {hh}"))
            continue

        # Schema-loser, aber eindeutig hostnamen-foermiger Linktext.
        bm = BARE_HOST_RE.match(atext)
        if bm:
            ah = _registrable(bm.group(1).lower())
            if ah and ah != hh and (ah, hh) not in reported_pairs:
                reported_pairs.add((ah, hh))
                rep.findings.append(Finding(
                    "H5", "Link-Text zeigt andere Domain als das Ziel", "medium",
                    f"Text: {ah}  ->  Ziel: {hh}"))


def h6_hidden_text(bodies, rep: Report):
    """H6: Unsichtbarer Text im HTML (Bayes-/Filter-Evasion).

    Reiner Vorschautext (Preheader) ist in legitimer Marketing-Mail Standard und
    darf das Urteil nicht nach oben ziehen. Als MEDIUM (echtes Salting) wird daher
    nur gewertet, wenn der versteckte Text selbst Link(s) oder mehrere
    Dringlichkeitsbegriffe transportiert; sonst LOW.
    """
    hidden = (bodies.get("hidden") or "").strip()
    if len(hidden) < 40:
        return
    preview = " ".join(hidden.split())[:80]
    has_link = bool(URL_RE.search(hidden))
    urg = sorted({w for w in URGENCY_WORDS if w in hidden.lower()})
    if has_link or len(urg) >= 2:
        reason = []
        if has_link:
            reason.append("Link(s)")
        if len(urg) >= 2:
            reason.append(f"{len(urg)} Dringlichkeitsbegriffe")
        rep.findings.append(Finding(
            "H6", "Versteckter Text mit Link/Dringlichkeit (Filter-Evasion)", "medium",
            f"{len(hidden)} Zeichen unsichtbarer Text, enthaelt "
            f"{' und '.join(reason)}. Auszug: {preview}"))
    else:
        rep.findings.append(Finding(
            "H6", "Versteckter Text im HTML (oft Preheader)", "low",
            f"{len(hidden)} Zeichen unsichtbarer Text ohne Link/Dringlichkeit "
            f"(haeufig legitimer Vorschautext). Auszug: {preview}"))


def h7_urgency(bodies, rep: Report):
    """H7: Dringlichkeits-/Credential-Sprache."""
    text = ((bodies.get("text") or "") + " " + (bodies.get("subject") or "")).lower()
    text = text[:MAX_TEXT_CHARS]
    hits = sorted({w for w in URGENCY_WORDS if w in text})
    if len(hits) >= 3:
        rep.findings.append(Finding(
            "H7", "Dringlichkeits-/Credential-Sprache", "medium",
            "Auffaellige Begriffe: " + ", ".join(hits[:8])))
    elif len(hits) >= 1:
        rep.findings.append(Finding(
            "H7", "Dringlichkeits-/Credential-Sprache", "low",
            "Begriffe: " + ", ".join(hits)))


def h8_attachments(msg, rep: Report):
    """H8: Gefaehrliche Anhaenge - genau EIN Finding pro Anhang."""
    titles = {
        "rtlo": "Dateiname mit Richtungssteuerzeichen (RTLO-Tarnung)",
        "double_ext": "Doppelte Dateiendung (Tarnung)",
        "dangerous": "Potentiell gefaehrlicher Anhang",
        "risky": "Anhang mit beobachtenswertem Dateityp",
    }
    seen_names: set[str] = set()
    for part in _iter_parts(msg):
        try:
            fn = part.get_filename()
        except Exception:  # noqa: BLE001
            fn = None
        if not fn:
            continue
        try:
            fn = str(fn)[:MAX_FILENAME_LEN]
        except Exception:  # noqa: BLE001
            continue
        key = fn.lower()
        if key in seen_names:
            continue
        seen_names.add(key)

        res = _classify_attachment(fn)
        if not res:
            continue
        kind, sev, extra = res
        safe_name = fn.replace("\r", " ").replace("\n", " ")
        # Steuerzeichen sichtbar machen, damit die Konsole nicht getaeuscht wird.
        safe_name = "".join(
            ("<U+%04X>" % ord(ch)) if (ch in BIDI_CONTROLS or ord(ch) < 32) else ch
            for ch in safe_name
        )
        rep.findings.append(Finding(
            "H8", titles[kind], sev, f"{safe_name} ({extra})"))


def h9_origin(msg, rep: Report):
    """H9: Ursprungs-IPs (nur oeffentlich routbar) und Versand-Hinweise."""
    received = _safe_headers(msg, "Received")
    ips = _extract_public_ips(received)
    if ips:
        shown = ips[:MAX_IPS_REPORTED]
        more = f" (+{len(ips) - len(shown)} weitere)" if len(ips) > len(shown) else ""
        # Der unterste Received-Header ist i.d.R. der aelteste Hop.
        origin = ""
        if received:
            last_hop = _extract_public_ips([received[-1]])
            if last_hop:
                origin = f" | wahrscheinliche Ursprungs-IP: {last_hop[0]}"
        rep.findings.append(Finding(
            "H9", "Urspruengliche Absender-IP(s) extrahiert", "info",
            "Zur manuellen Pruefung (whois/Geo, offline durchfuehren): "
            + ", ".join(shown) + more + origin))

    php_script = (_safe_header(msg, "X-PHP-Script")
                  or _safe_header(msg, "X-PHP-Originating-Script"))
    if php_script:
        rep.findings.append(Finding(
            "H9", "Hinweis auf Versand per PHP-Skript", "medium",
            "Header X-PHP-Script/X-PHP-Originating-Script deutet auf "
            f"Skript-Versand (ggf. kompromittiertes Hosting) hin: {php_script[:80]}"))
    else:
        xmailer = _safe_header(msg, "X-Mailer")
        if xmailer and "php" in xmailer.lower():
            rep.findings.append(Finding(
                "H9", "Hinweis auf Versand per PHP-Skript", "low",
                f"X-Mailer deutet auf Massen-/Skript-Versand hin: {xmailer[:80]}"))


def h10_mime(msg, rep: Report, bodies):
    """H10: MIME-Struktur-Auffaelligkeiten."""
    has_html = bodies.get("has_html", False)
    has_text = bodies.get("has_text", False)
    if has_html and not has_text:
        rep.findings.append(Finding(
            "H10", "Nur HTML, kein Text-Teil", "low",
            "Reine HTML-Mail ohne text/plain-Alternative (haeufig bei Phishing)."))
    # Base64-kodierter HTML-Body (Verschleierung)
    for part in _iter_parts(msg):
        try:
            ctype = part.get_content_type()
        except Exception:  # noqa: BLE001
            continue
        if ctype == "text/html":
            try:
                enc = (part.get("Content-Transfer-Encoding") or "")
                enc = str(enc).strip().lower()
            except Exception:  # noqa: BLE001
                enc = ""
            if enc == "base64":
                rep.findings.append(Finding(
                    "H10", "HTML-Body base64-kodiert", "low",
                    "HTML als base64 - kann Signatur-Scanner umgehen."))
                break


def h11_brand_impersonation(bodies, rep: Report):
    """H11: Markenimitation an prominenter Stelle bei fremder Absenderdomain.

    Gewertet wird nur der BETREFF - dort behauptet eine Phishing-Mail, von der
    Marke zu stammen. Der Anzeigename gehoert zu H2 (Doppelzaehlung vermeiden),
    und eine blosse Erwaehnung im Fliesstext (z. B. ein 'Apple Store'-Downloadlink
    in einem legitimen Newsletter) ist KEIN Impersonation-Signal.
    """
    subject = (rep.subject or "").lower()
    from_dom = ""
    if "@" in rep.from_addr:
        from_dom = _registrable(rep.from_addr.split("@")[-1])
    if not from_dom or not subject.strip():
        return
    for brand in BRANDS:
        if brand in from_dom:
            continue
        if _brand_in_text(subject, brand):
            rep.findings.append(Finding(
                "H11", "Markenimitation im Betreff", "medium",
                f"Betreff nennt '{brand}', Absenderdomain ist '{from_dom}'."))
            break


# --------------------------------------------------------------------------
# Analyse-Pipeline
# --------------------------------------------------------------------------

def _collect_bodies(msg) -> dict:
    """Sammelt Text-, HTML-, Hidden-Teile, Links und URLs (rein lokal)."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    hidden_parts: list[str] = []
    links: list[tuple[str, str]] = []
    has_html = has_text = False

    for part in _iter_parts(msg):
        try:
            ctype = part.get_content_type()
            maintype = part.get_content_maintype()
            is_attachment = bool(part.is_attachment())
        except Exception:  # noqa: BLE001
            continue
        if maintype == "multipart":
            continue
        if is_attachment:
            continue

        if ctype == "text/plain":
            has_text = True
            text_parts.append(_decode_part(part)[:MAX_HTML_CHARS])
        elif ctype == "text/html":
            has_html = True
            raw = _decode_part(part)[:MAX_HTML_CHARS]
            ex = _TextExtractor()
            try:
                ex.feed(raw)
                ex.close()
            except Exception:  # noqa: BLE001 - kaputtes HTML darf nicht stoppen
                pass
            text_parts.append(" ".join(ex.text_parts))
            hidden_parts.append(" ".join(ex.hidden_parts))
            if len(links) < MAX_LINKS:
                links.extend(ex.links[:MAX_LINKS - len(links)])
            html_parts.append(raw)

    joined_text = "\n".join(text_parts)[:MAX_TEXT_CHARS]
    joined_hidden = "\n".join(hidden_parts)[:MAX_TEXT_CHARS]

    urls: set[str] = set()
    for candidate in URL_RE.findall(joined_text):
        if len(urls) >= MAX_URLS:
            break
        urls.add(candidate[:2000])
    for raw in html_parts:
        if len(urls) >= MAX_URLS:
            break
        for candidate in URL_RE.findall(raw):
            if len(urls) >= MAX_URLS:
                break
            urls.add(candidate[:2000])
    for href, _anchor in links:
        if len(urls) >= MAX_URLS:
            break
        if href and href.lower().startswith(("http://", "https://")):
            urls.add(href[:2000])

    return {
        "text": joined_text,
        "hidden": joined_hidden,
        "has_html": has_html,
        "has_text": has_text,
        "urls": urls,
        "links": links,
        "subject": _safe_header(msg, "Subject"),
    }


def _run_heuristic(rep: Report, hid: str, func, *args) -> None:
    """
    Fuehrt eine Heuristik gekapselt aus.

    Eine absichtlich kaputte Mail darf nur die betroffene Heuristik kosten -
    alle uebrigen laufen weiter. Der Fehler wird score-neutral (info)
    protokolliert, damit er im Report nachvollziehbar bleibt.
    """
    try:
        func(*args)
    except Exception as exc:  # noqa: BLE001
        rep.findings.append(Finding(
            hid, f"{hid}: Heuristik konnte nicht vollstaendig ausgefuehrt werden",
            "info", f"{type(exc).__name__}: {str(exc)[:200]}"))


def _dedup_findings(findings: list) -> list:
    """Exakt identische Findings entfernen (verhindert Score-Verzerrung)."""
    seen: set[tuple[str, str, str, str]] = set()
    out = []
    for f in findings:
        key = (f.hid, f.title, f.severity, f.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _parse_eml(path: Path):
    """Mail parsen; bei Problemen mit policy.default auf compat32 ausweichen."""
    try:
        with path.open("rb") as fh:
            return BytesParser(policy=policy.default).parse(fh)
    except Exception:  # noqa: BLE001
        with path.open("rb") as fh:
            return BytesParser(policy=policy.compat32).parse(fh)


def analyze(path: Path, max_bytes: int = MAX_EML_BYTES) -> Report:
    """
    Analysiert eine .eml-Datei rein lesend und liefert einen Report.

    Raises:
        EmlTooLargeError: wenn die Datei den Groessen-Guard ueberschreitet.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise OSError(f"Datei nicht lesbar: {exc}") from exc
    if max_bytes > 0 and size > max_bytes:
        raise EmlTooLargeError(
            f"{size} Bytes > Limit {max_bytes} Bytes")

    msg = _parse_eml(path)

    raw_from = _safe_header(msg, "From")
    disp, addr = parseaddr(raw_from)
    rep = Report(source=str(path), subject=_safe_header(msg, "Subject"),
                 from_display=(disp or "")[:300], from_addr=(addr or "")[:300])

    try:
        bodies = _collect_bodies(msg)
    except Exception as exc:  # noqa: BLE001
        bodies = {"text": "", "hidden": "", "has_html": False, "has_text": False,
                  "urls": set(), "links": [], "subject": rep.subject}
        rep.findings.append(Finding(
            "H10", "Mail-Koerper konnte nicht vollstaendig geparst werden", "info",
            f"{type(exc).__name__}: {str(exc)[:200]}"))
    bodies["subject"] = rep.subject

    _run_heuristic(rep, "H1", h1_sender_homoglyph, msg, rep)
    _run_heuristic(rep, "H2", h2_display_mismatch, msg, rep)
    _run_heuristic(rep, "H3", h3_replyto_returnpath, msg, rep)
    _run_heuristic(rep, "H4", h4_authentication, msg, rep)
    _run_heuristic(rep, "H5", h5_urls, bodies, rep, bodies.get("links", []))
    _run_heuristic(rep, "H6", h6_hidden_text, bodies, rep)
    _run_heuristic(rep, "H7", h7_urgency, bodies, rep)
    _run_heuristic(rep, "H8", h8_attachments, msg, rep)
    _run_heuristic(rep, "H9", h9_origin, msg, rep)
    _run_heuristic(rep, "H10", h10_mime, msg, rep, bodies)
    _run_heuristic(rep, "H11", h11_brand_impersonation, bodies, rep)

    rep.findings = _dedup_findings(rep.findings)
    # Deterministische Sortierung: Severity absteigend, dann H-ID, Titel, Detail.
    rep.findings.sort(key=lambda f: (
        -SEVERITY_ORDER.get(f.severity, 0),
        int(f.hid[1:]) if f.hid[1:].isdigit() else 99,
        f.title,
        f.detail,
    ))
    return rep


# --------------------------------------------------------------------------
# Ausgabe
# --------------------------------------------------------------------------

C = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m",
     "info": "\033[90m", "ok": "\033[92m", "bold": "\033[1m", "off": "\033[0m"}

VERDICT_KEY = {"HIGH RISK": "high", "SUSPICIOUS": "medium",
               "LOW RISK": "low", "CLEAN": "ok"}
VERDICT_ORDER = ["HIGH RISK", "SUSPICIOUS", "LOW RISK", "CLEAN"]


def _c(txt, key, color):
    return f"{C[key]}{txt}{C['off']}" if color else txt


def _visible_findings(rep: Report, min_severity: str = "info") -> list:
    """Findings fuer die ANZEIGE filtern (Score/Urteil bleiben unberuehrt)."""
    threshold = SEVERITY_ORDER.get(min_severity, 0)
    if threshold <= 0:
        return list(rep.findings)
    return [f for f in rep.findings
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold]


def print_report(rep: Report, color=True, min_severity: str = "info"):
    """Gibt einen Report im klassischen PhishScan-Format aus."""
    print(_c("=" * 64, "bold", color))
    print(_c(f"PhishScan-Report: {rep.source}", "bold", color))
    print("=" * 64)
    print(f"Betreff : {rep.subject}")
    print(f"Von     : {rep.from_display} <{rep.from_addr}>")
    vkey = VERDICT_KEY.get(rep.verdict, "info")
    print(f"Urteil  : {_c(rep.verdict, vkey, color)}  (Score {rep.score}, "
          f"{len(rep.findings)} Finding(s))")
    print("-" * 64)

    shown = _visible_findings(rep, min_severity)
    hidden_count = len(rep.findings) - len(shown)

    if not rep.findings:
        print(_c("Keine verdaechtigen Merkmale gefunden.", "ok", color))
    elif not shown:
        print(_c(f"Keine Findings >= {min_severity.upper()} "
                 f"({hidden_count} ausgeblendet).", "info", color))
    for f in shown:
        print(f"[{f.hid}] {_c(f.severity.upper(), f.severity, color)}  {f.title}")
        print(f"      {f.detail}")
    if shown and hidden_count > 0:
        print(_c(f"      ({hidden_count} Finding(s) unterhalb von "
                 f"'{min_severity}' ausgeblendet - Score unveraendert)",
                 "info", color))
    print()


def print_summary(reports: list, color=True, errors: int = 0, skipped: int = 0):
    """Kurze Sammel-Uebersicht beim Triagieren ganzer Ordner."""
    counts = {v: 0 for v in VERDICT_ORDER}
    for r in reports:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print(_c("=" * 64, "bold", color))
    print(_c(f"Zusammenfassung: {len(reports)} Mail(s) analysiert", "bold", color))
    print("=" * 64)
    for verdict in VERDICT_ORDER:
        label = f"{verdict:<11}"
        print(f"  {_c(label, VERDICT_KEY[verdict], color)}: {counts.get(verdict, 0)}")
    if skipped:
        print(f"  {'UEBERSPRUNGEN':<11}: {skipped}")
    if errors:
        print(f"  {'FEHLER':<11}: {errors}")
    print()


# --------------------------------------------------------------------------
# Selftest (keine Netzwerk-/Dateizugriffe, rein in-memory)
# --------------------------------------------------------------------------

def run_selftest(color: bool = True) -> int:
    """Prueft die Kernfunktionen an eingebauten Beispielen."""
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, got, expected) -> None:
        ok = got == expected
        checks.append((name, ok, f"erwartet={expected!r} erhalten={got!r}"))

    # --- Confusable-/Homoglyph-Erkennung ---
    check("confusable: reines ASCII 'ionos.de'", _has_confusable("ionos.de") == [], True)
    check("confusable: kyrillisches 'o' in 'i\u043enos.de'",
          len(_has_confusable("i\u043enos.de")) > 0, True)
    check("confusable: deutsches Umlaut-Label bleibt latein",
          _has_confusable("m\u00fcller.de") == [], True)

    # --- Punycode-Dekodierung ---
    check("idna: xn--bcher-kva.de -> buecher-Form",
          _idna_decode("xn--bcher-kva.de"), "b\u00fccher.de")
    check("idna: ASCII-Domain liefert ''", _idna_decode("example.com"), "")
    check("idna: kaputtes Punycode crasht nicht",
          isinstance(_idna_decode("xn--!!!.de"), str), True)

    # --- ipaddress-Filter (H9) ---
    check("ip: 8.8.8.8 ist public", _is_public_ip("8.8.8.8"), True)
    check("ip: 10.0.0.1 ist privat", _is_public_ip("10.0.0.1"), False)
    check("ip: 172.16.0.1 ist privat", _is_public_ip("172.16.0.1"), False)
    check("ip: 172.20.10.5 ist privat (Bugfix /12)", _is_public_ip("172.20.10.5"), False)
    check("ip: 172.31.255.254 ist privat (Bugfix /12)",
          _is_public_ip("172.31.255.254"), False)
    check("ip: 172.32.0.1 ist public (ausserhalb /12)",
          _is_public_ip("172.32.0.1"), True)
    check("ip: 192.168.1.1 ist privat", _is_public_ip("192.168.1.1"), False)
    check("ip: 127.0.0.1 ist loopback", _is_public_ip("127.0.0.1"), False)
    check("ip: 169.254.1.1 ist link-local", _is_public_ip("169.254.1.1"), False)
    check("ip: 100.64.0.1 ist CGNAT", _is_public_ip("100.64.0.1"), False)
    check("ip: 255.255.255.0 (Netzmaske) nicht global",
          _is_public_ip("255.255.255.0"), False)
    check("ip: 999.1.1.1 ungueltig", _is_public_ip("999.1.1.1"), False)
    check("ip: 1.2.3 ungueltig", _is_public_ip("1.2.3"), False)
    check("ip6: 2a00:1450:4001:81b::200e ist public",
          _is_public_ip("2a00:1450:4001:81b::200e"), True)
    check("ip6: fe80::1 ist link-local", _is_public_ip("fe80::1"), False)
    check("ip6: ::1 ist loopback", _is_public_ip("::1"), False)
    check("ip6: fd00::1 ist ULA", _is_public_ip("fd00::1"), False)
    check("ip6: 2001:db8::1 ist Doku-Praefix", _is_public_ip("2001:db8::1"), False)

    received_demo = [
        "from mx.example.net (mx.example.net [8.8.8.8]) by relay (Postfix) "
        "with ESMTP id ABC; Mon, 1 Jan 2024 10:20:30 +0100",
        "from internal (internal [172.20.10.5]) by mx.example.net with ESMTP",
        "from v6.example.org (IPv6:2a00:1450:4001:81b::200e) by relay",
        "from bogus ([999.1.1.1]) by relay; netmask 255.255.255.0",
    ]
    extracted = _extract_public_ips(received_demo)
    check("received: nur public IPv4/IPv6 extrahiert",
          extracted, ["8.8.8.8", "2a00:1450:4001:81b::200e"])

    # --- Endungs-/Anhang-Check (H8) ---
    check("ext: setup.exe -> dangerous",
          (_classify_attachment("setup.exe") or ("", "", ""))[0], "dangerous")
    check("ext: rechnung.pdf.exe -> double_ext (nur EIN Finding)",
          (_classify_attachment("rechnung.pdf.exe") or ("", "", ""))[0], "double_ext")
    check("ext: foto.jpg -> kein Finding", _classify_attachment("foto.jpg"), None)
    check("ext: bericht.pdf -> kein Finding", _classify_attachment("bericht.pdf"), None)
    check("ext: archiv.zip -> risky (medium)",
          (_classify_attachment("archiv.zip") or ("", "", ""))[1], "medium")
    check("ext: backup.2024.12.01.zip -> keine falsche Doppelendung",
          (_classify_attachment("backup.2024.12.01.zip") or ("", "", ""))[0], "risky")
    check("ext: RTLO im Namen erkannt",
          (_classify_attachment("rechnung\u202egpj.exe") or ("", "", ""))[0], "rtlo")
    check("ext: leerer Name -> None", _classify_attachment(""), None)

    # --- Auth-Results (H4): schlechtester Wert gewinnt ---
    auth = _parse_auth_results([
        "mx.example.net; spf=pass smtp.mailfrom=example.net; dkim=pass "
        "header.d=example.net; dmarc=pass",
        "relay.example.org; spf=fail smtp.mailfrom=evil.tld; dmarc=fail",
    ])
    check("auth: spf worst=fail", auth.get("spf", {}).get("worst"), "fail")
    check("auth: dmarc worst=fail", auth.get("dmarc", {}).get("worst"), "fail")
    check("auth: dkim worst=pass", auth.get("dkim", {}).get("worst"), "pass")
    check("auth: kein Teilstring-Treffer bei 'x-spf='",
          _parse_auth_results(["x-spf=fail; dkim-atps=neutral"]), {})

    # --- Host-/Domain-Hilfen ---
    check("host: URL mit Userinfo", _host_of("http://user@evil.tld/x"), "evil.tld")
    check("host: Userinfo-Erkennung", _userinfo_in_url("http://ionos.de@evil.tld/"), True)
    check("host: kein Userinfo", _userinfo_in_url("https://ionos.de/pfad@x"), False)
    check("registrable: www.sub.ionos.de", _registrable("www.sub.ionos.de"), "ionos.de")
    check("registrable: a.b.co.uk", _registrable("a.b.co.uk"), "b.co.uk")

    # --- Score/Verdict-Determinismus ---
    demo = Report(source="selftest")
    demo.findings = [Finding("H1", "t", "high", "d"), Finding("H7", "t", "low", "d")]
    check("score: 3+1 = 4 -> SUSPICIOUS", (demo.score, demo.verdict), (4, "SUSPICIOUS"))
    check("verdict: leer -> CLEAN", Report(source="x").verdict, "CLEAN")

    # --- FP-Fixes H6/H11 (v1.2.0) ---
    r = Report(source="t")
    h6_hidden_text({"hidden": "vorschautext ohne link " * 3}, r)
    check("h6: reiner Preheader -> low",
          (r.findings[0].severity if r.findings else ""), "low")
    r = Report(source="t")
    h6_hidden_text({"hidden": "versteckter koeder text http://evil.tld/login bitte"}, r)
    check("h6: versteckter Link -> medium",
          (r.findings[0].severity if r.findings else ""), "medium")
    r = Report(source="t", subject="Ihre IONOS Rechnung", from_addr="x@fremd.example")
    h11_brand_impersonation({}, r)
    check("h11: Marke im Betreff feuert", bool(r.findings), True)
    r = Report(source="t", subject="Newsletter", from_addr="x@fremd.example")
    h11_brand_impersonation({"text": "jetzt im apple store laden"}, r)
    check("h11: Marke nur im Body feuert NICHT", r.findings, [])

    failed = [c for c in checks if not c[1]]
    print(_c(f"PhishScan {VERSION} - Selftest", "bold", color))
    print("=" * 64)
    for name, ok, info in checks:
        mark = _c("PASS", "ok", color) if ok else _c("FAIL", "high", color)
        line = f"[{mark}] {name}"
        if not ok:
            line += f"  ({info})"
        print(line)
    print("-" * 64)
    print(f"{len(checks) - len(failed)}/{len(checks)} Pruefungen bestanden.")
    if failed:
        print(_c("Selftest FEHLGESCHLAGEN - Tool nicht als vertrauenswuerdig "
                 "betrachten.", "high", color), file=sys.stderr)
        return 1
    print(_c("Selftest OK.", "ok", color))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _collect_targets(paths: list[str]) -> list[Path]:
    """Sammelt .eml-Dateien deterministisch (Datei oder Ordner)."""
    targets: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        pp = Path(p)
        try:
            is_dir = pp.is_dir()
            is_file = pp.is_file()
        except OSError:
            is_dir = is_file = False
        if is_dir:
            try:
                entries = sorted(pp.iterdir(), key=lambda q: q.name.lower())
            except OSError as exc:
                print(f"[!] Ordner nicht lesbar: {pp} ({exc})", file=sys.stderr)
                continue
            for entry in entries:
                try:
                    if entry.is_file() and entry.suffix.lower() == ".eml":
                        key = str(entry.resolve())
                        if key not in seen:
                            seen.add(key)
                            targets.append(entry)
                except OSError:
                    continue
        elif is_file:
            try:
                key = str(pp.resolve())
            except OSError:
                key = str(pp)
            if key not in seen:
                seen.add(key)
                targets.append(pp)
        else:
            print(f"[!] Nicht gefunden: {p}", file=sys.stderr)
    return targets


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="PhishScan - passiver .eml-Phishing-Analyzer (H1-H11). "
                    "Kein Netzwerkzugriff, keine Aenderung der Eingabe.")
    ap.add_argument("paths", nargs="*", help=".eml-Datei(en) oder Ordner")
    ap.add_argument("--json", action="store_true", help="Ausgabe als JSON")
    ap.add_argument("--no-color", action="store_true", help="ohne Farben")
    ap.add_argument("--min-severity", choices=("info", "low", "medium", "high"),
                    default="info",
                    help="blendet Findings unterhalb dieser Stufe in der ANZEIGE "
                         "aus (Score/Urteil bleiben unveraendert)")
    ap.add_argument("--max-size-mb", type=float, default=MAX_EML_BYTES / (1024 * 1024),
                    help="Groessen-Guard je .eml in MB (Default 25; 0 = aus)")
    ap.add_argument("--selftest", action="store_true",
                    help="prueft die Kernfunktionen und beendet sich")
    ap.add_argument("--version", action="version", version=f"PhishScan {VERSION}")
    args = ap.parse_args(argv)

    color = not args.no_color and sys.stdout.isatty()

    if args.selftest:
        return run_selftest(color=color)

    if not args.paths:
        print("[!] Keine Pfade angegeben (oder --selftest nutzen).", file=sys.stderr)
        return 2

    try:
        max_bytes = int(max(0.0, args.max_size_mb) * 1024 * 1024)
    except (TypeError, ValueError, OverflowError):
        max_bytes = MAX_EML_BYTES

    targets = _collect_targets(args.paths)
    if not targets:
        print("[!] Keine .eml-Dateien zu analysieren.", file=sys.stderr)
        return 2

    reports: list[Report] = []
    errors = 0
    skipped = 0
    for t in targets:
        try:
            reports.append(analyze(t, max_bytes=max_bytes))
        except EmlTooLargeError as exc:
            skipped += 1
            print(f"[!] Uebersprungen (Groessen-Guard): {t} - {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            errors += 1
            print(f"[!] Fehler bei {t}: {type(exc).__name__}: {exc}", file=sys.stderr)

    if args.json:
        payload = []
        for r in reports:
            d = asdict(r)
            d["findings"] = [asdict(f) for f in _visible_findings(r, args.min_severity)]
            d["findings_total"] = len(r.findings)
            d["score"] = r.score
            d["verdict"] = r.verdict
            payload.append(d)
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False))
    else:
        for r in reports:
            print_report(r, color=color, min_severity=args.min_severity)
        if len(reports) > 1 or skipped or errors:
            print_summary(reports, color=color, errors=errors, skipped=skipped)

    return 1 if any(r.verdict in ("HIGH RISK", "SUSPICIOUS") for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())