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
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from html.parser import HTMLParser
from pathlib import Path

VERSION = "1.0.0"

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
# Hilfsfunktionen
# --------------------------------------------------------------------------

URL_RE = re.compile(r"""https?://[^\s"'<>)\]]+""", re.IGNORECASE)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "s.id",
}
DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".com",
    ".pif", ".hta", ".jar", ".ps1", ".iso", ".img", ".lnk", ".html", ".htm",
    ".shtml", ".svg", ".zip", ".rar", ".7z", ".ace", ".cab",
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
}


class _TextExtractor(HTMLParser):
    """Zieht sichtbaren Text + versteckte Bereiche aus HTML (rein lokal)."""

    HIDDEN_RE = re.compile(
        r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
        r"|opacity\s*:\s*0|width\s*:\s*0|height\s*:\s*0)",
        re.IGNORECASE,
    )

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.hidden_parts: list[str] = []
        self.links: list[tuple[str, str]] = []  # (href, anchor_text)
        self._hidden_depth = 0
        self._cur_href: str | None = None
        self._cur_anchor: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        style = a.get("style", "") or ""
        hidden = bool(self.HIDDEN_RE.search(style)) or "hidden" in a
        if hidden:
            self._hidden_depth += 1
        if tag == "a":
            self._cur_href = a.get("href")
            self._cur_anchor = []

    def handle_endtag(self, tag):
        if tag == "a" and self._cur_href is not None:
            self.links.append((self._cur_href, "".join(self._cur_anchor).strip()))
            self._cur_href = None
            self._cur_anchor = []
        if self._hidden_depth > 0:
            self._hidden_depth -= 1

    def handle_data(self, data):
        if self._cur_href is not None:
            self._cur_anchor.append(data)
        if self._hidden_depth > 0:
            self.hidden_parts.append(data)
        else:
            self.text_parts.append(data)


def _decode_part(part) -> str:
    try:
        payload = part.get_content()
        if isinstance(payload, bytes):
            return payload.decode(part.get_content_charset() or "utf-8", "replace")
        return str(payload)
    except Exception:
        raw = part.get_payload(decode=True)
        if raw:
            return raw.decode("utf-8", "replace")
        return ""


def _registrable(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:@]+@)?([^/:?#]+)", url, re.IGNORECASE)
    return m.group(2).lower() if m else ""


def _has_confusable(s: str) -> list[str]:
    hits = []
    for ch in s:
        if ch in CONFUSABLES:
            hits.append(ch)
        elif ord(ch) > 127 and ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = ""
            if "LATIN" not in name:
                hits.append(ch)
    return hits


# --------------------------------------------------------------------------
# Heuristiken H1 - H11
# --------------------------------------------------------------------------

def h1_sender_homoglyph(msg, rep: Report):
    domain = rep.from_addr.split("@")[-1].lower() if "@" in rep.from_addr else ""
    if not domain:
        return
    if domain.startswith("xn--") or ".xn--" in domain:
        rep.findings.append(Finding("H1", "Punycode/IDN in Absenderdomain",
                                    "high", f"Absenderdomain nutzt Punycode: {domain}"))
    conf = _has_confusable(domain)
    if conf:
        rep.findings.append(Finding("H1", "Homoglyphen in Absenderdomain", "high",
                                    f"Nicht-lateinische/konfusable Zeichen: {', '.join(conf)} in {domain}"))


def h2_display_mismatch(msg, rep: Report):
    disp = rep.from_display.lower()
    domain = _registrable(rep.from_addr.split("@")[-1]) if "@" in rep.from_addr else ""
    for brand in BRANDS:
        if brand in disp and domain and brand not in domain:
            rep.findings.append(Finding("H2", "Anzeigename nennt Marke, Domain passt nicht",
                                        "high",
                                        f"Anzeigename enthaelt '{brand}', Domain ist '{domain}'"))
            break
    if "@" in disp:
        d2 = disp.split("@")[-1].strip(" >")
        if d2 and domain and _registrable(d2) != domain:
            rep.findings.append(Finding("H2", "E-Mail im Anzeigenamen weicht von Absender ab",
                                        "medium",
                                        f"Anzeigename-Domain '{_registrable(d2)}' != Absender '{domain}'"))


def h3_replyto_returnpath(msg, rep: Report):
    from_dom = _registrable(rep.from_addr.split("@")[-1]) if "@" in rep.from_addr else ""
    for header in ("Reply-To", "Return-Path"):
        val = msg.get(header, "")
        if not val:
            continue
        addr = parseaddr(val)[1]
        dom = _registrable(addr.split("@")[-1]) if "@" in addr else ""
        if dom and from_dom and dom != from_dom:
            rep.findings.append(Finding("H3", f"{header} weicht von Absenderdomain ab",
                                        "medium",
                                        f"{header}: {addr} (Domain {dom}) != From {from_dom}"))


def h4_authentication(msg, rep: Report):
    auth = " ".join(msg.get_all("Authentication-Results", []))
    arc = " ".join(msg.get_all("ARC-Authentication-Results", []))
    blob = (auth + " " + arc).lower()
    if not blob.strip():
        rep.findings.append(Finding("H4", "Keine Authentication-Results vorhanden", "low",
                                    "Mail enthaelt keinen Authentifizierungs-Header (SPF/DKIM/DMARC nicht pruefbar)."))
        return
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=(\w+)", blob)
        if m and m.group(1) in ("fail", "softfail", "none", "permerror", "temperror"):
            sev = "high" if mech == "dmarc" and m.group(1) == "fail" else "medium"
            rep.findings.append(Finding("H4", f"{mech.upper()}-Pruefung nicht bestanden", sev,
                                        f"{mech}={m.group(1)}"))


def h5_urls(bodies, rep: Report, links):
    seen = set()
    for url in list(bodies["urls"]):
        host = _host_of(url)
        if not host or host in seen:
            continue
        seen.add(host)
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            rep.findings.append(Finding("H5", "URL mit eingebettetem @ (Userinfo-Trick)", "high",
                                        url[:120]))
        if host.startswith("xn--") or ".xn--" in host:
            rep.findings.append(Finding("H5", "Punycode-Domain in Link", "high", host))
        if _has_confusable(host):
            rep.findings.append(Finding("H5", "Homoglyphen in Link-Domain", "high", host))
        if re.match(r"\d{1,3}(\.\d{1,3}){3}$", host):
            rep.findings.append(Finding("H5", "IP-Adresse statt Domain im Link", "medium", host))
        if _registrable(host) in SHORTENERS:
            rep.findings.append(Finding("H5", "URL-Shortener verschleiert Ziel", "medium", host))
    # Anchor-vs-Href-Mismatch
    for href, anchor in links:
        if not href or not anchor:
            continue
        atext = anchor.strip()
        if re.search(r"https?://", atext, re.IGNORECASE):
            ah = _registrable(_host_of(atext))
            hh = _registrable(_host_of(href))
            if ah and hh and ah != hh:
                rep.findings.append(Finding("H5", "Link-Text zeigt andere Domain als das Ziel",
                                            "high", f"Text: {ah}  ->  Ziel: {hh}"))


def h6_hidden_text(bodies, rep: Report):
    hidden = bodies["hidden"].strip()
    if len(hidden) >= 40:
        rep.findings.append(Finding("H6", "Versteckter Text im HTML (Filter-Evasion)", "medium",
                                    f"{len(hidden)} Zeichen unsichtbarer Text (display:none/font-size:0 o.ae.)."))


def h7_urgency(bodies, rep: Report):
    text = (bodies["text"] + " " + bodies["subject"]).lower()
    hits = sorted({w for w in URGENCY_WORDS if w in text})
    if len(hits) >= 3:
        rep.findings.append(Finding("H7", "Dringlichkeits-/Credential-Sprache", "medium",
                                    "Auffaellige Begriffe: " + ", ".join(hits[:8])))
    elif len(hits) >= 1:
        rep.findings.append(Finding("H7", "Dringlichkeits-/Credential-Sprache", "low",
                                    "Begriffe: " + ", ".join(hits)))


def h8_attachments(msg, rep: Report):
    for part in msg.walk():
        fn = part.get_filename()
        if not fn:
            continue
        low = fn.lower()
        ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
        if ext in DANGEROUS_EXT:
            rep.findings.append(Finding("H8", "Potentiell gefaehrlicher Anhang", "high", fn))
        if low.count(".") >= 2:
            tail = low.rsplit(".", 2)[-2:]
            if ("." + tail[0]) not in DANGEROUS_EXT and ("." + tail[1]) in DANGEROUS_EXT:
                rep.findings.append(Finding("H8", "Doppelte Dateiendung (Tarnung)", "high", fn))


def h9_origin(msg, rep: Report):
    received = msg.get_all("Received", [])
    ips = []
    for r in received:
        for m in re.finditer(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", r):
            ip = m.group(1)
            if not (ip.startswith("10.") or ip.startswith("192.168.")
                    or ip.startswith("127.") or ip.startswith("172.16.")):
                ips.append(ip)
    if ips:
        rep.findings.append(Finding("H9", "Urspruengliche Absender-IP(s) extrahiert", "info",
                                    "Zur manuellen Pruefung (whois/Geo): " + ", ".join(dict.fromkeys(ips))))
    xmailer = msg.get("X-Mailer", "") or msg.get("X-PHP-Script", "")
    if xmailer and ("php" in xmailer.lower() or "x-php-script" in str(msg.keys()).lower()):
        rep.findings.append(Finding("H9", "Hinweis auf Versand per PHP-Skript", "medium",
                                    f"Header deutet auf Massen-/Skript-Versand hin: {xmailer[:80]}"))


def h10_mime(msg, rep: Report, bodies):
    has_html = bodies["has_html"]
    has_text = bodies["has_text"]
    if has_html and not has_text:
        rep.findings.append(Finding("H10", "Nur HTML, kein Text-Teil", "low",
                                    "Reine HTML-Mail ohne text/plain-Alternative (haeufig bei Phishing)."))
    # Base64-kodierter HTML-Body (Verschleierung)
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            enc = (part.get("Content-Transfer-Encoding") or "").lower()
            if enc == "base64":
                rep.findings.append(Finding("H10", "HTML-Body base64-kodiert", "low",
                                            "HTML als base64 - kann Signatur-Scanner umgehen."))
                break


def h11_brand_impersonation(bodies, rep: Report):
    text = (bodies["text"] + " " + bodies["hidden"] + " " + bodies["subject"]).lower()
    from_dom = ""
    if "@" in rep.from_addr:
        from_dom = _registrable(rep.from_addr.split("@")[-1])
    for brand in BRANDS:
        if brand in text and from_dom and brand not in from_dom:
            # nur melden, wenn Marke prominent und Domain fremd
            if text.count(brand) >= 1:
                rep.findings.append(Finding("H11", "Markenimitation im Text", "medium",
                                            f"Text nennt '{brand}', Absenderdomain ist '{from_dom}'."))
                break


# --------------------------------------------------------------------------
# Analyse-Pipeline
# --------------------------------------------------------------------------

def _collect_bodies(msg) -> dict:
    text_parts, html_parts, hidden_parts = [], [], []
    links: list[tuple[str, str]] = []
    has_html = has_text = False
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_maintype() == "multipart":
            continue
        if part.is_attachment():
            continue
        if ctype == "text/plain":
            has_text = True
            text_parts.append(_decode_part(part))
        elif ctype == "text/html":
            has_html = True
            raw = _decode_part(part)
            ex = _TextExtractor()
            try:
                ex.feed(raw)
            except Exception:
                pass
            text_parts.append(" ".join(ex.text_parts))
            hidden_parts.append(" ".join(ex.hidden_parts))
            links.extend(ex.links)
            html_parts.append(raw)
    joined_text = "\n".join(text_parts)
    urls = set(URL_RE.findall(joined_text))
    for raw in html_parts:
        urls.update(URL_RE.findall(raw))
    for href, _ in links:
        if href and href.lower().startswith(("http://", "https://")):
            urls.add(href)
    return {
        "text": joined_text,
        "hidden": "\n".join(hidden_parts),
        "has_html": has_html,
        "has_text": has_text,
        "urls": urls,
        "links": links,
        "subject": str(msg.get("Subject", "")),
    }


def analyze(path: Path) -> Report:
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    disp, addr = parseaddr(str(msg.get("From", "")))
    rep = Report(source=str(path), subject=str(msg.get("Subject", "")),
                 from_display=disp, from_addr=addr)

    bodies = _collect_bodies(msg)
    bodies["subject"] = rep.subject

    h1_sender_homoglyph(msg, rep)
    h2_display_mismatch(msg, rep)
    h3_replyto_returnpath(msg, rep)
    h4_authentication(msg, rep)
    h5_urls(bodies, rep, bodies["links"])
    h6_hidden_text(bodies, rep)
    h7_urgency(bodies, rep)
    h8_attachments(msg, rep)
    h9_origin(msg, rep)
    h10_mime(msg, rep, bodies)
    h11_brand_impersonation(bodies, rep)

    rep.findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    return rep


# --------------------------------------------------------------------------
# Ausgabe
# --------------------------------------------------------------------------

C = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m",
     "info": "\033[90m", "ok": "\033[92m", "bold": "\033[1m", "off": "\033[0m"}


def _c(txt, key, color):
    return f"{C[key]}{txt}{C['off']}" if color else txt


def print_report(rep: Report, color=True):
    print(_c("=" * 64, "bold", color))
    print(_c(f"PhishScan-Report: {rep.source}", "bold", color))
    print("=" * 64)
    print(f"Betreff : {rep.subject}")
    print(f"Von     : {rep.from_display} <{rep.from_addr}>")
    vkey = {"HIGH RISK": "high", "SUSPICIOUS": "medium",
            "LOW RISK": "low", "CLEAN": "ok"}[rep.verdict]
    print(f"Urteil  : {_c(rep.verdict, vkey, color)}  (Score {rep.score}, "
          f"{len(rep.findings)} Finding(s))")
    print("-" * 64)
    if not rep.findings:
        print(_c("Keine verdaechtigen Merkmale gefunden.", "ok", color))
    for f in rep.findings:
        print(f"[{f.hid}] {_c(f.severity.upper(), f.severity, color)}  {f.title}")
        print(f"      {f.detail}")
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="PhishScan - passiver .eml-Phishing-Analyzer (H1-H11). "
                    "Kein Netzwerkzugriff, keine Aenderung der Eingabe.")
    ap.add_argument("paths", nargs="+", help=".eml-Datei(en) oder Ordner")
    ap.add_argument("--json", action="store_true", help="Ausgabe als JSON")
    ap.add_argument("--no-color", action="store_true", help="ohne Farben")
    ap.add_argument("--version", action="version", version=f"PhishScan {VERSION}")
    args = ap.parse_args(argv)

    targets: list[Path] = []
    for p in args.paths:
        pp = Path(p)
        if pp.is_dir():
            targets.extend(sorted(pp.glob("*.eml")))
        elif pp.is_file():
            targets.append(pp)
        else:
            print(f"[!] Nicht gefunden: {p}", file=sys.stderr)
    if not targets:
        print("[!] Keine .eml-Dateien zu analysieren.", file=sys.stderr)
        return 2

    reports = []
    for t in targets:
        try:
            reports.append(analyze(t))
        except Exception as e:  # noqa: BLE001
            print(f"[!] Fehler bei {t}: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(
            [{**asdict(r), "score": r.score, "verdict": r.verdict} for r in reports],
            ensure_ascii=False, indent=2))
    else:
        for r in reports:
            print_report(r, color=not args.no_color)

    return 1 if any(r.verdict in ("HIGH RISK", "SUSPICIOUS") for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
