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
