"""Conservative, full-question matching for common CVE questions.

Extra clauses, product/version constraints and instructions fall back to the LLM.
These rules never translate unrestricted user text.
"""
import re
import unicodedata

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

PATTERNS = {
    "description": (
        r"(?:que es|what is|describe|explica|explain) (?:el )?ID(?: en espanol| in english)?",
        r"(?:resume la descripcion de|describe la vulnerabilidad|explica la vulnerabilidad) ID",
        r"ID",
    ),
    "cvss": (
        r"(?:cual es el|what is the) (?:cvss|cvss score|score) (?:de |of |for )?ID",
        r"(?:que|what) (?:puntuacion cvss|puntuacion y severidad|puntuacion|score|cvss|severidad|severity) (?:tiene|registra|has) ID",
        r"(?:indica|muestra|dame|show) (?:el )?(?:cvss|severidad y puntuacion|puntuacion y severidad|severidad|severity) (?:para|de|for) ID",
    ),
    "cwe": (
        r"(?:que debilidad cwe se relaciona con|indica la clase de debilidad para|which cwe is associated with|explica la debilidad vinculada a) ID",
        r"(?:describe|explica|explain|show|muestra) (?:la |el |the )?(?:cwe|debilidad cwe) (?:de|para|for|of|associated with) ID",
        r"la coleccion registra una debilidad cwe para ID",
    ),
    "capec": (
        r"(?:que patron de ataque se asocia a|explicame el patron de ataque asociado a|explica sus patrones capec|which attack pattern is linked to|describe el patron de ataque de|what attack patterns are related to) ID",
        r"(?:describe|explica|explain|show|muestra) (?:el |the )?capec (?:de|para|for|of) ID",
        r"la coleccion contiene un patron capec para ID",
    ),
    "cpe": (
        r"(?:que productos y versiones aparecen para|lista las versiones afectadas documentadas de|which product versions are listed for|resume las entradas de producto de|que productos estan afectados por) ID",
    ),
    "exploit": (
        r"(?:hay un exploit asociado a|que referencia de exploit registra|is an exploit record available for|la coleccion contiene un exploit de|cual es el exploit publico confirmado para) ID",
        r"hay un registro de exploit en la coleccion para ID",
    ),
    "mitigation": (
        r"(?:que mitigacion especifica consta para|hay una solucion documentada para|is a cve-specific mitigation documented for|que recomienda la fuente para corregir|que mitigacion especifica documenta|como se mitiga|how is mitigated|como puedo mitigar riesgo) ID",
    ),
    "impact": (
        r"(?:que impacto documenta|resume las consecuencias descritas para|what impact is documented for|que podria permitir) ID(?: segun la descripcion)?",
        r"(?:what is the impact of|cual es el impacto de) ID",
    ),
}

QUERIES = {
    "description": "Describe {cve}.", "cvss": "CVSS score and severity of {cve}.",
    "cwe": "CWE weaknesses associated with {cve}.",
    "capec": "CAPEC attack patterns associated with {cve}.",
    "cpe": "Affected products and versions of {cve}.",
    "exploit": "Exploit records associated with {cve}.",
    "mitigation": "Documented mitigation of {cve}.", "impact": "Documented impact of {cve}.",
}


def normalize(text: str) -> str:
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return " ".join(re.sub(r"[¿¡?:.!]", " ", text.lower()).split())


def fast_intent(message: str) -> str | None:
    if len(CVE.findall(message)) != 1:
        return None
    normalized = CVE.sub("ID", normalize(message))
    for intent, patterns in PATTERNS.items():
        if any(re.fullmatch(pattern, normalized) for pattern in patterns):
            return intent
    return None


def simple_comparison(message: str) -> list[str]:
    identifiers = list(dict.fromkeys(x.upper() for x in CVE.findall(message)))
    if len(identifiers) != 2:
        return []
    if re.fullmatch(r"(?:compara|compare) ID (?:y|and) ID(?: descripcion severidad y diferencias| description severity and differences)?",
                    CVE.sub("ID", normalize(message.replace(',', ' ')))):
        return identifiers
    return []


def requested_kinds(message: str, intent: str | None) -> tuple[str, ...]:
    """Always retain NVD as context, including when a related type is absent."""
    if intent in ("description", "cvss", "impact", "mitigation"):
        return ("nvd",)
    if intent in ("cwe", "capec", "cpe", "exploit"):
        return ("nvd", intent)
    kinds = ["nvd"]
    text = normalize(message)
    for kind, pattern in (("cwe", r"cwe|weakness|debilidad"),
                          ("capec", r"capec|attack pattern|patron.*ataque"),
                          ("cpe", r"cpe|product|version"), ("exploit", r"exploit")):
        if re.search(pattern, text):
            kinds.append(kind)
    return tuple(kinds)
