"""Mechanical grounding checks; these cannot establish semantic truth."""
import json
import re
from app.contracts import Source
from app.services.query_preparer import CVE

CITATION = re.compile(r"\[(\d+)\]")
# Version prefixes such as v1.0.0 must not turn the supported number into
# the suffix 0.0 while the model's equivalent wording contains 1.0.0.
DECIMAL = re.compile(r"(?<![\d.])\d+(?:\.\d+)+(?![\d.])")
IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+)\b", re.I)
SCORE = re.compile(r"\b(?:CVSS(?:\s*v?\d\.\d)?\s*(?:score|base|puntuación|puntaje)?|score|puntuación|puntaje)\s*(?:is|of|es|de|:|=)?\s*(\d+(?:\.\d+)?)", re.I)
CVSS_VERSION = re.compile(r"\bCVSS\s+v?(2\.0|3\.[01]|4\.0)(?=\s*(?:[:,;(]|score|base|puntuación|puntaje|\[|[.!?]|$))", re.I)
LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


def validate_answer(answer: str, sources: list[Source]) -> str | None:
    # Only the displayed [n] contract is accepted, including after a retry.
    if re.search(r"\[\d+\s*[,;–-]", answer):
        return "invalid_citations"
    citations = {int(x) for x in CITATION.findall(answer)}
    if not citations or any(n < 1 or n > len(sources) for n in citations):
        return "invalid_citations"
    evidence = "\n".join(s.document_excerpt + "\n" + json.dumps(s.metadata) for s in sources)
    if set(DECIMAL.findall(answer)) - set(DECIMAL.findall(evidence)):
        return "unsupported_numbers"
    identifiers = supported_identifiers(sources, evidence)
    if answer_identifiers(answer) - identifiers:
        return "unsupported_identifiers"
    # Require scores to appear in the cited metadata, never in the user's question.
    for sentence in re.split(r"(?<=[.!?])\s+|\n", re.sub(r"[*`_]", "", answer)):
        refs = {int(x) for x in CITATION.findall(sentence)} or citations
        versions = {str(sources[n-1].metadata.get('cvss_version')) for n in refs}
        # A standard version label is not a score. Preserve decimal grounding
        # above, then check the actual score against the cited NVD metadata.
        scores = SCORE.findall(CVSS_VERSION.sub(
            lambda match: "CVSS" if match.group(1) in versions else match.group(), sentence))
        if not scores:
            continue
        allowed = {float(sources[n-1].metadata['base_score']) for n in refs
                   if isinstance(sources[n-1].metadata.get('base_score'), (int, float))}
        if any(float(score) not in allowed for score in scores):
            return "unsupported_numbers"
    return None


def answer_identifiers(answer: str) -> set[str]:
    """Return normalized CVE, CWE and CAPEC identifiers in a generated answer."""
    return {identifier.upper() for identifier in IDENTIFIER.findall(answer)}


def supported_identifiers(sources: list[Source], evidence: str | None = None) -> set[str]:
    """Identifiers supported by retrieved text or type-checked index metadata."""
    if evidence is None:
        evidence = "\n".join(source.document_excerpt + "\n" + json.dumps(source.metadata)
                              for source in sources)
    identifiers = {identifier.upper() for identifier in IDENTIFIER.findall(evidence)}
    for source in sources:
        if source.cve_id and CVE.fullmatch(source.cve_id):
            identifiers.add(source.cve_id.upper())
        kind = source.metadata.get("content_type")
        entity = source.metadata.get("entity_id")
        if not isinstance(kind, str) or not isinstance(entity, str):
            continue
        kind = kind.casefold()
        if kind == "cwe" and re.fullmatch(r"CWE-\d+", entity, re.IGNORECASE):
            identifiers.add(entity.upper())
        elif kind == "capec" and re.fullmatch(r"\d+", entity):
            identifiers.add(f"CAPEC-{entity}")
    return identifiers


def restrict_links(answer: str, sources: list[Source]) -> str:
    allowed = {source.url for source in sources if source.url}
    return LINK.sub(lambda m: m.group(0) if m.group(2) in allowed else
                    f"[{m.group(1)}]" if m.group(1).isdigit() else m.group(1), answer)
