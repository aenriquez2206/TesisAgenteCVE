from __future__ import annotations

import asyncio
import logging
import math
import re
import time
import uuid
from collections.abc import Callable

from app.config import Settings
from app.contracts import (ChatRequest, ChatResponse, Source, Trace, QueryPreparer,
                           EmbeddingProvider, VectorRepository, LLMProvider)
from app.errors import AppError
from app.services.query_preparer import CVE
from app.services.query_intent import requested_kinds
from app.services.prompt_builder import select_context, build_prompt
from app.services.answer_validation import (answer_identifiers, supported_identifiers,
                                           validate_answer, restrict_links)
from app.services.metrics import RequestMetrics, current_metrics

logger = logging.getLogger("cve.retrieval")


def cvss_answer(language: str, sources: list[Source], cve_id: str) -> str | None:
    """Only NVD metadata for the requested CVE can supply a structured answer."""
    records = [(index, source) for index, source in enumerate(sources, 1)
               if source.source == "nvd" and source.cve_id == cve_id]
    if not records:
        return None
    # Inconsistent metadata is not safe to summarize with a deterministic template.
    for key in ("base_score", "severity", "cvss_version"):
        values = {str(source.metadata[key]) for _, source in records if source.metadata.get(key) is not None}
        if len(values) > 1:
            return None
    index, source = max(records, key=lambda pair: sum(pair[1].metadata.get(k) is not None
                         for k in ("base_score", "severity", "cvss_version")))
    score, severity, version = (source.metadata.get(k) for k in ("base_score", "severity", "cvss_version"))
    valid_score = type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 10
    if score is not None and not valid_score:
        return None
    if severity is not None and severity not in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", ""):
        return None
    if version is not None and version not in ("2.0", "3.0", "3.1", "4.0", ""):
        return None
    if language == "es":
        severity_es = {"NONE": "ninguna", "LOW": "baja", "MEDIUM": "media", "HIGH": "alta", "CRITICAL": "crítica"}
        parts = [f"{cve_id}: puntuación CVSS: {score}" if valid_score else f"{cve_id}: puntuación CVSS no registrada"]
        parts.append(f"severidad: {severity_es[severity]}" if severity else "severidad no registrada")
        parts.append(f"versión: {version}" if version else "versión CVSS no registrada")
    else:
        parts = [f"{cve_id}: CVSS score: {score}" if valid_score else f"{cve_id}: CVSS score not recorded"]
        parts.append(f"severity: {severity}" if severity else "severity not recorded")
        parts.append(f"version: {version}" if version else "CVSS version not recorded")
    return "; ".join(parts) + f" [{index}]."


def missing_record_answer(language: str, message: str, intent: str | None,
                          sources: list[Source], cve_ids: list[str]) -> str | None:
    # This answers a database-presence question, not a vulnerability explanation
    # or a claim that a weakness/exploit cannot exist outside the retrieved data.
    if intent not in ("cwe", "capec", "cpe", "exploit") or len(cve_ids) != 1:
        return None
    if not re.search(r"\b(?:colección|coleccion|collection|record|registro)\b", message, re.I):
        return None
    if any(source.source == intent for source in sources):
        return None
    if any(identifier.startswith(intent.upper() + '-') for identifier in supported_identifiers(sources)):
        return None
    for index, source in enumerate(sources, 1):
        if source.source == "nvd" and source.cve_id == cve_ids[0]:
            kind = "Exploit DB" if intent == "exploit" else intent.upper()
            return (f"El registro NVD identifica {cve_ids[0]} [{index}]. No se recuperaron registros {kind} asociados."
                    if language == "es" else f"The NVD record identifies {cve_ids[0]} [{index}]. No associated {kind} records were retrieved.")
    return None


class ChatService:
    def __init__(self, settings: Settings, preparer: QueryPreparer, embeddings: EmbeddingProvider,
                 repository: VectorRepository, llm: LLMProvider) -> None:
        self.settings, self.preparer, self.embeddings = settings, preparer, embeddings
        self.repository, self.llm = repository, llm
        self._retrieval_slots = asyncio.Semaphore(4)

    async def _retrieval(self, name: str, fields: dict, query: str, limit: int,
                         call: Callable[[], list[Source]]) -> list[Source]:
        start = time.monotonic()
        fields = dict(fields, collection=self.settings.chroma_collection, operation=name,
                      query=query[:180], top_k=self.settings.top_k, limit=limit)
        logger.info("retrieval_start", extra={"fields": fields})
        try:
            # Retain the permit until the blocking call actually finishes, even on
            # timeout/cancellation. to_thread itself cannot cancel an HTTP operation.
            running = False
            async def bounded_call():
                nonlocal running
                async with self._retrieval_slots:
                    running = True
                    return await asyncio.to_thread(call)
            task = asyncio.create_task(bounded_call())
            task.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
            result = await asyncio.wait_for(asyncio.shield(task), self.settings.chroma_timeout)
        except Exception as exc:
            logger.error("retrieval_failed", extra={"fields": dict(fields,
                duration_ms=round((time.monotonic()-start)*1000), error=getattr(exc, 'code', type(exc).__name__))})
            if isinstance(exc, TimeoutError):
                if not running:
                    task.cancel()
                raise AppError("chroma_timeout", "ChromaDB agotó el tiempo de espera", 504) from exc
            raise
        except asyncio.CancelledError:
            if not running:
                task.cancel()
            raise
        logger.info("retrieval_complete", extra={"fields": dict(fields,
            duration_ms=round((time.monotonic()-start)*1000), result_count=len(result),
            ids=[s.id for s in result], cve_ids=sorted({s.cve_id for s in result if s.cve_id}),
            distances=[s.distance for s in result], sources=[s.source for s in result],
            summaries=[s.document_excerpt[:100] for s in result])})
        return result

    async def run(self, request: ChatRequest, request_id: str | None = None) -> ChatResponse:
        metrics = RequestMetrics()
        token = current_metrics.set(metrics)
        try:
            return await self._run(request, request_id, metrics)
        finally:
            current_metrics.reset(token)

    async def _run(self, request: ChatRequest, request_id: str | None, metrics: RequestMetrics) -> ChatResponse:
        request_id, conversation_id = request_id or str(uuid.uuid4()), request.conversation_id or str(uuid.uuid4())
        fields = {"request_id": request_id, "conversation_id": conversation_id}
        started = time.monotonic()
        logger.info("preparation_start", extra={"fields": fields})
        try:
            prepared = await self.preparer.prepare(request.message.strip(), request.history)
        except Exception as exc:
            logger.warning("preparation_failed", extra={"fields": dict(fields, error=getattr(exc, 'code', type(exc).__name__),
                duration_ms=round((time.monotonic()-started)*1000))})
            raise
        prepared_at = time.monotonic()
        logger.info("preparation_complete", extra={"fields": dict(fields, language=prepared.language,
            translation_status=prepared.status, query=prepared.query_en[:180], intent=prepared.intent,
            duration_ms=round((prepared_at-started)*1000))})
        cve_ids = list(dict.fromkeys(x.upper() for x in CVE.findall(prepared.query_en)))
        exact = prepared.intent in ("description", "cvss") and len(cve_ids) == 1
        embedding_ms = 0
        if exact:
            found = await self._retrieval("metadata_lookup", fields, cve_ids[0], 3,
                lambda: self.repository.grouped(cve_ids[0], ("nvd",)))
            retrieval_started = prepared_at
        else:
            try:
                vector = await asyncio.wait_for(asyncio.to_thread(self.embeddings.embed, prepared.query_en),
                                                self.settings.embedding_timeout)
            except TimeoutError as exc:
                raise AppError("embedding_timeout", "El modelo de embeddings agotó el tiempo de espera", 504) from exc
            retrieval_started = time.monotonic()
            embedding_ms = round((retrieval_started-prepared_at)*1000)
            found = await self._retrieval("vector_search", fields, prepared.query_en, self.settings.top_k,
                lambda: self.repository.search(vector, self.settings.top_k, cve_ids))
        ordered = {s.id: s for s in found}
        if not exact:
            # Explicit CVEs must all receive evidence, even if the shared top-k
            # contains neighbors belonging to only one member of a comparison.
            targets = list(dict.fromkeys(cve_ids + [s.cve_id for s in found if s.cve_id]))
            kinds = requested_kinds(request.message + " " + prepared.query_en, prepared.intent)
            lookups = [asyncio.create_task(self._retrieval("grouped_lookup", fields, f"{cve_id} {','.join(kinds)}",
                3 * len(kinds), lambda cve_id=cve_id: self.repository.grouped(cve_id, kinds))) for cve_id in targets]
            try:
                results = await asyncio.gather(*lookups)
            finally:
                for lookup in lookups:
                    lookup.cancel()
                await asyncio.gather(*lookups, return_exceptions=True)
            for sources in results:
                for source in sources:
                    ordered.setdefault(source.id, source)
        retrieved_at = time.monotonic()
        selected, chunks, generic = select_context(list(ordered.values()), request.message, cve_ids,
            self.settings.context_chars, intent=prepared.intent)
        if len(cve_ids) > 1:
            available = {s.cve_id for s in ordered.values()}
            used = {s.cve_id for s in selected}
            if not (set(cve_ids) & available).issubset(used):
                raise AppError("context_insufficient", "El contexto no permite incluir evidencia de todos los CVE solicitados", 422)
        generation_status, template = "skipped", False
        llm_calls, retries, validation_ms = prepared.llm_calls, prepared.retries, 0.0
        answer = cvss_answer(prepared.language, selected, cve_ids[0]) if prepared.intent == "cvss" and len(cve_ids) == 1 else None
        template_route = "cvss_template"
        if answer is None:
            answer = missing_record_answer(prepared.language, request.message, prepared.intent, selected, cve_ids)
            template_route = "missing_record_template"
        if answer is not None:
            validation_start = time.monotonic()
            error = validate_answer(answer, selected)
            validation_ms += (time.monotonic() - validation_start) * 1000
            if error:
                raise AppError(error, "La respuesta estructurada no coincide con sus fuentes", 502)
            template = True
            logger.info("generation_skipped", extra={"fields": dict(fields, reason="metadata_template")})
        elif not selected:
            answer = ("No encontré registros relacionados en la colección disponible. No puedo confirmar detalles de esa vulnerabilidad."
                if prepared.language == "es" else "I found no related records in the available collection, so I cannot confirm details of that vulnerability.")
            logger.info("generation_skipped", extra={"fields": dict(fields, reason="no_evidence")})
        else:
            score_lines = [cvss_answer(prepared.language, selected, cve_id) for cve_id in cve_ids]
            structured_comparison = prepared.intent == "comparison" and all(score_lines)
            generation_chunks = chunks
            if structured_comparison:
                # Keep deterministic CVSS metadata out of the prose-generation
                # task, then append it with its own citations before validation.
                generation_chunks = [chunk.partition('\n')[0].split('; CVSS ', 1)[0] + '\n' + chunk.partition('\n')[2]
                                     for chunk in chunks]
            system, prompt = build_prompt(prepared.language, request.message, prepared.query_en, generation_chunks, generic,
                                          source_kinds={s.source for s in selected if s.source}, intent=prepared.intent,
                                          structured_comparison=structured_comparison)
            budget = self.settings.comparison_tokens if len(cve_ids) > 1 else self.settings.answer_tokens
            logger.info("generation_start", extra={"fields": dict(fields, max_tokens=budget)})
            try:
                for attempt in range(2):
                    llm_calls += 1
                    retries += int(attempt > 0)
                    try:
                        answer = await self.llm.chat(system, prompt, max_tokens=budget)
                        if structured_comparison:
                            answer += '\n\n' + '\n'.join(score_lines)
                        validation_start = time.monotonic()
                        error = validate_answer(answer, selected)
                        validation_ms += (time.monotonic() - validation_start) * 1000
                    except AppError as exc:
                        if exc.code != "llm_truncated" or attempt:
                            raise
                        error, answer = exc.code, ""
                        budget = self.settings.comparison_tokens
                    allowed_ids, answer_ids = supported_identifiers(selected), answer_identifiers(answer)
                    logger.info("generation_validation", extra={"fields": dict(fields,
                        attempt=attempt + 1, max_tokens=budget, valid=error is None, error=error,
                        answer_identifiers=sorted(answer_ids), rejected_identifiers=sorted(answer_ids - allowed_ids),
                        allowed_identifiers=sorted(allowed_ids), source_ids=[s.id for s in selected],
                        source_kinds=[s.source for s in selected])})
                    if not error:
                        break
                    if attempt:
                        raise AppError(error, "No se pudo generar una respuesta respaldada por las fuentes", 502)
                    prompt += f"\nValidation failed: {error}. Regenerate in at most 60 words using only supplied evidence and valid [n] citations."
                answer = restrict_links(answer, selected)
            except Exception as exc:
                logger.warning("generation_failed", extra={"fields": dict(fields,
                    error=getattr(exc, 'code', type(exc).__name__), duration_ms=round((time.monotonic()-retrieved_at)*1000))})
                raise
            generation_status = "complete"
            logger.info("generation_complete", extra={"fields": dict(fields, source_count=len(selected),
                duration_ms=round((time.monotonic()-retrieved_at)*1000))})
        finished = time.monotonic()
        return ChatResponse(answer=answer, conversation_id=conversation_id, request_id=request_id, sources=selected,
            trace=Trace(detected_language=prepared.language, original_question=request.message,
                search_query_en=prepared.query_en, translation_status=prepared.status,
                retrieval_method="cve_metadata" if exact else "cve_filter_and_vector" if cve_ids else "vector",
                retrieved_count=len(ordered), used_count=len(selected), retrieval_status="complete" if ordered else "empty",
                generation_status=generation_status, collection=self.settings.chroma_collection,
                model=self.settings.llm_model, resolved_model=self.llm.resolved_model,
                route=template_route if template else "exact_cve" if exact else "semantic",
                template_answer=template, llm_calls=llm_calls, retries=retries,
                chroma_operations=metrics.chroma_operations,
                timings_ms={"preparation": round((prepared_at-started)*1000), "embedding": embedding_ms,
                    "retrieval": round((retrieved_at-retrieval_started)*1000), "generation": round((finished-retrieved_at)*1000),
                    "model_wait": round(metrics.model_wait_ms), "validation": round(validation_ms),
                    "total": round((finished-started)*1000)}))
