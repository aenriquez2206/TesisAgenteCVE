import type { ChatResponse, Source } from '../types/api'

const states: Record<string, string> = { translated: 'Traducida', templated: 'Consulta preparada localmente', reused: 'Sin traducción', not_required: 'No necesaria', contextualized: 'Referencia resuelta', complete: 'Completada', empty: 'Sin resultados', skipped: 'Omitida' }
const labels: Record<string, string> = { nvd: 'NVD', cwe: 'CWE', capec: 'CAPEC', cpe: 'CPE', exploit: 'Exploit DB' }

function EvidenceCard({ source, index }: { source: Source; index: number }) {
  const title = source.source === 'nvd' ? source.cve_id : source.metadata.entity_id || source.cve_id || source.id
  return <article className="evidence-card">
    <div className="evidence-top"><span>{labels[source.source || ''] || source.source || 'Registro'}</span><span>[{index + 1}]</span></div>
    <h3>{title}</h3>
    <p>{source.document_excerpt.split('\n').slice(1).join('\n').slice(0, 300) || source.document_excerpt.slice(0, 300)}</p>
    <div className="tags">
      {source.source === 'nvd' && source.metadata.severity && <span>{String(source.metadata.severity)}</span>}
      {source.source === 'nvd' && typeof source.metadata.base_score === 'number' && <span>CVSS {source.metadata.base_score}</span>}
      {source.distance != null && <span>Distancia {source.distance.toFixed(3)}</span>}
    </div>
    {source.url && /^https?:\/\//i.test(source.url) && <a href={source.url} target="_blank" rel="noopener noreferrer">Ver referencia ↗</a>}
  </article>
}

export function Evidence({ result }: { result?: ChatResponse }) {
  return <aside className="evidence" aria-label="Evidencia recuperada">
    <h2>Evidencia recuperada</h2>
    {!result && <p className="muted">Las fuentes de la respuesta aparecerán aquí.</p>}
    {result && <>
      <p className="muted">{result.trace.retrieved_count} recuperados · {result.sources.length} usados</p>
      {result.sources.map((source, index) => <EvidenceCard key={source.id} source={source} index={index} />)}
      <section className="trace"><h3>Trazabilidad</h3><dl>
        <div><dt>Idioma</dt><dd>{result.trace.detected_language === 'es' ? 'Español' : 'Inglés'}</dd></div>
        <div><dt>Búsqueda</dt><dd>{result.trace.search_query_en}</dd></div>
        <div><dt>Traducción</dt><dd>{states[result.trace.translation_status] || result.trace.translation_status}</dd></div>
        <div><dt>Preparación</dt><dd>{states[result.trace.preparation_status || ''] || 'Sin estado registrado'}</dd></div>
        <div><dt>Recuperación</dt><dd>{states[result.trace.retrieval_status || ''] || 'Sin estado registrado'}</dd></div>
        <div><dt>Generación</dt><dd>{states[result.trace.generation_status || ''] || 'Sin estado registrado'}</dd></div>
        <div><dt>Solicitud</dt><dd>{result.request_id}</dd></div>
        <div><dt>Colección</dt><dd>{result.trace.collection}</dd></div>
        <div><dt>Modelo</dt><dd>{result.trace.model}</dd></div>
        {result.trace.llm_calls !== undefined && <div><dt>Llamadas al modelo</dt><dd>{result.trace.llm_calls}</dd></div>}
        {result.trace.retries !== undefined && <div><dt>Reintentos</dt><dd>{result.trace.retries}</dd></div>}
        {result.trace.chroma_operations !== undefined && <div><dt>Operaciones Chroma</dt><dd>{result.trace.chroma_operations}</dd></div>}
        {Object.entries(result.trace.timings_ms).map(([stage, ms]) => <div key={stage}><dt>{({ preparation: 'Preparación', embedding: 'Embedding', retrieval: 'Recuperación', generation: 'Generación', model_wait: 'Espera del modelo', validation: 'Validación', total: 'Total' } as Record<string, string>)[stage] || stage}</dt><dd>{ms} ms</dd></div>)}
      </dl></section>
    </>}
  </aside>
}
