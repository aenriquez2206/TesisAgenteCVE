import type { ChatResponse, Source } from '../types/api'

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
    {source.url && <a href={source.url} target="_blank" rel="noopener noreferrer">Ver referencia ↗</a>}
  </article>
}

export function Evidence({ result }: { result?: ChatResponse }) {
  return <aside className="evidence" aria-label="Evidencia recuperada">
    <h2>Evidencia recuperada</h2>
    {!result && <p className="muted">Las fuentes de la respuesta aparecerán aquí.</p>}
    {result && <>
      <p className="muted">{result.sources.length} registros usados</p>
      {result.sources.map((source, index) => <EvidenceCard key={source.id} source={source} index={index} />)}
      <section className="trace"><h3>Trazabilidad</h3><dl>
        <div><dt>Idioma</dt><dd>{result.trace.detected_language === 'es' ? 'Español' : 'Inglés'}</dd></div>
        <div><dt>Búsqueda</dt><dd>{result.trace.search_query_en}</dd></div>
        <div><dt>Colección</dt><dd>{result.trace.collection}</dd></div>
        <div><dt>Modelo</dt><dd>{result.trace.model}</dd></div>
      </dl></section>
    </>}
  </aside>
}
