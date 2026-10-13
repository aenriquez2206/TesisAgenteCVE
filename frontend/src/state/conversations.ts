import type { Conversation, Message, ChatResponse } from '../types/api.ts'

export const storageKey = 'cve-intelligence-conversations-v1'
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value)
const string = (value: unknown): value is string => typeof value === 'string'

export function validResult(value: unknown): value is ChatResponse {
  if (!object(value) || !string(value.answer) || !string(value.conversation_id) || !string(value.request_id) || !Array.isArray(value.sources) || !object(value.trace)) return false
  const trace = value.trace
  return value.sources.every(s => object(s) && string(s.id) && string(s.document_excerpt) && object(s.metadata)
    && Object.values(s.metadata).every(v => v === null || ['string', 'number', 'boolean'].includes(typeof v))
    && ['cve_id', 'source', 'url'].every(k => s[k] == null || string(s[k]))
    && (s.distance == null || (typeof s.distance === 'number' && Number.isFinite(s.distance))))
    && ['es', 'en'].includes(String(trace.detected_language))
    && ['original_question', 'search_query_en', 'translation_status', 'retrieval_method', 'collection', 'model', 'resolved_model'].every(k => string(trace[k]))
    && ['retrieved_count', 'used_count'].every(k => Number.isInteger(trace[k]) && Number(trace[k]) >= 0)
    && (trace.preparation_status === undefined || trace.preparation_status === 'complete')
    && (trace.retrieval_status === undefined || ['complete', 'empty'].includes(String(trace.retrieval_status)))
    && (trace.generation_status === undefined || ['complete', 'skipped'].includes(String(trace.generation_status)))
    && (trace.route == null || string(trace.route))
    && (trace.template_answer === undefined || typeof trace.template_answer === 'boolean')
    && ['llm_calls', 'retries', 'chroma_operations'].every(k => trace[k] === undefined || (Number.isInteger(trace[k]) && Number(trace[k]) >= 0))
    && object(trace.timings_ms) && Object.values(trace.timings_ms).every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0)
}

export function readConversations(raw: string | null): Conversation[] {
  const value: unknown = JSON.parse(raw || '[]')
  if (!Array.isArray(value) || !value.every(c => object(c) && string(c.id) && string(c.title)
    && typeof c.updatedAt === 'number' && Number.isFinite(c.updatedAt) && Array.isArray(c.messages)
    && c.messages.every(m => object(m) && string(m.id) && ['user', 'assistant'].includes(String(m.role)) && string(m.content)
      && (m.error === undefined || string(m.error)) && (m.retryOf === undefined || string(m.retryOf))
      && (m.result === undefined || validResult(m.result)))
    && new Set(c.messages.map(m => (m as Message).id)).size === c.messages.length)
    || new Set(value.map(c => c.id)).size !== value.length) throw new Error('Historial inválido')
  return value as Conversation[]
}

export function boundedHistory(messages: Message[]) {
  const result: { role: 'user' | 'assistant'; content: string }[] = []
  let remaining = 12000
  for (const message of [...messages].reverse()) {
    if (message.error || !message.content.trim()) continue
    if (result.length === 10 || remaining === 0) break
    const content = Array.from(message.content).slice(0, Math.min(4000, remaining)).join('')
    result.unshift({ role: message.role, content })
    remaining -= Array.from(content).length
  }
  return result
}

export function retryTarget(messages: Message[], errorId: string) {
  const index = messages.findIndex(m => m.id === errorId && m.error)
  if (index < 1) return null
  const failed = messages[index]
  const userIndex = failed.retryOf ? messages.findIndex(m => m.id === failed.retryOf) : index - 1
  if (userIndex < 0 || userIndex >= index || messages[userIndex].role !== 'user') return null
  return { user: messages[userIndex], history: messages.slice(0, userIndex), errorId }
}
