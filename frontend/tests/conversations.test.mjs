import test from 'node:test'
import assert from 'node:assert/strict'
import { boundedHistory, readConversations, retryTarget, validResult } from '../src/state/conversations.ts'

test('history obeys per-message, aggregate and message-count limits', () => {
  const messages = Array.from({ length: 15 }, (_, i) => ({ id: String(i), role: 'user', content: 'x'.repeat(5000) }))
  const history = boundedHistory(messages)
  assert.equal(history.length, 3)
  assert.equal(history.reduce((n, m) => n + m.content.length, 0), 12000)
  assert.ok(history.every(m => m.content.length <= 4000))
})
test('retry identifies its own user without removing later messages', () => {
  const messages = [{ id: 'u1', role: 'user', content: 'first' }, { id: 'e1', role: 'assistant', content: '', error: 'failed', retryOf: 'u1' }, { id: 'u2', role: 'user', content: 'later' }]
  assert.equal(retryTarget(messages, 'e1').user.content, 'first')
  assert.equal(messages.length, 3)
  assert.equal(retryTarget(messages, 'missing'), null)
})
test('corrupt nested messages and duplicate IDs are rejected', () => {
  assert.throws(() => readConversations('[{"id":"a","title":"t","updatedAt":1,"messages":[null]}]'))
  assert.throws(() => readConversations('broken'))
  assert.deepEqual(readConversations(null), [])
  const c = { id: 'a', title: 't', updatedAt: 1, messages: [] }
  assert.throws(() => readConversations(JSON.stringify([c, c])))
})

test('validated metadata answers persist with sources and skipped generation', () => {
  const result = { answer: 'CVSS 9.8 [1].', conversation_id: 'c', request_id: 'r',
    sources: [{ id: 'nvd', document_excerpt: 'Evidence', metadata: { base_score: 9.8 } }],
    trace: { detected_language: 'es', original_question: 'CVSS?', search_query_en: 'CVSS', translation_status: 'templated',
      retrieval_method: 'cve_metadata', collection: 'catalog', model: 'model', resolved_model: 'model',
      retrieved_count: 1, used_count: 1, generation_status: 'skipped', template_answer: true,
      route: 'cvss_template', llm_calls: 0, retries: 0, chroma_operations: 1, timings_ms: { total: 20 } } }
  assert.equal(validResult(result), true)
  const conversation = { id: 'c', title: 'CVSS', updatedAt: 1, messages: [{ id: 'a', role: 'assistant', content: result.answer, result }] }
  assert.equal(readConversations(JSON.stringify([conversation]))[0].messages[0].result.trace.template_answer, true)
  assert.equal(validResult({ ...result, trace: { ...result.trace, llm_calls: -1 } }), false)
  assert.equal(validResult({ ...result, trace: { ...result.trace, template_answer: 'true' } }), false)
  const legacy = { ...result.trace }
  for (const key of ['template_answer', 'route', 'llm_calls', 'retries', 'chroma_operations']) delete legacy[key]
  assert.equal(validResult({ ...result, trace: legacy }), true)
})
