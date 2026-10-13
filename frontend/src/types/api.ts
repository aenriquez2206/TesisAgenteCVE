export type Source = {
  id: string
  document_excerpt: string
  metadata: Record<string, string | number | boolean | null>
  cve_id?: string | null
  source?: string | null
  url?: string | null
  distance?: number | null
}

export type Trace = {
  detected_language: 'es' | 'en'
  original_question: string
  search_query_en: string
  translation_status: string
  retrieval_method: string
  retrieved_count: number
  used_count: number
  collection: string
  model: string
  resolved_model: string
  timings_ms: Record<string, number>
}

export type ChatResponse = {
  answer: string
  conversation_id: string
  request_id: string
  sources: Source[]
  trace: Trace
}

export type Health = {
  backend: string
  chroma: string
  embeddings: string
  llm: string
  collection: string
  document_count?: number
}

export type Message = {
  id: string
  role: 'user' | 'assistant'
  content: string
  result?: ChatResponse
  error?: string
}

export type Conversation = { id: string; title: string; messages: Message[]; updatedAt: number }
