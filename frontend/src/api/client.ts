import type { ChatResponse, Health, Message } from '../types/api'

import { boundedHistory, validResult } from '../state/conversations'

const base = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')

export async function sendChat(message: string, conversationId: string, history: Message[]): Promise<ChatResponse> {
  const response = await fetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, conversation_id: conversationId,
      history: boundedHistory(history) }),
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(`${body.message || `Error HTTP ${response.status}`}${body.request_id ? ` · Solicitud ${body.request_id}` : ''}`)
  if (!validResult(body)) throw new Error('El servidor devolvió una respuesta inválida')
  return body as ChatResponse
}

export async function fetchHealth(): Promise<Health> {
  const response = await fetch(`${base}/api/health`)
  if (!response.ok) throw new Error('No se pudo consultar la salud del servicio')
  return response.json() as Promise<Health>
}
