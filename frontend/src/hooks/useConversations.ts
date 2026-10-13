import { useEffect, useRef, useState } from 'react'
import { sendChat } from '../api/client'
import { readConversations, retryTarget, storageKey } from '../state/conversations'
import type { Conversation, Message } from '../types/api'

function initial() {
  try { return { conversations: readConversations(localStorage.getItem(storageKey)), warning: '' } }
  catch { return { conversations: [] as Conversation[], warning: 'No se pudo leer el historial local. Las nuevas conversaciones se guardarán si el navegador lo permite.' } }
}

export function useConversations() {
  const [loaded] = useState(initial)
  const [conversations, setConversations] = useState(loaded.conversations)
  const [storageWarning, setStorageWarning] = useState(loaded.warning)
  const [selected, setSelected] = useState<string | null>(loaded.conversations[0]?.id || null)
  const [pendingId, setPendingId] = useState<string | null>(null)
  const lock = useRef(false)
  const busy = pendingId !== null
  useEffect(() => {
    try { localStorage.setItem(storageKey, JSON.stringify(conversations)) }
    catch { setStorageWarning('No se pudo guardar el historial. Esta conversación solo estará disponible durante la sesión actual.') }
  }, [conversations])
  const active = conversations.find(c => c.id === selected)

  function newConversation() { setSelected(null) }

  async function perform(id: string, user: Message, history: Message[], errorId?: string) {
    try {
      const result = await sendChat(user.content, id, history)
      const assistant: Message = { id: errorId || crypto.randomUUID(), role: 'assistant', content: result.answer, result }
      setConversations(previous => previous.map(c => c.id === id ? { ...c, updatedAt: Date.now(),
        messages: errorId ? c.messages.map(m => m.id === errorId ? assistant : m) : [...c.messages, assistant] } : c))
    } catch (error) {
      const assistant: Message = { id: errorId || crypto.randomUUID(), role: 'assistant', content: '', retryOf: user.id,
        error: error instanceof Error ? error.message : 'Error desconocido' }
      setConversations(previous => previous.map(c => c.id === id ? { ...c,
        messages: errorId ? c.messages.map(m => m.id === errorId ? assistant : m) : [...c.messages, assistant] } : c))
    } finally { lock.current = false; setPendingId(null) }
  }

  function send(text: string) {
    const content = text.trim()
    if (!content || lock.current) return
    lock.current = true
    const id = selected || crypto.randomUUID()
    setPendingId(id)
    const existing = conversations.find(c => c.id === id)
    const history = existing?.messages || []
    const user: Message = { id: crypto.randomUUID(), role: 'user', content }
    setConversations(previous => [{ id, title: existing?.title || content.slice(0, 48), updatedAt: Date.now(),
      messages: [...history, user] }, ...previous.filter(c => c.id !== id)])
    setSelected(id)
    void perform(id, user, history)
  }

  function retry(errorId: string) {
    if (!active || lock.current) return
    const target = retryTarget(active.messages, errorId)
    if (!target) return
    lock.current = true
    setPendingId(active.id)
    void perform(active.id, target.user, target.history, errorId)
  }

  return { conversations, selected, setSelected, active, busy, pendingId, send, retry, newConversation, storageWarning }
}
