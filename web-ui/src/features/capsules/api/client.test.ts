import { describe, expect, it } from 'vitest'
import { servedHistoryFrom } from '@/features/capsules/api/client'

const KEY = 'a'.repeat(64)
const reply = (fields: Record<string, unknown>) => `${JSON.stringify(fields)}\n`

describe('servedHistoryFrom', () => {
  it('takes a card the node signed under its own key, bytes unchanged', () => {
    const text = reply({ responder: KEY, derivation: 'history_card/1' })
    expect(servedHistoryFrom({ form: 'history_card/1', outcome: 'answered', reply: text, node_key_id: KEY })).toEqual({
      replyText: text,
      outcome: 'answered',
      form: 'history_card'
    })
  })

  it('names a Service History by its form', () => {
    const text = reply({ responder: KEY })
    expect(servedHistoryFrom({ form: 'service_history/1', outcome: 'answered', reply: text, node_key_id: KEY }).form).toBe('service_history')
  })

  it('refuses a card signed under another key', () => {
    const text = reply({ responder: 'b'.repeat(64) })
    expect(() => servedHistoryFrom({ form: 'history_card/1', outcome: 'answered', reply: text, node_key_id: KEY })).toThrow(
      'signed under another key'
    )
    expect(() => servedHistoryFrom({ form: 'history_card/1', outcome: 'answered', reply: reply({ responder: KEY }) })).toThrow(
      'signed under another key'
    )
  })

  it('takes a refusal as it is, which names no responder', () => {
    const text = reply({ reason: 'coverage_unsatisfiable', sig: '00' })
    expect(servedHistoryFrom({ form: 'history_card/1', outcome: 'refused', reply: text, node_key_id: KEY }).outcome).toBe('refused')
  })

  it('refuses a body that is not a history', () => {
    for (const body of [null, 'text', {}, { outcome: 'answered', reply: 7 }, { outcome: 'maybe', reply: '{}' }]) {
      expect(() => servedHistoryFrom(body)).toThrow('this node did not give its history')
    }
  })
})
