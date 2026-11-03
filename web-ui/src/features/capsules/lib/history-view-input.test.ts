import { HISTORY_CHECK_IDS, historyViewHtml } from '@action-state-group/capsule-viewer/history-view'
import { describe, expect, it } from 'vitest'
import { NOT_RUN, PERIOD_COUNTS_NOT_RUN, type HistoryVerdict } from '@/features/capsules/lib/history-verify'
import { historyViewInput } from '@/features/capsules/lib/history-view-input'

const context = {
  nodeKeyId: 'b'.repeat(64),
  savedAt: '2026-11-03T04:00:00Z',
  builtBy: 'test',
  sharing: {
    standard_history: true,
    history_segments: 'peers',
    record_at_completion: 'counterparty',
    adjudications: 'off',
    exchange_corroboration: true
  } as const
}

describe('historyViewInput', () => {
  it('maps every check id the verifier can report onto the view’s closed list', () => {
    const ids = ['readable', 'refusal', 'artifact_digest', 'card_digest', 'card', 'checkpoints', 'chain', 'consistency', 'anchor']
    const verdict: HistoryVerdict = {
      kind: 'answered',
      verified: false,
      checks: [...ids.map((id) => ({ id, status: 'pass' as const, detail: '' })), PERIOD_COUNTS_NOT_RUN, ...NOT_RUN],
      checkpoints: []
    }
    const input = historyViewInput(verdict, context)
    for (const check of input.checks) expect(HISTORY_CHECK_IDS).toContain(check.id)
    expect(input.checks.length).toBe(new Set(input.checks.map((c) => c.id)).size)
    expect(NOT_RUN.every((c) => input.checks.some((m) => m.status === 'not_run'))).toBe(true)
  })

  it('draws a verified answer, every row not time-stamped and not countersigned', () => {
    const verdict: HistoryVerdict = {
      kind: 'answered',
      verified: true,
      checks: [{ id: 'checkpoints', status: 'pass', detail: '' }, ...NOT_RUN],
      checkpoints: [{ size: 5, time: '2026-11-03T01:00:00Z', anchor: 'ab'.repeat(32) }],
      keyId: 'c'.repeat(64)
    }
    const input = historyViewInput(verdict, context)
    expect(input.holder.node).toBe('c'.repeat(64))
    expect(input.rows[0]).toMatchObject({ signature: 'pass', witness: { state: 'not_checked' }, second_signature: { state: 'not_checked' } })
    expect(() => historyViewHtml(input)).not.toThrow()
  })
})
