import { HISTORY_CHECK_IDS, historyViewHtml } from '@action-state-group/capsule-viewer/history-view'
import { describe, expect, it } from 'vitest'
import { NOT_RUN, PERIOD_COUNTS_NOT_RUN, VERIFIER_CHECK_IDS, type HistoryVerdict } from '@/features/capsules/lib/history-verify'
import { CHECK_ID, historyViewInput } from '@/features/capsules/lib/history-view-input'

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
    expect(Object.keys(CHECK_ID).sort()).toEqual([...VERIFIER_CHECK_IDS].sort())
    for (const mapped of Object.values(CHECK_ID)) expect(HISTORY_CHECK_IDS).toContain(mapped)
    // Every id the verifier reports, passing; the always-not-run ones come from NOT_RUN.
    const notRun = new Set<string>([...NOT_RUN, PERIOD_COUNTS_NOT_RUN].map((c) => c.id))
    const ids = VERIFIER_CHECK_IDS.filter((id) => !notRun.has(id))
    const verdict: HistoryVerdict = {
      kind: 'answered',
      verified: false,
      checks: [...ids.map((id) => ({ id, status: 'pass' as const, detail: '' })), PERIOD_COUNTS_NOT_RUN, ...NOT_RUN],
      checkpoints: []
    }
    const input = historyViewInput(verdict, context)
    for (const check of input.checks) expect(HISTORY_CHECK_IDS).toContain(check.id)
    expect(input.checks.length).toBe(new Set(input.checks.map((c) => c.id)).size)
    expect(input.checks.filter((c) => c.status === 'not_run').map((c) => c.id)).toEqual(
      expect.arrayContaining(['witness', 'envelope_signature', 'key_is_node', 'reply_bound', 'period_counts'])
    )
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

  it('keeps node-supplied text inside what the view accepts', () => {
    for (const reason of ['', 'x'.repeat(300)]) {
      const refusal: HistoryVerdict = { kind: 'refused', verified: false, checks: [{ id: 'refusal', status: 'not_run', detail: '' }], checkpoints: [], reason }
      expect(() => historyViewHtml(historyViewInput(refusal, context))).not.toThrow()
    }
  })

  it('does not say a complementary count is under the floor', () => {
    const verdict: HistoryVerdict = {
      kind: 'answered',
      verified: true,
      checks: [],
      checkpoints: [{ size: 5, time: '2026-11-03T01:00:00Z', anchor: 'ab'.repeat(32) }],
      keyId: 'c'.repeat(64),
      counts: [
        {
          from: '2026-10-26',
          to: '2026-11-01',
          cells: [
            { what: 'model a', value: 'withheld (below the floor)' },
            { what: 'model b', value: 'withheld (showing it would let a count under the floor be worked out)' }
          ]
        }
      ]
    }
    const html = historyViewHtml(historyViewInput(verdict, context))
    expect(html).toContain('model a: fewer than 5')
    expect(html).not.toContain('model b: fewer than 5')
    expect(html).toContain('model b: withheld')
  })
})
