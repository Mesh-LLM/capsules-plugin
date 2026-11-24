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

  it('draws the checkpoints, with failed time-stamp slots, when only the witness check fails', () => {
    const verdict: HistoryVerdict = {
      kind: 'answered',
      verified: false,
      checks: [{ id: 'checkpoints', status: 'pass', detail: '' }, { id: 'witness_receipts', status: 'fail', detail: '' }, ...NOT_RUN.filter((c) => c.id !== 'witness_receipts')],
      checkpoints: [{ size: 5, time: '2026-11-03T01:00:00Z', anchor: 'ab'.repeat(32), witness: { state: 'failed' } }],
      keyId: 'c'.repeat(64)
    }
    const html = historyViewHtml(historyViewInput(verdict, context))
    expect(html).toContain('Time stamps didn')
    expect(html).not.toContain('No checkpoints yet')
    // A failed signature check still hides them.
    const bad: HistoryVerdict = { ...verdict, checks: [{ id: 'checkpoints', status: 'fail', detail: '' }] }
    expect(historyViewInput(bad, context).rows).toEqual([])
  })

  it('draws a passed time-stamp slot as stamped, in the chip and on the row', () => {
    const verdict: HistoryVerdict = {
      kind: 'answered',
      verified: true,
      checks: [{ id: 'checkpoints', status: 'pass', detail: '' }, { id: 'witness_receipts', status: 'pass', detail: '' }],
      checkpoints: [{ size: 5, time: '2026-11-03T01:00:00Z', anchor: 'ab'.repeat(32), witness: { state: 'passed', by: 'w', at: '2026-11-03T02:00:00Z' } }],
      keyId: 'c'.repeat(64)
    }
    const html = historyViewHtml(historyViewInput(verdict, context))
    expect(html).toContain('Time-stamped: all 1')
    expect(html).not.toContain('Time stamps not checked here')
  })

  describe('the witness check names the checkpoint the witness has not registered', () => {
    const cp = (i: number, witness: HistoryVerdict['checkpoints'][number]['witness']) => ({
      size: 10 * (i + 1),
      time: `2026-11-03T0${i}:00:00Z`,
      anchor: `${i}`.repeat(64),
      ...(witness ? { witness } : {})
    })
    const stamped = { state: 'passed', by: 'w', at: '2026-11-03T09:00:00Z' } as const
    const verdictOf = (checkpoints: HistoryVerdict['checkpoints'], witnessStatus: 'pass' | 'not_run' = 'not_run'): HistoryVerdict => ({
      kind: 'answered',
      verified: true,
      checks: [{ id: 'checkpoints', status: 'pass', detail: '' }, { id: 'witness_receipts', status: witnessStatus, detail: '' }],
      checkpoints,
      keyId: 'c'.repeat(64)
    })
    const witnessCheck = (v: HistoryVerdict) => historyViewInput(v, context).checks.find((c) => c.id === 'witness')

    it('sends the last checkpoint when it has no registered receipt and every earlier one is stamped', () => {
      const v = verdictOf([cp(1, stamped), cp(2, stamped), cp(3, { state: 'not_checked', unregistered: true })])
      expect(witnessCheck(v)).toEqual({ id: 'witness', status: 'not_run', values: { n: 3, at: '2026-11-03T03:00:00Z' } })
      // The view takes it, and the chip and the list name the same checkpoint.
      const text = historyViewHtml(historyViewInput(v, context))
      expect(text).toContain('Time-stamped: 2 of 3')
      expect(text).toContain('A witness time-stamped these records. Checkpoint 3 (cut ')
    })

    it('sends a middle checkpoint when it is the only one without a registered receipt', () => {
      const open = { state: 'not_checked', unregistered: true } as const
      const v = verdictOf([cp(1, stamped), cp(2, open), cp(3, stamped)])
      expect(witnessCheck(v)).toEqual({ id: 'witness', status: 'not_run', values: { n: 2, at: '2026-11-03T02:00:00Z' } })
      const text = historyViewHtml(historyViewInput(v, context))
      expect(text).toContain('Time-stamped: 2 of 3')
      expect(text).toContain('A witness time-stamped these records. Checkpoint 2 (cut ')
    })

    it('sends nothing for a last checkpoint that is not checked for any other reason', () => {
      // No keys, a receipt without a time, an algorithm this browser cannot check: never "not registered".
      const v = verdictOf([cp(1, stamped), cp(2, { state: 'not_checked' })])
      expect(witnessCheck(v)).toEqual({ id: 'witness', status: 'not_run' })
    })

    it('sends nothing when two checkpoints are open, one failed, or there is only one checkpoint', () => {
      const open = { state: 'not_checked', unregistered: true } as const
      expect(witnessCheck(verdictOf([cp(1, stamped), cp(2, open), cp(3, open)]))).toEqual({ id: 'witness', status: 'not_run' })
      expect(witnessCheck(verdictOf([cp(1, { state: 'failed' }), cp(2, open)]))).toEqual({ id: 'witness', status: 'not_run' })
      expect(witnessCheck(verdictOf([cp(1, open)]))).toEqual({ id: 'witness', status: 'not_run' })
    })

    it('sends nothing when every checkpoint is stamped', () => {
      expect(witnessCheck(verdictOf([cp(1, stamped), cp(2, stamped)], 'pass'))).toEqual({ id: 'witness', status: 'pass' })
    })
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
