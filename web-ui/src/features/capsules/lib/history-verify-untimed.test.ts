// A witness receipt that verifies but states no registration time cannot be shown as time-stamped,
// so the check list and every slot say "not checked" together instead of the list saying Checked.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it, vi } from 'vitest'

// `only`: the 1-based calls (one per checkpoint, in checkpoint order) that lose their time; null means all.
const untimed: { only: number[] | null; calls: number } = { only: null, calls: 0 }

vi.mock('@action-state-group/agent-action-capsule/witness', async (importOriginal) => {
  const real = await importOriginal<typeof import('@action-state-group/agent-action-capsule/witness')>()
  return {
    ...real,
    checkAnchorWitnessed: async (...args: Parameters<typeof real.checkAnchorWitnessed>) => {
      const call = ++untimed.calls
      const report = await real.checkAnchorWitnessed(...args)
      return untimed.only === null || untimed.only.includes(call) ? { ...report, witnessed_time: null } : report
    }
  }
})

import { verifyHistoryReply } from '@/features/capsules/lib/history-verify'

const witnessed = readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/history_card_2_witnessed.json'), 'utf8')
const KEY = '302a300506032b6570032100d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da'

describe('a verified receipt with no registration time', () => {
  it('is not checked in the list and in every slot', async () => {
    const v = await verifyHistoryReply(witnessed, { witnesses: [{ name: 'w', keys: [KEY] }] })
    expect(v.verified).toBe(true)
    expect(v.checks.find((c) => c.id === 'witness_receipts')!.status).toBe('not_run')
    for (const c of v.checkpoints) expect(c.witness).toEqual({ state: 'not_checked' })
  })

  it('is not Checked in the list when only an earlier checkpoint lacks its time and the last one passes (#359)', async () => {
    untimed.only = [1]
    untimed.calls = 0
    try {
      const v = await verifyHistoryReply(witnessed, { witnesses: [{ name: 'w', keys: [KEY] }] })
      expect(v.verified).toBe(true)
      expect(v.checks.find((c) => c.id === 'witness_receipts')!.status).toBe('not_run')
      // Not "unregistered": a witness may hold it, so the line never says it is not registered.
      expect(v.checkpoints[0]!.witness).toEqual({ state: 'not_checked' })
      expect(v.checkpoints[v.checkpoints.length - 1]!.witness?.state).toBe('passed')
    } finally {
      untimed.only = null
    }
  })
})
