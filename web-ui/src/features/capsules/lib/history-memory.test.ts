import { afterEach, describe, expect, it, vi } from 'vitest'
import { historyNote } from '@/features/capsules/lib/ask-for-history'
import {
  HISTORY_MEMORY_KEY,
  loadVerifiedHistories,
  newestRowPerPeer,
  rememberVerifiedHistory
} from '@/features/capsules/lib/history-memory'

afterEach(() => vi.restoreAllMocks())

describe('the last verified history per peer, kept in this browser', () => {
  it('keeps a verified result per peer, with its witness standing, and reads it back after a reload', () => {
    const verified = { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 4, witness: 'witnessed' } as const
    const map = rememberVerifiedHistory(new Map(), 'peer-a', verified)
    expect(map.get('peer-a')).toEqual(verified)
    expect(loadVerifiedHistories().get('peer-a')).toEqual(verified)
    const unwitnessed = { kind: 'verified', at: '2026-10-22T11:00:00Z', checkpoints: 2, witness: 'unwitnessed' } as const
    rememberVerifiedHistory(map, 'peer-b', unwitnessed)
    expect(loadVerifiedHistories().get('peer-b')).toEqual(unwitnessed)
    expect(historyNote(loadVerifiedHistories().get('peer-a')!)?.verified).toBe(true)
  })

  it('keeps that a remembered history was a sample, and drops any other stored value', () => {
    const sampled = { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 12, witness: 'witnessed', sampled: true } as const
    rememberVerifiedHistory(new Map(), 'peer-s', sampled)
    expect(loadVerifiedHistories().get('peer-s')).toEqual(sampled)
    window.localStorage.setItem(
      HISTORY_MEMORY_KEY,
      JSON.stringify({ odd: { ...sampled, sampled: 'yes' } })
    )
    expect(loadVerifiedHistories().get('odd')).not.toHaveProperty('sampled')
  })

  it('an entry stored before the witness standing was kept reads back as "not recorded", never as witnessed', () => {
    window.localStorage.setItem(
      HISTORY_MEMORY_KEY,
      JSON.stringify({
        old: { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 4 },
        odd: { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 4, witness: 'trusted' }
      })
    )
    const loaded = loadVerifiedHistories()
    expect(loaded.get('old')).toEqual({ kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 4, witness: 'not_recorded' })
    expect(loaded.get('odd')?.witness).toBe('not_recorded')
    const note = historyNote(loaded.get('old')!)
    expect(note?.verified).toBe(false)
    expect(note?.detail).toContain('witness standing was not recorded')
    expect(`${note?.text} ${note?.detail}`).not.toMatch(/✓|checks out|verified/i)
  })

  it('keeps nothing for a refusal or a failure', () => {
    const before = new Map()
    expect(rememberVerifiedHistory(before, 'peer-a', { kind: 'refused', at: 'x', reason: 'not_authorized' })).toBe(before)
    expect(rememberVerifiedHistory(before, 'peer-a', { kind: 'failed', at: 'x', detail: 'd' })).toBe(before)
    expect(window.localStorage.getItem(HISTORY_MEMORY_KEY)).toBeNull()
  })

  it('skips anything unreadable in storage', () => {
    window.localStorage.setItem(
      HISTORY_MEMORY_KEY,
      JSON.stringify({ good: { kind: 'verified', at: 't', checkpoints: null }, bad: { kind: 'failed' }, odd: 3 })
    )
    expect([...loadVerifiedHistories().keys()]).toEqual(['good'])
    window.localStorage.setItem(HISTORY_MEMORY_KEY, 'not json')
    expect(loadVerifiedHistories().size).toBe(0)
  })

  it('works without storage: nothing remembered, and a new result still shows this visit', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    expect(loadVerifiedHistories().size).toBe(0)
    const map = rememberVerifiedHistory(new Map(), 'peer-a', { kind: 'verified', at: 't', checkpoints: 1, witness: 'witnessed' })
    expect(map.get('peer-a')?.checkpoints).toBe(1)
  })
})

describe('which row shows a peer’s remembered history', () => {
  it('only that peer’s newest row', () => {
    const newest = newestRowPerPeer([
      { key: 'old-a', peerId: 'a', timestamp: '2026-09-01T10:00:00Z' },
      { key: 'new-a', peerId: 'a', timestamp: '2026-09-03T10:00:00Z' },
      { key: 'mid-a', peerId: 'a', timestamp: '2026-09-02T10:00:00Z' },
      { key: 'only-b', peerId: 'b', timestamp: null },
      { key: 'nobody', peerId: null, timestamp: '2026-09-09T10:00:00Z' }
    ])
    expect(newest).toEqual(
      new Map([
        ['a', 'new-a'],
        ['b', 'only-b']
      ])
    )
  })

  it('a row with a time beats one without', () => {
    const newest = newestRowPerPeer([
      { key: 'untimed', peerId: 'a', timestamp: null },
      { key: 'timed', peerId: 'a', timestamp: '2026-09-01T10:00:00Z' }
    ])
    expect(newest.get('a')).toBe('timed')
  })
})
