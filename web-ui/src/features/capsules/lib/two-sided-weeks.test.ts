import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { type OtherSide, twoSidedWeeks, weekLine, weekStartOf } from '@/features/capsules/lib/two-sided-weeks'

const row = (key: string, timestamp: string | null) => ({ exchange_key: key, timestamp }) as unknown as PaneCRow

describe('two-sided exchanges by week', () => {
  it('starts weeks on the UTC Monday', () => {
    expect(weekStartOf('2026-11-23T06:46:00Z')).toBe('2026-11-23') // a Monday
    expect(weekStartOf('2026-11-22T23:59:59Z')).toBe('2026-11-16') // the Sunday before
    expect(weekStartOf('2026-11-29T00:00:00Z')).toBe('2026-11-23')
    expect(weekStartOf('not a time')).toBeNull()
    expect(weekStartOf(null)).toBeNull()
  })

  it('counts both halves held per week, split into matching and differing, newest first', () => {
    const sides: Record<string, OtherSide> = { a: 'matching', b: 'differing', c: 'not_held', d: 'matching', e: 'not_held' }
    const { weeks, undated } = twoSidedWeeks(
      [
        row('a', '2026-11-23T06:46:00Z'),
        row('b', '2026-11-24T10:00:00Z'),
        row('c', '2026-11-25T10:00:00Z'),
        row('d', '2026-11-17T10:00:00Z'),
        row('e', null)
      ],
      (r) => sides[r.exchange_key]
    )
    expect(weeks).toEqual([
      { weekStart: '2026-11-23', exchanges: 3, matching: 1, differing: 1 },
      { weekStart: '2026-11-16', exchanges: 1, matching: 1, differing: 0 }
    ])
    expect(undated).toBe(1)
    expect(weekLine(weeks[0])).toBe("2 of 3 with both sides' records held (1 matching, 1 differing)")
  })

  it('keeps only the newest weeks', () => {
    const rows = Array.from({ length: 10 }, (_, i) => row(`r${i}`, new Date(Date.UTC(2026, 8, 7 + 7 * i)).toISOString()))
    const { weeks } = twoSidedWeeks(rows, () => 'not_held', 8)
    expect(weeks).toHaveLength(8)
    expect(weeks[0].weekStart > weeks[7].weekStart).toBe(true)
  })
})
