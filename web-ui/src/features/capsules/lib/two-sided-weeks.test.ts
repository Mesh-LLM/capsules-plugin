import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { type OtherSide, earlierLine, twoSidedWeeks, undatedLine, weekLine, weekStartOf } from '@/features/capsules/lib/two-sided-weeks'

const row = (key: string, timestamp: string | null) => ({ exchange_key: key, timestamp }) as unknown as PaneCRow

describe('two-sided exchanges by week', () => {
  it('starts weeks on the UTC Monday', () => {
    expect(weekStartOf('2026-11-23T06:46:00Z')).toBe('2026-11-23') // a Monday
    expect(weekStartOf('2026-11-22T23:59:59Z')).toBe('2026-11-16') // the Sunday before
    expect(weekStartOf('2026-11-29T00:00:00Z')).toBe('2026-11-23')
    expect(weekStartOf('not a time')).toBeNull()
    // A zone-less time names no one instant, so no one week.
    expect(weekStartOf('2026-11-23T00:30:00')).toBeNull()
    expect(weekStartOf(null)).toBeNull()
  })

  it('counts both halves held per week, split into matching and differing, newest first', () => {
    const sides: Record<string, OtherSide> = { a: 'matching', b: 'differing', c: 'not_held', d: 'matching', e: 'not_held' }
    const { weeks, undated, earlierWeeks } = twoSidedWeeks(
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
    expect(undated).toEqual({ exchanges: 1, matching: 0, differing: 0 })
    expect(earlierWeeks).toBe(0)
    expect(undatedLine(undated)).toBe("1 exchange has no time, so no week: 0 of 1 with both sides' records held (0 matching, 0 differing).")
    expect(weekLine(weeks[0])).toBe("2 of 3 with both sides' records held (1 matching, 1 differing)")
  })

  it('keeps only the newest weeks', () => {
    const rows = Array.from({ length: 10 }, (_, i) => row(`r${i}`, new Date(Date.UTC(2026, 8, 7 + 7 * i)).toISOString()))
    const { weeks, earlierWeeks, earlier } = twoSidedWeeks(rows, (r) => (r.exchange_key === 'r0' ? 'matching' : 'not_held'), 8)
    expect(weeks).toHaveLength(8)
    expect(earlierWeeks).toBe(2)
    expect(earlier).toEqual({ exchanges: 2, matching: 1, differing: 0 })
    expect(earlierLine(earlierWeeks, earlier)).toBe("2 earlier weeks, not listed: 1 of 2 with both sides' records held (1 matching, 0 differing).")
    expect(weeks[0].weekStart > weeks[7].weekStart).toBe(true)
  })
})
