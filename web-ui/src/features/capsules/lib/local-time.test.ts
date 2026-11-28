import { describe, expect, it } from 'vitest'
import {
  formatExchangeTimestamp,
  formatExchangeTimestampFull,
  formatUtcTimestamp,
  localDateParts,
  localDayKey
} from '@/features/capsules/lib/local-time'

// Sherlock2's ruling on #408: the live page uses local time with the zone
// named, and day headers bucket in that same zone. These tests pin a zone so
// they read the same on any machine.
const CHICAGO = 'America/Chicago'

describe('formatExchangeTimestamp', () => {
  it('names the zone on every time it prints', () => {
    const text = formatExchangeTimestamp('2026-11-28T02:21:22Z', CHICAGO)
    expect(text).toMatch(/CST|GMT-6/)
    expect(text).toMatch(/8:21/)
    expect(text).not.toMatch(/Z$|T\d/)
  })

  it('keeps the unavailable and unparseable cases as they were', () => {
    expect(formatExchangeTimestamp(null)).toBe('timestamp unavailable')
    expect(formatExchangeTimestamp('not a time')).toBe('not a time')
  })
})

describe('formatExchangeTimestampFull', () => {
  it('keeps the year, never seconds (times are kept to the minute), with the zone named', () => {
    const a = formatExchangeTimestampFull('2026-11-28T02:21:00Z', CHICAGO)
    const nextYear = formatExchangeTimestampFull('2027-11-28T02:21:00Z', CHICAGO)
    expect(a).toMatch(/2026/)
    expect(a).toMatch(/8:21/)
    // No seconds field (h:mm:ss); an on-the-hour time still reads "9:00".
    expect(a).not.toMatch(/\d:\d\d:\d\d/)
    expect(formatExchangeTimestampFull('2026-11-28T03:00:00Z', CHICAGO)).toMatch(/9:00 PM/)
    expect(nextYear).toMatch(/2027/)
    expect(a).toMatch(/CST|GMT-6/)
  })
})

describe('formatUtcTimestamp', () => {
  it('prints a saved page\'s time in UTC with the zone said, whatever the input offset', () => {
    // capsule-viewer's R6 words form, to the minute, never ":00" seconds.
    expect(formatUtcTimestamp('2026-11-28T02:21:22Z')).toBe('Nov 28, 2026, 02:21 UTC')
    expect(formatUtcTimestamp('2026-11-27T20:21:22-06:00')).toBe('Nov 28, 2026, 02:21 UTC')
    expect(formatUtcTimestamp('2026-10-27T22:09:00Z')).toBe('Oct 27, 2026, 22:09 UTC')
    expect(formatUtcTimestamp('not a time')).toBe('not a time')
  })
})

describe('localDayKey and localDateParts', () => {
  it('8:21 PM Chicago is still the 27th there, though it is the 28th in UTC', () => {
    expect(localDayKey(new Date('2026-11-28T02:21:22Z'), CHICAGO)).toBe('2026-11-27')
    expect(localDayKey(new Date('2026-11-28T02:21:22Z'), 'UTC')).toBe('2026-11-28')
    expect(localDateParts('2026-11-28T02:21:22Z', CHICAGO)).toEqual({ day: 27, month: 'Nov', year: 2026 })
  })

  it('an unparseable time has no date parts', () => {
    expect(localDateParts('not a time')).toBeNull()
  })
})
