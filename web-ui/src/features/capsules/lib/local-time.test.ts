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
  it('keeps year and seconds apart, with the zone named', () => {
    const a = formatExchangeTimestampFull('2026-11-28T02:21:22Z', CHICAGO)
    const b = formatExchangeTimestampFull('2026-11-28T02:21:23Z', CHICAGO)
    const nextYear = formatExchangeTimestampFull('2027-11-28T02:21:22Z', CHICAGO)
    expect(a).not.toBe(b)
    expect(a).toMatch(/2026/)
    expect(nextYear).toMatch(/2027/)
    expect(a).toMatch(/CST|GMT-6/)
  })
})

describe('formatUtcTimestamp', () => {
  it('prints a saved page\'s time in UTC with the zone said, whatever the input offset', () => {
    expect(formatUtcTimestamp('2026-11-28T02:21:22Z')).toBe('2026-11-28T02:21:22 UTC')
    expect(formatUtcTimestamp('2026-11-27T20:21:22-06:00')).toBe('2026-11-28T02:21:22 UTC')
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
