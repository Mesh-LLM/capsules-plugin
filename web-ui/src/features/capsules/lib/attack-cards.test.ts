import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { buildAttackCards } from '@/features/capsules/lib/attack-cards'
import { HERO_BY_ROLE, HERO_DESCRIPTION, pageRole } from '@/features/capsules/lib/tooltip-copy'

function row(overrides: Record<string, unknown> = {}): PaneCRow {
  return {
    exchange_key: 'k',
    role_tag: 'served',
    mine: { state: 'present' },
    theirs: { state: 'absent' },
    ...overrides
  } as unknown as PaneCRow
}

describe('buildAttackCards', () => {
  it('reads "N/M unchanged" and shows what is not checked, never a guess', () => {
    const [rewrote, leftOut, swapped] = buildAttackCards({ records: 13, covered: 13, witness: 'off', rows: [] })
    expect(rewrote).toMatchObject({ title: 'Rewrote the record', badge: '13/13 unchanged', tone: 'good' })
    expect(buildAttackCards({ records: 13, covered: 9, witness: 'off', rows: [] })[0].badge).toBe('9/13 unchanged')
    expect(rewrote.rows.map((r) => [r.label, r.value])).toEqual([
      ['Sealed when it happened', '13'],
      ['In a signed checkpoint', '13/13'],
      ['Held by an outside witness', 'off · only you can check']
    ])
    expect(rewrote.action).toEqual({ label: 'Turn on a witness', target: 'integrity' })
    expect(leftOut.badge).toBe('no peer record yet')
    expect(leftOut.rows.at(-1)).toMatchObject({ label: 'Their full history compared', value: 'not checked' })
    expect(swapped).toMatchObject({ badge: 'not checked', tone: 'muted', action: null })
  })

  it('says nothing is sealed yet for an empty node and reports missing coverage as "not reported"', () => {
    const [empty] = buildAttackCards({ records: 0, covered: null, witness: 'unknown', rows: [] })
    expect(empty.badge).toBe('not checked')
    const [partial] = buildAttackCards({ records: 4, covered: null, witness: 'latest', rows: [] })
    expect(partial.rows[1].value).toBe('not reported')
    expect(partial.action).toBeNull()
  })

  const adjudicated = (verdict: string) => ({ state: 'adjudicated', verdict, referee: 'r', tier: 1 })
  const half = (bracket: string, referee_row: unknown, extra: Record<string, unknown> = {}) =>
    row({ twin: { bracket_id: bracket, same_answer: false, other_row: 'x', referee_row, ...extra } })

  it('counts a pair once and always shows how many were checked', () => {
    const [, , swapped] = buildAttackCards({
      records: 4,
      covered: 4,
      witness: 'off',
      rows: [
        half('b1', adjudicated('contradicted:abcd')),
        half('b1', adjudicated('contradicted:abcd')),
        half('b2', adjudicated('corroborated')),
        half('b3', adjudicated('inconclusive'))
      ]
    })
    expect(swapped).toMatchObject({ badge: '1 caught · 3 checked', tone: 'bad' })
    expect(swapped.rows.map((r) => r.value)).toEqual(['3 pairs', '1 caught · 3 checked'])
    expect(swapped.action).toEqual({ label: 'Open the verdict', target: 'exchanges' })
  })

  it('with nothing asked it reads "not checked"; "not comparable" and an unjudged pair are no check', () => {
    const [, , swapped] = buildAttackCards({
      records: 2,
      covered: 2,
      witness: 'off',
      rows: [
        half('b1', { state: 'not_adjudicated', reason: 'twins_agree' }),
        half('b2', adjudicated('not_comparable')),
        half('b3', null)
      ]
    })
    expect(swapped).toMatchObject({ badge: 'not checked', tone: 'muted', action: null })
    expect(swapped.rows[1].value).toBe('not checked')
  })

  it('never reads another node\'s ask or an inferred mismatch', () => {
    const [, , swapped] = buildAttackCards({
      records: 2,
      covered: 2,
      witness: 'off',
      rows: [
        // A verdict a referee delivered to this node about its own answer: someone else's ask.
        row({ adjudication: { verdict: 'contradicted:me', about_this_node: true, referee_node_id: 'r' } }),
        // The two answers differ, but nobody was asked: an inferred mismatch.
        half('b1', null, { same_answer: false })
      ]
    })
    expect(swapped.badge).toBe('not checked')
  })

  it('a half the door refused counts as a disagreement and as a counterparty, even with no record received', () => {
    const refused = row({
      theirs: { state: 'absent', capsule_id: null, evidence_outcome: 'claims_refused', evidence_outcome_reason: 'model_mismatch' }
    })
    const [, leftOut] = buildAttackCards({ records: 1, covered: 1, witness: 'off', rows: [refused] })
    expect(leftOut).toMatchObject({ badge: '1 of 1 differ', tone: 'bad' })
    expect(leftOut.rows.map((r) => r.value)).toEqual(['1/1', '0/1', 'not checked'])
  })

  it('offers "Turn on a witness" only when the witness is off or unknown', () => {
    const actionFor = (witness: 'off' | 'unknown' | 'pending' | 'earlier' | 'latest') =>
      buildAttackCards({ records: 2, covered: 2, witness, rows: [] })[0].action
    expect(actionFor('off')).not.toBeNull()
    expect(actionFor('unknown')).not.toBeNull()
    for (const on of ['pending', 'earlier', 'latest'] as const) expect(actionFor(on)).toBeNull()
  })
})

describe('the page speaks for its role (#388)', () => {
  it('reads the role from the rows: all asked, all served, or both; none says nothing', () => {
    expect(pageRole(['ASKED', 'ASKED'])).toBe('buying')
    expect(pageRole(['SERVED'])).toBe('selling')
    expect(pageRole(['SERVED', 'FAILED', 'ASKED'])).toBe('both')
    expect(pageRole(['FAILED'])).toBeNull()
    expect(pageRole([])).toBeNull()
  })

  it('each role has its own label and header line; buying keeps today\'s line', () => {
    expect(HERO_BY_ROLE.buying.description).toBe(HERO_DESCRIPTION)
    expect(HERO_BY_ROLE.selling.description).not.toMatch(/gave you|cheat you/)
    expect(new Set(Object.values(HERO_BY_ROLE).map((h) => h.label)).size).toBe(3)
  })

  it('a node that only sells reads the swapped-model card from the seller\'s side; titles stay', () => {
    const selling = buildAttackCards({ records: 1, covered: 1, witness: 'off', rows: [], role: 'selling' })
    const buying = buildAttackCards({ records: 1, covered: 1, witness: 'off', rows: [], role: 'buying' })
    expect(selling[2].summary).toMatch(/your answers came from the model you advertised/)
    expect(buying[2].summary).toBe('A peer serves a cheaper model or quant than it advertised.')
    expect(selling.map((card) => card.title)).toEqual(buying.map((card) => card.title))
  })
})
