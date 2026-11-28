import { describe, expect, it } from 'vitest'
import { rightCellDetail, type RightCellStateKind } from '@/features/capsules/lib/exchange-row-state'
import { OWN_RECORD_MISSING, ownRecordMissing, rowCombinationText, WITNESS_HOLDS_IT, type RowCombinationInput } from '@/features/capsules/lib/row-combination'

const ALL_OK = { content: '✓', sig: '✓', inclusion: '✓', registered: '–' } as const

function input(overrides: Partial<RowCombinationInput>): RowCombinationInput {
  return { state: 'closed', roleTag: 'ASKED', yoursHeld: true, marks: ALL_OK, refusedAtTheDoor: false, ...overrides }
}

describe('rowCombinationText -- what the badge and the chips say together', () => {
  it('confirmed: in a checkpoint or newer than it (A2/A3), and says when a witness holds it (A18)', () => {
    expect(rowCombinationText(input({}))).toMatch(/^Both records agree and check out/)
    expect(rowCombinationText(input({ marks: { ...ALL_OK, inclusion: '–' } }))).toMatch(/next one will cover it/)
    expect(rowCombinationText(input({ marks: { ...ALL_OK, registered: '✓' } }))).toContain(WITNESS_HOLDS_IT.trim())
  })

  it('#388: a confirmed SERVED row says the other record names you as its server, never "the node that served you"', () => {
    const served = rowCombinationText(input({ roleTag: 'SERVED' }))
    expect(served).toContain('the node you served signed its own record with the key it announced, and it names you as the node that served it')
    expect(served).not.toContain('served you')
    expect(rowCombinationText(input({}))).toContain('from the node that served you')
  })

  it('#388: a record counts as missing only when the records were fetched after its exchange', () => {
    const fetchedAt = Date.parse('2026-11-28T03:00:00Z')
    const missing = (timestamp: string | null, held = false, at: number | null = fetchedAt) =>
      ownRecordMissing({ capsuleId: 'c1', timestamp, held: () => held, ledgerFetchedAt: at })
    expect(missing('2026-11-28T02:58:00Z')).toBe(true)
    // Served in the gap between the two fetches: not missing yet.
    expect(missing('2026-11-28T02:59:30Z')).toBe(false)
    expect(missing('2026-11-28T03:00:00Z')).toBe(false)
    expect(missing('2026-11-28T02:58:00Z', true)).toBe(false)
    expect(missing('2026-11-28T02:58:00Z', false, null)).toBe(false)
    expect(missing(null)).toBe(false)
  })

  it('a SERVED row never says "sent": not given reads "nothing that arrived" (60d4b649)', () => {
    expect(rowCombinationText(input({ state: 'open_not_given', roleTag: 'SERVED' }))).toMatch(/nothing that arrived names it by its id/)
    expect(rowCombinationText(input({ state: 'open_not_given', roleTag: 'SERVED' }))).not.toMatch(/\bsent\b/)
    expect(rowCombinationText(input({ state: 'open_not_given' }))).toMatch(/nothing they sent names it/)
    expect(rightCellDetail({ kind: 'open_not_given', date: null }, 'SERVED')).toMatch(/nothing that arrived names it by its id/)
    expect(rightCellDetail({ kind: 'open_not_given', date: null }, 'SERVED')).not.toMatch(/they sent/)
  })

  it('#388: a record missing from the loaded records says why and what to do; still loading says "yet"', () => {
    const unloaded = { ...ALL_OK, content: '–', sig: '–' } as const
    expect(rowCombinationText(input({ marks: unloaded }))).toMatch(/isn’t loaded on this page yet/)
    expect(rowCombinationText(input({ marks: unloaded, ownRecordMissing: true }))).toBe(OWN_RECORD_MISSING)
  })

  it('a failed check on your own copy wins over any badge (A15)', () => {
    for (const state of ['closed', 'contradicted', 'open_not_held'] as RightCellStateKind[]) {
      expect(rowCombinationText(input({ state, marks: { ...ALL_OK, content: '✗' } }))).toMatch(/^Your own copy fails its checks/)
      expect(rowCombinationText(input({ state, marks: { ...ALL_OK, sig: '✗' } }))).toMatch(/^Your own copy fails its checks/)
    }
  })

  it('disagreement: refused at the door names another server or model (A6); otherwise the record disagrees (A4/A5)', () => {
    expect(rowCombinationText(input({ state: 'contradicted', refusedAtTheDoor: true }))).toMatch(/another server or another model/)
    expect(rowCombinationText(input({ state: 'contradicted' }))).toMatch(/disagrees with it, or doesn’t match its own id/)
  })

  it('not arrived: never "normally arrives" (their record push may be off); points to the ask the row offers', () => {
    const text = rowCombinationText(input({ state: 'open_not_held' }))
    expect(text).not.toMatch(/normally arrives|usually/)
    expect(text).toMatch(/on by default/)
    expect(text).toMatch(/ask for it on this row/)
  })

  it('a row the pane shows with no other side, whose own record names one, says whom to ask', () => {
    expect(rowCombinationText(input({ state: 'open_not_asked', askPeer: 'ab12cd34' }))).toBe(
      'Their record hasn’t arrived. You can ask ab12cd34 for it.'
    )
  })

  it('only their record, nothing loaded, served locally, unknown other side (A17/A16/A10/A11)', () => {
    expect(rowCombinationText(input({ yoursHeld: false }))).toMatch(/^Only their record exists/)
    expect(rowCombinationText(input({ marks: { content: '–', sig: '–', inclusion: '–', registered: '–' } }))).toMatch(
      /isn’t loaded on this page/
    )
    expect(rowCombinationText(input({ state: 'open_not_asked', roleTag: 'SERVED' }))).toMatch(/You served this yourself/)
    const paid = rowCombinationText(input({ state: 'open_not_asked', roleTag: 'SERVED', servedForPay: true }))
    expect(paid).toMatch(/You served this for pay to another node/)
    expect(paid).not.toMatch(/yourself/)
    expect(rowCombinationText(input({ state: 'open_not_asked', roleTag: 'ASKED' }))).toMatch(/no one to ask/)
  })

  it('every state has its own text, at most two sentences', () => {
    const states: RightCellStateKind[] = [
      'closed', 'contradicted', 'open_refused', 'open_absent', 'open_asked', 'open_not_held', 'open_not_given', 'open_not_asked'
    ]
    const texts = states.map((state) => rowCombinationText(input({ state })))
    expect(new Set(texts).size).toBe(states.length)
    for (const text of texts) expect(text.split(/(?<=[.!?])\s+/).length).toBeLessThanOrEqual(2)
  })
})
