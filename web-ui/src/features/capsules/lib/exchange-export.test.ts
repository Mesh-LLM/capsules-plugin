import { describe, expect, it } from 'vitest'
import { exchangeRowsToCsv } from '@/features/capsules/lib/exchange-export'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'

function row(overrides: Partial<ExchangeLedgerRow>): ExchangeLedgerRow {
  return {
    exchangeKey: 'exch-1',
    timestamp: '2026-09-08T00:00:00Z',
    roleTag: 'ASKED',
    counterparty: 'node:aa11bb22',
    confirmed: true,
    localOnly: false,
    hasIssue: false,
    checksText: '—',
    rightCellState: { kind: 'closed', date: null },
    contentToggleState: { your: { kind: 'populated', date: null }, their: { kind: 'not_asked', date: null } },
    sessionId: null,
    twinBracketId: null,
    raw: {} as PaneCRow,
    ...overrides
  }
}

describe('exchangeRowsToCsv', () => {
  it('is a distinct view export — the header names exactly the table columns', () => {
    const csv = exchangeRowsToCsv([row({})])
    const [header] = csv.split('\n')
    expect(header).toBe('Time,Exchange ID,Counterparty,Your role,Confirmed,Checks')
  })

  it('never renders Checks as a count in the CSV either', () => {
    const csv = exchangeRowsToCsv([row({ checksText: 'checkpoint signed' })])
    expect(csv).toContain('checkpoint signed')
    expect(csv).not.toMatch(/\d\/\d/)
  })

  it('quotes a field containing a comma', () => {
    const csv = exchangeRowsToCsv([row({ checksText: 'checkpoint signed, continuity' })])
    expect(csv).toContain('"checkpoint signed, continuity"')
  })
})
