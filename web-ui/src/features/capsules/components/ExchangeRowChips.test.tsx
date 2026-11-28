import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { TooltipProvider } from '@/components/ui/tooltip'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { RecomputedIdentity } from '@/features/capsules/lib/recompute-identity'
import { ExchangeRowChips } from '@/features/capsules/components/ExchangeRowChips'
import { buildChecksRows, type ChecksRow } from '@/features/capsules/lib/security-checks-view'
import { witnessCoverageLine, type WitnessCoverage } from '@/features/capsules/lib/integrity-view'
import { ENTRY_CHIP_RESULT_TOOLTIPS, THEIRS_CONFIRMED_SERVED } from '@/features/capsules/lib/tooltip-copy'

const NOT_RECOMPUTED: RecomputedIdentity = { idMatch: null, signatureOk: null }

function paneCRow(overrides: Partial<PaneCRow> = {}): PaneCRow {
  return {
    exchange_key: 'exch-1',
    role_tag: 'ASKED',
    header_state: 'ok',
    properties: null,
    has_issue: false,
    mine: { state: 'present', capsule_id: 'mine-1' },
    theirs: { state: 'absent', capsule_id: null },
    unilateral: false,
    timestamp: '2026-11-28T02:21:22Z',
    ...overrides
  }
}

function checks(state: Record<string, string>): ChecksRow[] {
  return Object.entries(state).map(([key, wire]) => ({
    key,
    label: key,
    group: 'yours',
    yours: { state: wire, label: wire.toLowerCase(), detail: '' },
    theirs: null
  })) as ChecksRow[]
}

function renderChips(rows: ChecksRow[], witnessOff = false, witnessCoverage: WitnessCoverage | null = null, served = false) {
  render(
    <TooltipProvider>
      <ExchangeRowChips checks={rows} onChipActivate={vi.fn()} served={served} witnessCoverage={witnessCoverage} witnessOff={witnessOff} />
    </TooltipProvider>
  )
}

describe('ExchangeRowChips -- one tooltip per result, not one per chip', () => {
  it('a ✓, a ✗ and a – on the same chip each say what that result means', () => {
    renderChips(checks({ content_binding: 'PASS', producer_signature: 'FAIL' }))
    expect(screen.getByLabelText('words match: jump to that check')).toHaveAccessibleDescription(
      ENTRY_CHIP_RESULT_TOOLTIPS.content['✓']
    )
    expect(screen.getByLabelText('signed: jump to that check')).toHaveAccessibleDescription(
      ENTRY_CHIP_RESULT_TOOLTIPS.sig['✗']
    )
    expect(screen.getByLabelText('witnessed: jump to that check')).toHaveAccessibleDescription(
      ENTRY_CHIP_RESULT_TOOLTIPS.registered['–']
    )
  })

  it('every chip has a distinct text for each of its marks (✓, ✗, – and the checkpoint chip’s ◐)', () => {
    for (const byMark of Object.values(ENTRY_CHIP_RESULT_TOOLTIPS)) {
      expect(new Set(Object.values(byMark)).size).toBe(Object.keys(byMark).length)
    }
    expect(Object.keys(ENTRY_CHIP_RESULT_TOOLTIPS.inclusion)).toContain('◐')
  })

  it('never claims the checkpoint coverage or a witness receipt is checked on this page', () => {
    expect(ENTRY_CHIP_RESULT_TOOLTIPS.inclusion['✓']).toContain('doesn’t check that coverage itself')
    expect(ENTRY_CHIP_RESULT_TOOLTIPS.registered['✓']).toContain('isn’t checked on this page')
  })

  it('#411: the witnessed chip says the record\'s witness coverage, the same words its checks panel shows', () => {
    const at = '2026-11-28T02:00:00Z'
    const covered: WitnessCoverage = { kind: 'covered', at }
    renderChips(checks({}), false, covered)
    const chip = screen.getByLabelText('witnessed: jump to that check')
    expect(chip).toHaveTextContent('◐')
    const panel = buildChecksRows(paneCRow({ properties: null }), NOT_RECOMPUTED, undefined, { witnessCoverage: covered })
    const detail = panel.find((r) => r.key === 'external_registration')?.yours?.detail
    expect(detail).toBe(witnessCoverageLine(covered))
    expect(chip).toHaveAccessibleDescription(detail!)
  })

  it('#388: on a SERVED row "their record ✓" says the record names you as its server', () => {
    renderChips(checks({ outcome_corroboration: 'PASS' }), false, null, true)
    expect(screen.getByLabelText('their record: jump to that check')).toHaveAccessibleDescription(THEIRS_CONFIRMED_SERVED)
    expect(THEIRS_CONFIRMED_SERVED).toContain('signed a record, with the key it announced, naming you as the node that served it')
  })

  it('with the witness off, no "witnessed" chip: it could only ever read –', () => {
    renderChips(checks({ content_binding: 'PASS' }), true)
    expect(screen.queryByLabelText('witnessed: jump to that check')).not.toBeInTheDocument()
    expect(screen.getByLabelText('words match: jump to that check')).toBeInTheDocument()
    expect(screen.getByLabelText('their record: jump to that check')).toBeInTheDocument()
  })
})
