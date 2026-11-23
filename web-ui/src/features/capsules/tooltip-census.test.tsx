// Tooltip census (UX review §8). Renders
// the real Evidence tab -- Peers, Exchanges (every row state, a TWIN pair, a
// CLOSED row's cells, the chip strip), one row's checks panel, and Integrity --
// and checks every chip TYPE the tab ships:
//   1. it renders with a tooltip (hover + a persistent aria-describedby copy);
//   2. that tooltip is short plain copy with no retired or banned phrase;
//   3. outside Dig (the checks panel), none of the engineer's words either.
// A chip type that ships without a tooltip, or with a retired phrase, fails.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { PaneCListJson, PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { HARNESS_PANE_B_PAYLOAD } from '@/features/capsules/lib/peer-fixtures'
import { fixtureMineCell, fixtureTheirsCell } from '@/features/capsules/lib/pushed-half-fixtures'
import {
  buildSetupSteps,
  continuityFact,
  coverageBadge,
  recordsStripBreakdown,
  recordsStripHeading,
  sealedBreakdownText
} from '@/features/capsules/lib/integrity-view'
import {
  rightCellAction,
  rightCellStatusLabel,
  rightCellText,
  type RightCellStateKind
} from '@/features/capsules/lib/exchange-row-state'
import { peerAttention } from '@/features/capsules/lib/peer-row-view'
import * as COPY from '@/features/capsules/lib/tooltip-copy'
import { LedgerPageContent } from '@/features/capsules/pages/LedgerPage'
import { STANDING_WORD } from '@/features/capsules/lib/banned-terms'

// ---------------------------------------------------------------------------
// The words. BANNED: never on screen, even negated (§8 rule 4). ENGINEER: fine
// in Dig, never outside it (§8 rule 3).
// ---------------------------------------------------------------------------
const BANNED = new RegExp(`\\b(${STANDING_WORD}|score|scores|rating|ranking|judgement|judgment|proven|trust score)\\b`, 'i')
const ENGINEER = /\b(half|halves|capsule id|leaf|leaves|recomputed?|corroboration)\b|expand checks to fetch it/i

function checkWords(text: string, where: 'dig' | 'face'): string[] {
  const problems: string[] = []
  if (BANNED.test(text)) problems.push(`banned word: "${text}"`)
  if (where === 'face' && ENGINEER.test(text)) problems.push(`engineer's word outside Dig: "${text}"`)
  return problems
}

// ---------------------------------------------------------------------------
// The census: every chip type the tab ships, and where it lives.
// ---------------------------------------------------------------------------
const ALL_KINDS: RightCellStateKind[] = [
  'closed',
  'contradicted',
  'open_refused',
  'open_absent',
  'open_asked',
  'open_not_held',
  'open_not_given',
  'open_not_asked'
]

const REQUIRED = {
  hero: [] as string[],
  peers: [
    'peer_column:exchanges',
    'peer_column:rewrote',
    'peer_column:leftOut',
    'peer_column:swapped',
    'peer_column:period',
    // A disagreement and a differing answer are the Left-something-out and Swapped columns now;
    // the self-reported note is the sentence above the table.
    'peer_attention:logFailed',
    'peers:through_split'
  ],
  exchanges: [
    ...ALL_KINDS.map((kind) => `row_state:${kind}`),
    // The verdict's (i): the longer sentences moved off the face.
    'row:verdict_detail',
    'twin:no_verdict',
    'split:stage_cell',
    'split:handoffs',
    // A paid exchange’s payment chips.
    'settlement:paid',
    'settlement_state:settled',
    'settlement_state:outcome_not_reported',
    'settlement:provider_book',
    // An exchange this node served for pay: its own book as the provider.
    'settlement:served_for_pay',
    'provider_settlement_state:settled',
    // A service evidence agreement: one covered row, and a paid row under none.
    'agreement_coverage:covered',
    'agreement_coverage:no_agreement',
    'agreement_finding:accepted_before_action',
    'agreement:side',
    'agreement:spend_cap'
  ],
  // The checks panel always shows at least these two (they are always
  // checked in the browser); every other chip it shows must carry one too.
  // UX §3: the CLOSED per-property cells lead the expansion of a CLOSED row.
  checks: [
    // The per-check chips sit at the top of "How we checked".
    'entry_chip:content',
    'entry_chip:sig',
    'entry_chip:inclusion',
    'entry_chip:registered',
    'entry_chip:theirs',
    'closed_cell:their_id',
    'closed_cell:signature',
    'closed_cell:request',
    'closed_cell:response',
    'check_chip:content_binding',
    'check_chip:producer_signature'
  ],
  integrity: [
    'integrity_tile:Sealed',
    'integrity_tile:Confirmed by the other side',
    'integrity_tile:Disagreements',
    'integrity:chain_strip',
    'integrity:close_card',
    'integrity:close_card_counts'
  ]
} as const

// ---------------------------------------------------------------------------
// Fixtures: one Pane C row per right-cell state, a TWIN pair, pushed halves.
// ---------------------------------------------------------------------------
function row(key: string, overrides: Partial<PaneCRow>): PaneCRow {
  return {
    exchange_key: key,
    role_tag: 'ASKED',
    counterparty: 'node:aa11bb22',
    header_state: 'absent',
    properties: null,
    has_issue: false,
    mine: { state: 'present-unverified', capsule_id: 'd'.repeat(64) },
    theirs: { state: 'absent', capsule_id: null },
    unilateral: true,
    timestamp: '2026-09-26T10:00:00Z',
    ...overrides
  }
}

// A split request as its requester holds it: the Rust plugin's own bundle.
const SPLIT_BUNDLE = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../vectors/split-stage/rust-split-bundle.json'), 'utf8')
)

const PANE_C: PaneCListJson = {
  row_count: 13,
  default_sort: 'timestamp',
  filters: ['all', 'served', 'asked', 'issues'],
  next_after_seq: null,
  archived_segments: [],
  rows: [
    row('exch-closed', {
      mine: fixtureMineCell(),
      theirs: fixtureTheirsCell('agrees'),
      unilateral: false,
      settlement: {
        observed_by: 'payer',
        state: 'settled',
        terms_digests: ['f'.repeat(64)],
        entries: [],
        provider_book: 'not_available'
      }
    }),
    row('exch-uncertain', {
      timestamp: '2026-09-26T09:00:00Z',
      settlement: {
        observed_by: 'payer',
        state: 'outcome_not_reported',
        terms_digests: ['f'.repeat(64)],
        entries: [],
        final_accounted_msat: null,
        provider_book: 'not_available'
      }
    }),
    row('exch-served-paid', {
      role_tag: 'SERVED',
      timestamp: '2026-09-26T09:30:00Z',
      provider_settlement: {
        observed_by: 'provider',
        who_paid: 'requester',
        state: 'settled',
        terms_digests: ['f'.repeat(64)],
        entries: [],
        delivered_tokens: 42
      },
      agreement: {
        side: 'provider',
        coverage: 'covered',
        acceptance_digest: 'a'.repeat(64),
        count: { position: 1, max_exchanges: 5 },
        spend: {
          observed_msat: 995,
          lower_bound: false,
          spend_cap_msat: 3000,
          basis: 'agent_origin_assertion',
          observed_by: 'payee_observed'
        },
        finding: 'accepted_before_action'
      }
    }),
    row('exch-contradicted', { mine: fixtureMineCell(), theirs: fixtureTheirsCell('disagrees'), unilateral: false }),
    row('exch-refused', {
      theirs: { state: 'absent', capsule_id: null, evidence_outcome: 'signed_refusal', evidence_outcome_date: '4 Sep' }
    }),
    row('exch-absent', {
      theirs: {
        state: 'absent',
        capsule_id: null,
        evidence_outcome: 'recorded_absence',
        evidence_outcome_date: '4 Sep'
      }
    }),
    row('exch-asked', {
      theirs: { state: 'absent', capsule_id: null, evidence_outcome: 'unanswered', evidence_outcome_date: '3 Sep' }
    }),
    row('exch-not-held', { theirs: { state: 'NOT_CHECKED', capsule_id: 'e'.repeat(64), peer_id: 'peer-1' } }),
    row('exch-not-given', { theirs: { state: 'NOT_CHECKED', capsule_id: 'capsule-chatcmpl-1', peer_id: 'peer-1' } }),
    row('exch-not-asked', {}),
    row('exch-twin-a', { twin_bracket_id: 'twin-census', timestamp: '2026-09-26T11:00:00Z' }),
    row('exch-twin-b', { twin_bracket_id: 'twin-census', timestamp: '2026-09-26T11:00:01Z' }),
    row('exch-split', {
      timestamp: '2026-09-26T12:00:00Z',
      split: { viewer: 'requester', main: SPLIT_BUNDLE.capsule, stage_records: SPLIT_BUNDLE.split_stage_records }
    })
  ]
}

vi.mock('@/features/capsules/api/sidecarClient', () => ({
  fetchPaneA: vi.fn().mockResolvedValue({ rows: [], operator: null, witness_checkpoint_supplied: false, card: null }),
  fetchPaneB: vi.fn(async () => HARNESS_PANE_B_PAYLOAD),
  fetchPaneCList: vi.fn(async () => PANE_C)
}))
vi.mock('@/features/capsules/api/client', () => ({
  fetchCapsuleLedger: vi.fn().mockResolvedValue({ records: [], nodePubKeyPem: null }),
  fetchSignedStatement: vi.fn().mockResolvedValue(null),
  fetchSettlementReportStatus: vi.fn().mockResolvedValue({ kind: 'unknown' })
}))
vi.mock('@/features/network/api/use-status-query', () => ({
  useStatusQuery: vi.fn(() => ({ data: undefined }))
}))

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

// ---------------------------------------------------------------------------
// Reading a rendered chip's tooltip: the sr-only copy its describedby names.
// ---------------------------------------------------------------------------
function tooltipFor(censusElement: Element): string {
  const described = censusElement.querySelector('[aria-describedby]')
  const id = described?.getAttribute('aria-describedby')
  return (id ? document.getElementById(id)?.textContent : null)?.trim() ?? ''
}

function censusOnScreen(): Map<string, string> {
  const found = new Map<string, string>()
  for (const el of document.querySelectorAll('[data-census-chip]')) {
    const key = el.getAttribute('data-census-chip') as string
    if (!found.has(key)) found.set(key, tooltipFor(el))
  }
  return found
}

function expectCovered(required: readonly string[], seen: Map<string, string>, where: 'dig' | 'face') {
  const missing = required.filter((key) => !seen.has(key))
  expect(missing, 'chip types rendered without a tooltip').toEqual([])
  for (const key of required) {
    const tooltip = seen.get(key) ?? ''
    expect(tooltip.length, `${key} has an empty tooltip`).toBeGreaterThan(0)
    expect(checkWords(tooltip, where), key).toEqual([])
  }
}

describe('tooltip census -- every chip type the Evidence tab ships has a plain one-line tooltip', () => {
  it('Peers + hero: every column header, the identity note and each counted badge', async () => {
    render(<LedgerPageContent />, { wrapper })
    await screen.findByText(/on the record\. Names are self-reported/)
    const seen = censusOnScreen()
    expectCovered(REQUIRED.hero, seen, 'face')
    expectCovered(REQUIRED.peers, seen, 'face')
    // The header carries no icons (Steven's word budget), so the live/local chip has no (i) any more.
    expect(seen.has('hero:live') || seen.has('hero:local') || seen.has('hero:sample')).toBe(false)
    // No generic warning glyph anywhere on the Peers face (§8).
    expect(document.body.textContent).not.toContain('⚠')
  })

  it('Exchanges: every row state, the verdict detail and the TWIN badge', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper })
    await user.click(await screen.findByRole('tab', { name: /exchanges/i }))
    await screen.findAllByText('Waiting for theirs')
    expectCovered(REQUIRED.exchanges, censusOnScreen(), 'face')
  })

  it('row expansion (Dig): every chip in the checks panel has a hover, and the click still opens the full explanation', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper })
    await user.click(await screen.findByRole('tab', { name: /exchanges/i }))
    const closedRow = await screen.findByRole('group', { name: 'Exchange exch-closed' })
    await user.click(within(closedRow).getByRole('button', { name: /How we checked/ }))
    const panel = await screen.findByLabelText('Security checks for exch-closed')
    // The checks sit in groups that open on their own.
    for (const question of [
      /Could anyone have rewritten this/,
      /Do both sides tell the same story/,
      /Was it the model they advertised/,
      /Who stands behind it/
    ]) {
      await user.click(within(panel).getByRole('button', { name: question }))
    }

    const seen = censusOnScreen()
    expectCovered(REQUIRED.checks, seen, 'dig')
    // Every chip trigger in the panel is wrapped by a census entry with a hover.
    const triggers = panel.querySelectorAll('button[aria-haspopup="dialog"]')
    expect(triggers.length).toBeGreaterThan(0)
    for (const trigger of triggers) {
      const census = trigger.closest('[data-census-chip]')
      expect(census, `a checks chip ships without a hover: "${trigger.textContent}"`).not.toBeNull()
      expect(checkWords(tooltipFor(census as Element), 'dig')).toEqual([])
    }
    // Click-through still works: the four-part explanation opens.
    await user.click(triggers[0] as HTMLElement)
    expect(await screen.findByText(/What this means:/)).toBeInTheDocument()
  })

  it('Integrity: every tile and the chain strip', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper })
    await user.click(await screen.findByRole('tab', { name: /integrity/i }))
    await screen.findByText(/Have an outside witness hold your checkpoints/)
    expectCovered(REQUIRED.integrity, censusOnScreen(), 'face')
  })
})

describe('tooltip census -- the copy itself', () => {
  it('the hero sentence (page text, not a tooltip, so longer): full sentences, no banned word', () => {
    expect(COPY.HERO_DESCRIPTION.endsWith('.')).toBe(true)
    expect(checkWords(COPY.HERO_DESCRIPTION, 'face')).toEqual([])
  })

  it('every registered tooltip is one or two plain sentences with no banned word; outside Dig, no engineer’s words', () => {
    const face: string[] = [
      ...Object.values(COPY.HERO_TOOLTIPS),
      ...Object.values(COPY.PEER_COLUMN_TOOLTIPS),
      ...Object.values(COPY.PEER_ATTENTION).flatMap((entry) => [entry.tooltip(1), entry.tooltip(2)]),
      ...Object.values(COPY.ROW_STATE_TOOLTIPS),
      ...Object.values(COPY.CLOSED_CELL_TOOLTIPS),
      ...Object.values(COPY.ENTRY_CHIP_RESULT_TOOLTIPS).flatMap((byMark) => Object.values(byMark)),
      COPY.OWN_RECORD_FAILS_WARNING,
      COPY.SAVED_BECAUSE_YOU_ASKED,
      COPY.CONFIRMED_NOT_KEPT,
      ...Object.values(COPY.TWIN_TOOLTIPS),
      ...Object.values(COPY.TWIN_VERDICT_TOOLTIPS),
      COPY.SETUP_STEPS_TOOLTIP,
      COPY.CONTINUITY_TOOLTIP,
      COPY.SAVE_EVIDENCE_FILE_TOOLTIP,
      ...Object.values(COPY.STAGE_CELL_TOOLTIPS),
      ...Object.values(COPY.HANDOFF_TOOLTIPS),
      COPY.TWIN_NO_VERDICT_TOOLTIP,
      ...Object.values(COPY.SPLIT_TOOLTIPS),
      ...Object.values(COPY.INTEGRITY_TILE_TOOLTIPS),
      COPY.CHAIN_STRIP_TOOLTIP,
      COPY.exchangeTextKeptNotice(30),
      COPY.exchangeTextKeptNotice(1),
      COPY.exchangeTextStillHeldNotice(3, 30),
      COPY.exchangeTextStillHeldNotice(1, 1)
    ]
    const dig = Object.values(COPY.CHECK_CHIP_TOOLTIPS)
    for (const text of [...face, ...dig]) {
      expect(text.trim().length).toBeGreaterThan(0)
      expect(text.endsWith('.'), `not a full sentence: "${text}"`).toBe(true)
      expect(text.split(/(?<=[.!?])\s+/).length, `more than two sentences: "${text}"`).toBeLessThanOrEqual(2)
    }
    expect(face.flatMap((text) => checkWords(text, 'face'))).toEqual([])
    expect(dig.flatMap((text) => checkWords(text, 'dig'))).toEqual([])
  })

  it('the Exchanges opening line (page text, ruled verbatim) carries no banned word', () => {
    // "leaves" there is the verb ("each exchange leaves two records"), not
    // the log's leaves, so only the banned-word check applies.
    expect(COPY.EXCHANGES_INTRO.endsWith('.')).toBe(true)
    expect(checkWords(COPY.EXCHANGES_INTRO, 'dig')).toEqual([])
  })

  it('the row faces, actions and badges carry no banned or engineer’s word', () => {
    const texts = ALL_KINDS.flatMap((kind) => {
      const state = { kind, date: '4 Sep' }
      return [rightCellText(state), rightCellStatusLabel(state), rightCellAction(state) ?? '']
    })
    expect(texts.flatMap((text) => checkWords(text, 'face'))).toEqual([])
  })

  it('Integrity faces: setup steps and every chain caption variant', () => {
    const steps = buildSetupSteps({ checkpoint_count: 0 }, null)
    const texts = [
      ...steps.flatMap((step) => [step.title, step.status, step.body ?? '']),
      recordsStripHeading(5, 1),
      recordsStripHeading(2, null),
      coverageBadge(5, 1, 1),
      coverageBadge(5, 2, null),
      coverageBadge(2, null, null),
      coverageBadge(1, 0, null),
      coverageBadge(8, 1, 8),
      recordsStripBreakdown(5, 3, 1, 1, '2026-09-10T16:28:00Z'),
      ...buildSetupSteps({ checkpoint_count: 1, witness_configured: true }, { verified: true }, {
        total: 4,
        received: 3
      }).flatMap((step) => [step.title, step.status, step.body ?? '', step.guards]),
      ...steps.map((step) => step.guards),
      continuityFact(null),
      continuityFact(1),
      continuityFact(3),
      sealedBreakdownText(5, 3)
    ]
    expect(texts.flatMap((text) => checkWords(text, 'face'))).toEqual([])
  })

  it('the counted peer badges name the specific thing and count it; the two uncounted states are named, not numbered', () => {
    const [clean, alarmed] = HARNESS_PANE_B_PAYLOAD.rows
    expect(peerAttention(clean)).toEqual([])
    expect(peerAttention(alarmed).map((item) => item.label)).toEqual([
      '1 disagreement',
      '1 differing answer',
      'log didn’t check out'
    ])
    const failedLog = peerAttention({ ...clean, history: { ...clean.history, state: 'failed' } })
    expect(failedLog.map((item) => item.label)).toEqual(['log didn’t check out'])
    const refused = peerAttention({ ...clean, served: { ...clean.served, state: 'refused' } })
    expect(refused.map((item) => item.label)).toEqual(['refused a request'])
  })
})
