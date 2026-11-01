// Tests for LedgerPageContent — the three-section Ledger tab (the served / asked strip is
// a header strip on Exchanges, not a tab of its own).
//
// Test goals:
//   1. Three section tabs present (Peers/Exchanges/Integrity), Peers is the
//      default, with no configuration step required to see them populate
//   2. The premise line is rendered verbatim
//   3. No leaked internal IDs or tool names in the empty state, and no
//      sidecar URL box anywhere
//   4. Exchanges header shows two counts, never a ratio
//   5. The Exchanges served / asked line counts the rows below by role, and
//      never a number the page doesn't hold
//   6. The exceptions-first line above the table, and the Ledger badge's
//      "This node's copy" rename
import {
  NARRATED_LABEL,
  NARRATION_NEEDS_AGENT,
  SEALED_LABEL,
  STAMPED_LABEL,
  noReportNote,
  sealedNote
} from '@/features/capsules/lib/what-happened'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LedgerPageContent } from '@/features/capsules/pages/LedgerPage'
import { setPluginHost } from '@/plugin-host/host'
import { createStandaloneHost } from '@/plugin-host/standalone-host'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { fixtureMineCell, fixtureTheirsCell } from '@/features/capsules/lib/pushed-half-fixtures'
import { CHAIN_BAR_INFO, INTEGRITY_TILE_INFO } from '@/features/capsules/lib/integrity-view'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import { HERO_DESCRIPTION } from '@/features/capsules/lib/tooltip-copy'
import { HISTORY_MEMORY_KEY } from '@/features/capsules/lib/history-memory'

// ---------------------------------------------------------------------------
// Mock all network fetchers — tests must never hit the real network.
// ---------------------------------------------------------------------------

vi.mock('@/features/capsules/api/sidecarClient', () => ({
  fetchPaneA: vi.fn().mockResolvedValue({
    rows: [],
    operator: null,
    witness_checkpoint_supplied: false,
    card: null
  }),
  fetchPaneB: vi.fn().mockResolvedValue({ rows: [], peer_count: 0 }),
  fetchPaneCList: vi.fn().mockResolvedValue({
    rows: [],
    row_count: 0,
    default_sort: '',
    filters: [],
    next_after_seq: null,
    archived_segments: []
  })
}))

vi.mock('@/features/capsules/api/recordsClient', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/features/capsules/api/recordsClient')>()
  return {
    ...actual,
    fetchRecordsStatus: vi.fn().mockResolvedValue({
      records_path: '/data/capsules/ledger',
      record_count: 5,
      head: null,
      log_id: 'capsules',
      stored_text_count: 0,
      new_history_pending: null,
      sharing: {
        record_at_completion: { value: 'counterparty', source: 'default' },
        history_segments: { value: 'prospective', source: 'default' },
        adjudications: { value: 'deliver_to_subjects', source: 'default' },
        witness: { value: null, source: 'default' }
      }
    })
  }
})

vi.mock('@/features/capsules/api/evidenceRequestClient', () => ({
  announcedKeyFor: vi.fn().mockResolvedValue(null),
  askForRecord: vi.fn().mockResolvedValue({ kind: 'no_answer', message: 'no reply' }),
  askForHistory: vi.fn().mockResolvedValue({
    kind: 'answer',
    answer: {},
    verification: { state: 'artifact', records: [], checkpoints: 2, witnessed: 1 },
    requestDigest: 'f'.repeat(64),
    announcedKeyId: 'e'.repeat(64),
    held: []
  })
}))
// The real judge, spied on so one test can hand the page a verified record.
vi.mock('@/features/capsules/lib/ask-for-record', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/features/capsules/lib/ask-for-record')>()
  return { ...actual, judgeAskReply: vi.fn(actual.judgeAskReply) }
})
vi.mock('@/features/capsules/api/client', () => ({
  fetchCapsuleLedger: vi.fn().mockResolvedValue({ records: [], nodePubKeyPem: null }),
  fetchServedHistory: vi.fn(),
  fetchSettlementReport: vi.fn()
}))

// Owner identity is live `/api/status` data
// -- defaults to no owner (a bare node), overridden per-test
// with `vi.mocked(useStatusQuery).mockReturnValue(...)`.
vi.mock('@/features/network/api/use-status-query', () => ({
  useStatusQuery: vi.fn(() => ({ data: undefined }))
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } }
  })
  function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return Wrapper
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('LedgerPageContent', () => {
  // `mockResolvedValue` (not `...Once`) on one test persists past that
  // test's end -- `clearAllMocks` (below) clears call history, not
  // implementations. Re-establishing the same defaults the top-level
  // `vi.mock` factory set keeps every test's starting state independent of
  // whatever a previous test last configured, without touching the
  // per-test overrides that rely on `mockResolvedValue`'s persistence
  // *within* their own test (see the "Exchanges header shows two counts"
  // test's own comment on that).
  beforeEach(async () => {
    const { fetchPaneA, fetchPaneB, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: null
    })
    vi.mocked(fetchPaneB).mockResolvedValue({ rows: [], peer_count: 0 })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [],
      row_count: 0,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('shows three section tabs, Peers first and default', () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })

    expect(screen.queryByRole('tab', { name: /balance/i })).not.toBeInTheDocument()
    const peersTab = screen.getByRole('tab', { name: /peers/i })
    expect(peersTab).toBeInTheDocument()
    expect(peersTab).toHaveAttribute('data-state', 'active')
    expect(screen.getByRole('tab', { name: /exchanges/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /integrity/i })).toBeInTheDocument()
  })

  it('the hero says in one line how many records, how many the other side confirmed, and disagreements', async () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    // The default pane A mock carries no card: the node did not say whether a
    // witness is set, so the line does not say it is off.
    expect(await screen.findByTestId('hero-status-line')).toHaveTextContent(
      /^0 records · 0 saved as confirmed · 0 disagreements · no outside witness$/
    )
  })

  it('"Clean up records" opens the three-choice dialog, and Close shuts it without acting', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('button', { name: 'Clean up records' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Start a new log')).toBeInTheDocument()
    const closeButtons = within(dialog).getAllByRole('button', { name: /^close$/i })
    await user.click(closeButtons[closeButtons.length - 1])
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('shows the 20-word premise line, with no docs link and no icon', () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    expect(HERO_DESCRIPTION.split(/\s+/)).toHaveLength(20)
    expect(screen.queryByRole('link', { name: 'docs' })).not.toBeInTheDocument()
    expect(screen.queryByText(/Everything here is checked on this machine/)).not.toBeInTheDocument()

    expect(
      screen.getByText((_, element) => element?.textContent === HERO_DESCRIPTION && element.tagName === 'DIV')
    ).toBeInTheDocument()
  })

  it('the premise line stays on the face and the connectivity chip carries no info icon', () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    expect(
      screen.getByText((_, element) => element?.textContent === HERO_DESCRIPTION && element.tagName === 'DIV')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'About the Live chip' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'About the Local chip' })).not.toBeInTheDocument()
  })

  it('shows the attack cards once the panes load, and a card action switches the tab', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    const region = await screen.findByRole('region', { name: 'Three ways a stranger could cheat you' })
    await user.click(within(region).getByRole('button', { name: 'Turn on a witness' }))
    expect(screen.getByRole('tab', { name: /integrity/i })).toHaveAttribute('aria-selected', 'true')
  })

  it('shows no leaked IDs in empty state', () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })

    const bodyText = document.body.textContent ?? ''
    expect(bodyText).not.toMatch(/\[mesh-/)
    expect(bodyText).not.toMatch(/self_accountability\.py/)
    expect(bodyText).not.toMatch(/not built yet/i)
  })

  it('never renders a sidecar URL box — sections are native, no configuration step', () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })

    expect(screen.queryByRole('textbox', { name: /sidecar url/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^save$/i })).not.toBeInTheDocument()
    const bodyText = document.body.textContent ?? ''
    expect(bodyText).not.toMatch(/sidecar url/i)
    expect(bodyText).not.toMatch(/configure a sidecar/i)
    expect(bodyText).not.toMatch(/set the url/i)
    expect(bodyText).not.toMatch(/localhost:8089|127\.0\.0\.1:8089/)
  })

  it('populates a section immediately with no prior configuration', async () => {
    const { fetchPaneB } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneB).mockResolvedValueOnce({
      rows: [
        {
          peer_id: 'peer-1',
          node: { state: 'present', text: 'peer-1', peer_id: 'peer-1', member_kind: 'member', exchange_count: 1 },
          rung: {
            state: 'present',
            text: 'full_bilateral',
            rung: 'full_bilateral',
            distinct_rungs: ['full_bilateral']
          },
          role: {
            state: 'present',
            text: 'you_to_them · 1',
            role: 'you_to_them',
            you_to_them_count: 1,
            them_to_you_count: 0,
            exchange_count: 1
          },
          history: { state: 'NOT_CHECKED', text: null },
          served: { state: 'NOT_CHECKED', text: null },
          pair: { state: 'absent', text: null, verified: 0, failed: 0, missing: 0, details: [] },
          verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } },
          asked: { state: 'absent', text: null, count: 0 },
          exchange_count: 1,
          first_seen: null,
          last_seen: null
        }
      ],
      peer_count: 1
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /peers/i }))

    expect(await screen.findByText('peer-1')).toBeInTheDocument()

    // The header counts the peers on the record; nodes only advertised are Network's.
    expect(screen.getByText(/^1 peer on the record\./)).toBeInTheDocument()
    expect(screen.queryByText(/peers? advertised/)).not.toBeInTheDocument()
  })

  it('Peers empty state is an invitation, never a bare "No peer exchanges recorded yet."', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /peers/i }))

    expect(await screen.findByText('No peers recorded yet')).toBeInTheDocument()
    // Nodes only advertised on the mesh are Network's: the invitation shows with none dealt with.
    expect(screen.getByText('Open Chat to start one')).toBeInTheDocument()
    expect(screen.queryByText(/peers advertised on the mesh/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Open Chat to start one' })).toBeInTheDocument()
    expect(screen.queryByText('No peer exchanges recorded yet.')).not.toBeInTheDocument()
  })

  it('Peers: no card for an unattributed row — its exchanges roll into one headline count, never "unknown peer"', async () => {
    const { fetchPaneB } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneB).mockResolvedValueOnce({
      rows: [
        {
          peer_id: 'peer-1',
          node: { state: 'present', text: 'peer-1', peer_id: 'peer-1', member_kind: 'member', exchange_count: 1 },
          rung: {
            state: 'present',
            text: 'full_bilateral',
            rung: 'full_bilateral',
            distinct_rungs: ['full_bilateral']
          },
          role: {
            state: 'present',
            text: 'you_to_them · 1',
            role: 'you_to_them',
            you_to_them_count: 1,
            them_to_you_count: 0,
            exchange_count: 1
          },
          history: { state: 'NOT_CHECKED', text: null },
          served: { state: 'NOT_CHECKED', text: null },
          pair: { state: 'absent', text: null, verified: 0, failed: 0, missing: 0, details: [] },
          verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } },
          asked: { state: 'absent', text: null, count: 0 },
          exchange_count: 1,
          first_seen: null,
          last_seen: null
        },
        {
          // No `peer_id`, no `node.peer_id` — no counterparty evidence at
          // all for these 3 exchanges (the case that used to render a
          // synthetic "unknown peer" card).
          peer_id: null,
          node: { state: 'present', text: null },
          rung: { state: 'present', text: 'unilateral_fallback', rung: 'unilateral_fallback' },
          role: {
            state: 'present',
            text: 'you_to_them · 3',
            role: 'you_to_them',
            you_to_them_count: 3,
            them_to_you_count: 0,
            exchange_count: 3
          },
          history: { state: 'NOT_CHECKED', text: null },
          served: { state: 'NOT_CHECKED', text: null },
          pair: { state: 'absent', text: null, verified: 0, failed: 0, missing: 0, details: [] },
          verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } },
          asked: { state: 'absent', text: null, count: 0 },
          exchange_count: 3,
          first_seen: null,
          last_seen: null
        }
      ],
      peer_count: 2
    })
    // The count comes from the rows Exchanges lists: three with no
    // counterparty, one naming peer-1. Pane B's residual (3 above) agrees
    // here, but the line never reads it.
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    const exchangeRow = (key: string, counterparty: string | null) => ({
      exchange_key: key,
      role_tag: 'ASKED',
      counterparty,
      header_state: 'ok',
      properties: null,
      has_issue: false,
      mine: { state: 'present', capsule_id: null },
      theirs: { state: 'absent', capsule_id: null },
      unilateral: true,
      timestamp: null
    })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [exchangeRow('e1', null), exchangeRow('e2', null), exchangeRow('e3', null), exchangeRow('e4', 'peer-1')],
      row_count: 4,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /peers/i }))

    expect(await screen.findByText('peer-1')).toBeInTheDocument()
    expect(
      await screen.findByText('3 exchanges have no other side recorded yet. They appear under Exchanges.')
    ).toBeInTheDocument()
    expect(screen.queryByText(/unknown peer/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/peer identity not resolved yet/i)).not.toBeInTheDocument()
  })

  it('Exchanges header shows two counts not a ratio', async () => {
    // Set up mock with 3 rows, 1 of which is bilateral (not unilateral).
    // `mockResolvedValue` (persistent, not `...Once`): Peers is now the
    // default/first-mounted tab and ALSO queries pane-c (for its own
    // exchange-timeline join, sharing this cache key by design) -- an
    // initial Peers mount consumes a one-time override before this test
    // ever switches to the Exchanges tab, and switching tabs mounts a new
    // pane-c observer that refetches (staleTime 0). A persistent value
    // matches real usage too: hitting the endpoint twice returns the same
    // data both times.
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exc-1',
          role_tag: 'initiator',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: null },
          theirs: { state: 'present', capsule_id: null },
          unilateral: false,
          timestamp: null
        },
        {
          exchange_key: 'exc-2',
          role_tag: 'responder',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: null },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: null
        },
        {
          exchange_key: 'exc-3',
          role_tag: 'responder',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: null },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: null
        }
      ],
      row_count: 3,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })

    // Navigate to Exchanges tab
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    // Wait for data. Matched on "saved as confirmed" (unique to
    // this line) rather than "3 exchange" -- the exceptions-first line
    // below it also states the same total, so a bare "3 exchange" query is
    // ambiguous between the two.
    //
    // finding 1: `theirs.state
    // !== 'absent'` is a peer-asserted id, not a held/confirmed artifact --
    // none of these three rows carry a real fetch, so `confirmed` is
    // honestly 0, not 1 (the old count treated exc-1's bare `theirs.state:
    // 'present'` as a confirmation).
    // The Exchanges headline (the hero line above says the same counts).
    const headerEl = await screen.findByTestId('exchanges-headline')
    expect(headerEl.textContent).toMatch(/3 exchange/)
    expect(headerEl.textContent).toMatch(/0 saved as confirmed/)

    // Ratios and percentages must NOT appear
    const bodyText = document.body.textContent ?? ''
    expect(bodyText).not.toMatch(/1\/3/)
    expect(bodyText).not.toMatch(/33%/)
  })

  it('UX §3: ONE Exchanges headline -- count, confirmed, disagreements; registration stays on Integrity', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exc-1',
          role_tag: 'initiator',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: null },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: null
        }
      ],
      row_count: 1,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    const headerEl = await screen.findByTestId('exchanges-headline')
    expect(headerEl.textContent).toBe('1 exchange · 0 saved as confirmed · 0 disagreements')
    expect(headerEl.textContent).not.toMatch(/registered/)
    // Nothing needs attention, so no second line repeats the count.
    expect(screen.queryByText(/sealed by you/)).not.toBeInTheDocument()
  })

  it('"See the setup steps" beside the Exchanges headline opens Integrity, and its hover says that is all it does', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exc-1',
          role_tag: 'initiator',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: null },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: null
        }
      ],
      row_count: 1,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByTestId('exchanges-headline')

    expect(screen.queryByRole('button', { name: 'Register a checkpoint' })).not.toBeInTheDocument()
    const setup = screen.getByRole('button', { name: 'See the setup steps' })
    const wrapper = setup.closest('[aria-describedby]') as HTMLElement
    expect(document.getElementById(wrapper.getAttribute('aria-describedby') as string)).toHaveTextContent(
      'Opens Integrity, which lists how to get the other side’s record'
    )
    await user.click(setup)
    expect(await screen.findByText('Will your records hold up later, to someone else?')).toBeInTheDocument()
  })

  it('Exchanges empty state is an invitation, never a bare table header over nothing', async () => {
    // `mockResolvedValue` (not `...Once`) on a prior test in this describe
    // block persists across tests -- `clearAllMocks` in `afterEach` clears
    // call history, not implementations -- so this test restores the
    // empty-pane-c default explicitly rather than depending on ordering.
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [],
      row_count: 0,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    expect(await screen.findByText('No exchanges yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Open Chat to start one' })).toBeInTheDocument()
    expect(screen.queryByText('No exchanges recorded yet.')).not.toBeInTheDocument()
  })

  // Both tests below need at least one exchange row -- at true zero rows
  // now renders the L3.7
  // invitation card instead of the headline/exceptions-first line, so a
  // populated fixture is what actually exercises the code these tests
  // describe (previously this relied on an EARLIER test's persistent
  // `mockResolvedValue` leaking a 3-row payload forward -- an
  // order-dependent coincidence the `beforeEach` default-reset above no
  // longer allows).
  function oneCleanExchangeRow() {
    return {
      rows: [
        {
          exchange_key: 'exc-only',
          role_tag: 'initiator',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: null },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: null
        }
      ],
      row_count: 1,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    }
  }

  it('Exchanges counts the rows it lists by role: "You served n · you asked m", never a fold it doesn’t have', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(oneCleanExchangeRow())

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    await screen.findByTestId('exchanges-headline')
    const role = oneCleanExchangeRow().rows[0].role_tag
    expect(screen.getByTestId('served-asked-line')).toHaveTextContent(
      role === 'SERVED' ? 'You served 1 · you asked 0' : 'You served 0 · you asked 1'
    )
    expect(screen.queryByText('No served-summary data available yet.')).not.toBeInTheDocument()
  })

  it('never renders the retired "No served-summary data available yet." string, even off the empty-state path', async () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    const bodyText = document.body.textContent ?? ''
    expect(bodyText).not.toMatch(/No served-summary data available yet\./)
  })

  it('the retired "This node\'s copy" label is gone; "Your records" opens the node\'s real facts', async () => {
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [{}, {}, {}, {}, {}] as never,
      operator: null,
      witness_checkpoint_supplied: false,
      card: { covered_record_count: 3, registered_no_later_than: '2026-09-28T16:16:00.000Z' }
    })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    expect(screen.queryByText("This node's copy")).not.toBeInTheDocument()

    await user.click(await screen.findByTestId('hero-your-records'))
    const facts = await screen.findByTestId('your-records-facts')
    expect(await within(facts).findByText('/data/capsules/ledger')).toBeInTheDocument()
    expect(facts).toHaveTextContent('5 records')
    expect(facts).toHaveTextContent(
      `Covers 3 records, made no later than ${formatExchangeTimestamp('2026-09-28T16:16:00.000Z')}.`
    )
    expect(facts.textContent).not.toMatch(/\d{4}-\d\d-\d\dT/)
    expect(screen.getByTestId('what-you-share')).toBeInTheDocument()
  })

  it('p2 item 5: on sample data the two setup jumps are disabled, with the reason on hover', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(oneCleanExchangeRow())
    vi.stubEnv('VITE_EVIDENCE_FIXTURES', 'freeze-candidate')
    try {
      const user = userEvent.setup()
      render(<LedgerPageContent />, { wrapper: makeWrapper() })
      await user.click(screen.getByRole('tab', { name: /exchanges/i }))
      for (const name of ['See the setup steps']) {
        const button = await screen.findByRole('button', { name })
        expect(button).toBeDisabled()
        const wrapper = button.closest('[aria-describedby]') as HTMLElement
        expect(document.getElementById(wrapper.getAttribute('aria-describedby') as string)).toHaveTextContent(
          'Not available on sample data.'
        )
      }
      // The downloads work on the sample, so they stay enabled.
      expect(screen.getByRole('button', { name: /export view/i })).toBeEnabled()
      expect(screen.getByRole('button', { name: STAMPED_LABEL })).toBeEnabled()
      expect(screen.getByRole('button', { name: SEALED_LABEL })).toBeEnabled()
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('Next contradiction is not shown at all when there is nothing to jump to, never greyed', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(oneCleanExchangeRow())
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByTestId('exchanges-headline')
    expect(screen.queryByRole('button', { name: /next contradiction/i })).not.toBeInTheDocument()
  })

  it('look finding 6: in fixture replay the hero chip reads "Sample data", never "Live"', async () => {
    vi.stubEnv('VITE_EVIDENCE_FIXTURES', 'freeze-candidate')
    try {
      render(<LedgerPageContent />, { wrapper: makeWrapper() })
      expect(await screen.findByText('Sample data')).toBeInTheDocument()
      expect(screen.queryByText('Live')).not.toBeInTheDocument()
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('UX §2: the Peers intro is plain grey text that links to the Network tab', async () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    const link = await screen.findByRole('link', { name: 'Network tab' })
    expect(link).toHaveAttribute('href', '/')
    expect(link.closest('p')?.className).not.toMatch(/emerald/)
  })

  it('a plain click on "Network tab" navigates through the console host, never a full reload', async () => {
    const navigate = vi.fn()
    setPluginHost(createStandaloneHost({ navigate }))
    try {
      render(<LedgerPageContent />, { wrapper: makeWrapper() })
      const link = await screen.findByRole('link', { name: 'Network tab' })
      const click = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 })
      link.dispatchEvent(click)
      expect(click.defaultPrevented).toBe(true)
      expect(navigate).toHaveBeenCalledWith('/')
    } finally {
      setPluginHost(createStandaloneHost())
    }
  })

  it('UX §3: no range banner when every exchange is already on screen', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(oneCleanExchangeRow())
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByTestId('exchanges-headline')
    expect(screen.queryByText(/^Showing /)).not.toBeInTheDocument()
    expect(screen.queryByText(/Not shown here/)).not.toBeInTheDocument()
  })

  it('shows one headline, and no all-clear second line repeating its count', async () => {
    // finding 7: the calm-state
    // line no longer claims "Nothing needs your attention... all recomputed
    // clean" -- it states the role-aware truth (sealed / confirmed by
    // anyone else / registered).
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(oneCleanExchangeRow())

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    expect(await screen.findByTestId('exchanges-headline')).toHaveTextContent(/^1 exchange/)
    expect(screen.queryByText(/sealed by you/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Nothing needs your attention/)).not.toBeInTheDocument()
  })

  it('says plainly, under the hero, when this node keeps exchange text; says nothing when it does not', async () => {
    const { fetchRecordsStatus } = await import('@/features/capsules/api/recordsClient')
    const status = await vi.mocked(fetchRecordsStatus)()
    vi.mocked(fetchRecordsStatus).mockResolvedValue({ ...status, exchange_text: { kept: true, retention_days: 30 } })
    try {
      render(<LedgerPageContent />, { wrapper: makeWrapper() })
      expect(await screen.findByTestId('hero-exchange-text-notice')).toHaveTextContent(
        'This node keeps the text of exchanges on its own disk (deleted after 30 days). Nothing is shared.'
      )
    } finally {
      vi.mocked(fetchRecordsStatus).mockResolvedValue(status)
    }
    cleanup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await screen.findByTestId('hero-your-records')
    expect(screen.queryByTestId('hero-exchange-text-notice')).not.toBeInTheDocument()
  })

  it('after keeping is turned off, says how much kept text is still held, and Delete now opens Clean up records', async () => {
    const { fetchRecordsStatus } = await import('@/features/capsules/api/recordsClient')
    const status = await vi.mocked(fetchRecordsStatus)()
    vi.mocked(fetchRecordsStatus).mockResolvedValue({
      ...status,
      stored_text_count: 4,
      exchange_text: { kept: false, retention_days: 30 }
    })
    try {
      const user = userEvent.setup()
      render(<LedgerPageContent />, { wrapper: makeWrapper() })
      expect(await screen.findByTestId('hero-exchange-text-notice')).toHaveTextContent(
        'This node still holds 4 kept texts on its own disk (deleted after 30 days, or delete them now). Nothing is shared.'
      )
      await user.click(screen.getByTestId('hero-exchange-text-delete'))
      expect(await screen.findByRole('dialog')).toBeInTheDocument()
    } finally {
      vi.mocked(fetchRecordsStatus).mockResolvedValue(status)
    }
  })

  it('the hero never shows the retired "This node\'s copy" or "Local only" labels', () => {
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    expect(screen.queryByText("This node's copy")).not.toBeInTheDocument()
    expect(screen.queryByText('Local only')).not.toBeInTheDocument()
  })
})

describe('LedgerPageContent — Part 3: Exchanges two-sided stream + row inspector', () => {
  afterEach(() => {
    vi.clearAllMocks()
    // The toolbar test stubs URL and spies on anchor clicks to see saves.
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })


  it('renders a two-sided row per exchange (OPEN · not held for a peer-asserted id with no bytes held, OPEN for a unilateral one), the `▸ checks` toggle expands full detail inline', async () => {
    // Finding 1: a peer-
    // asserted id with no held bytes is OPEN · not held, never CLOSED
    // -- this fixture used to read `theirs: { state: 'present', ... }` and
    // assert CLOSED off nothing but that presence, exactly the bug the
    // 2026-09-23 assessment found live on 110 of 135 rows.
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exch-clean-00',
          role_tag: 'ASKED',
          header_state: 'ok',
          properties: {
            content_binding: { state: 'PASS' },
            checkpoint_signature: { state: 'PASS' },
            outcome_corroboration: { state: 'PASS' }
          },
          has_issue: false,
          mine: { state: 'present', capsule_id: 'mine-clean' },
          theirs: { state: 'NOT_CHECKED', capsule_id: 'a'.repeat(64), peer_id: 'peer-1' },
          unilateral: false,
          timestamp: '2026-09-08T16:58:05Z'
        },
        {
          exchange_key: 'exch-alarm-07',
          role_tag: 'ASKED',
          header_state: 'issue',
          properties: { checkpoint_signature: { state: 'FAIL', text: 'could not verify against the pinned key' } },
          has_issue: true,
          mine: { state: 'present', capsule_id: 'mine-alarm' },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: '2026-09-08T08:03:00Z'
        }
      ],
      row_count: 2,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    // Both rows load — one OPEN · not held (a peer-asserted id, no
    // bytes held or fetched), one OPEN (never asked, per L-C -- an absent
    // theirs record with no evidence_outcome carried can only honestly
    // resolve to "not asked").
    expect(await screen.findByRole('group', { name: 'Exchange exch-clean-00' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Exchange exch-alarm-07' })).toBeInTheDocument()
    expect(screen.getAllByText('Waiting for theirs').length).toBeGreaterThan(0)
    expect(screen.queryByText('Confirmed')).not.toBeInTheDocument()
    // Neither row carries a counterparty (the
    // default fetchPaneB mock returns no rows), so the OPEN row's ask
    // action is gated -- a fact, never a fabricated "not yet asked" ask
    // button pointed at nobody. Both fixture rows are ASKED (a remote
    // exchange whose peer is unrecorded), so the gated text names that truth.
    expect(screen.getByText('Other side: not known')).toBeInTheDocument()
    expect(screen.queryByText('nothing to ask yet')).not.toBeInTheDocument()
    // The asks stay on the row, disabled with the reason: never a button
    // pointed at nobody, never one that clicks into nothing.
    for (const button of screen.getAllByRole('button', { name: 'Ask for their record' })) {
      expect(button).toBeDisabled()
    }

    // `▸ checks` expands the full nine-property detail inline, under the
    // row -- never a dialog.
    const alarmRow = screen.getByLabelText('Exchange exch-alarm-07')
    await user.click(within(alarmRow).getByRole('button', { name: 'How we checked ▸' }))
    const checksRegion = await screen.findByRole('region', { name: /Security checks for exch-alarm-07/ })
    expect(checksRegion).toHaveTextContent('Contents match the record’s id')
    expect(checksRegion).toHaveTextContent('Signed with the node’s key')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('a row with a recorded counterparty shows the ask action; clicking it never opens a dialog', async () => {
    const { fetchPaneB, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exch-known-peer',
          role_tag: 'ASKED',
          header_state: 'issue',
          properties: null,
          has_issue: true,
          mine: { state: 'present', capsule_id: 'mine-known' },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: '2026-09-08T08:03:00Z'
        }
      ],
      row_count: 1,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })
    vi.mocked(fetchPaneB).mockResolvedValue({
      rows: [
        {
          peer_id: 'peer-known',
          node: {
            state: 'present',
            text: 'peer-known',
            peer_id: 'peer-known',
            member_kind: 'member',
            exchange_count: 1
          },
          rung: {
            state: 'present',
            text: 'full_bilateral',
            rung: 'full_bilateral',
            distinct_rungs: ['full_bilateral']
          },
          role: {
            state: 'present',
            text: 'you_to_them · 1',
            role: 'you_to_them',
            you_to_them_count: 1,
            them_to_you_count: 0,
            exchange_count: 1
          },
          history: { state: 'NOT_CHECKED', text: null },
          served: { state: 'NOT_CHECKED', text: null },
          pair: {
            state: 'present',
            text: null,
            verified: 0,
            failed: 0,
            missing: 1,
            details: [{ exchange_id: 'exch-known-peer', state: 'missing' }]
          },
          verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } },
          asked: { state: 'absent', text: null, count: 0 },
          exchange_count: 1,
          first_seen: null,
          last_seen: null
        }
      ],
      peer_count: 1
    })

    // Our own record names whom to ask (the node that served us) and the
    // client nonce both records carry.
    const { fetchCapsuleLedger } = await import('@/features/capsules/api/client')
    vi.mocked(fetchCapsuleLedger).mockResolvedValue({
      records: [
        {
          capsule_id: 'mine-known',
          effect: { request_digest: 'a'.repeat(64) },
          model_attestation: {
            compute_attestation: {
              'x-mesh-poc-v1': {
                role: 'requested',
                client_nonce: 'nonce-known',
                serving_provenance: { served_by_node_id: 'c'.repeat(64) }
              }
            }
          }
        }
      ],
      nodePubKeyPem: null
    } as never)
    const { askForRecord } = await import('@/features/capsules/api/evidenceRequestClient')

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    expect(await screen.findByText('Waiting for their record')).toBeInTheDocument()
    const askButton = await screen.findByRole('button', { name: 'Ask for their record' })

    await user.click(askButton)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    // The ask went to the node that served us, naming the exchange by nonce,
    // and with no answer the row says so.
    expect(askForRecord).toHaveBeenCalledWith(
      'c'.repeat(64),
      expect.objectContaining({ nonce: 'nonce-known', digests: null })
    )
    // The verdict waits; its (i) says when it asked and, in plain words, that
    // the ask didn't go through -- never the tool's own message.
    expect(await screen.findByText(/^Asked .*No verified reply yet\. The ask didn’t go through, so there is no reply to check yet\.$/)).toBeInTheDocument()
    expect(screen.queryByText(/no reply\)/)).not.toBeInTheDocument()

    // Their history: asked of the same node, its verified outcome on the row.
    const { askForHistory } = await import('@/features/capsules/api/evidenceRequestClient')
    await user.click(screen.getByRole('button', { name: 'Ask for their history' }))
    expect(askForHistory).toHaveBeenCalledWith('c'.repeat(64))
    expect(await screen.findByText(/^✓ Their history checks out · 2 checkpoints/)).toBeInTheDocument()

    // Nothing on this row ever opens a dialog -- not the ask action, not
    // the `▸ checks` toggle either.
    const knownRow = screen.getByLabelText('Exchange exch-known-peer')
    await user.click(within(knownRow).getByRole('button', { name: 'How we checked ▸' }))
    expect(await screen.findByRole('region', { name: /Security checks for exch-known-peer/ })).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('Export view (CSV) and the three What happened buttons are distinct, present toolbar actions', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exch-1',
          role_tag: 'SERVED',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: 'mine-1' },
          theirs: { state: 'present', capsule_id: 'theirs-1' },
          unilateral: false,
          timestamp: '2026-09-08T00:00:00Z'
        }
      ],
      row_count: 1,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-1' })

    const exportButton = screen.getByRole('button', { name: /export view \(csv\)/i })
    const narratedButton = screen.getByRole('button', { name: NARRATED_LABEL })
    const historyButton = screen.getByRole('button', { name: STAMPED_LABEL })
    const settlementButton = screen.getByRole('button', { name: SEALED_LABEL })
    expect(exportButton).toBeInTheDocument()
    expect(new Set([exportButton, narratedButton, historyButton, settlementButton]).size).toBe(4)
    // The old JSON download of every exchange is gone from this row.
    expect(screen.queryByRole('button', { name: /save evidence file/i })).not.toBeInTheDocument()

    // Narrated: the dashboard has no agent, so it says so and narrates nothing.
    await user.click(narratedButton)
    expect(screen.getByRole('status')).toHaveTextContent(NARRATION_NEEDS_AGENT)

    // Sealed and checked: the node's page, saved unchanged, with its seal time.
    const { fetchSettlementReport } = await import('@/features/capsules/api/client')
    const saved: Blob[] = []
    const createObjectURL = vi.fn((blob: Blob) => (saved.push(blob), 'blob:x'))
    vi.stubGlobal('URL', Object.assign(function () {}, { createObjectURL, revokeObjectURL: () => {} }))
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    vi.mocked(fetchSettlementReport).mockResolvedValueOnce({
      kind: 'report',
      page: '<!doctype html><p>sealed</p>',
      sealedAt: '2026-11-01T19:45:33Z',
      date: '2026-11-01'
    })
    await user.click(settlementButton)
    expect(await screen.findByRole('status')).toHaveTextContent(sealedNote('2026-11-01T19:45:33Z', '2026-11-01'))
    expect(await saved[0].text()).toBe('<!doctype html><p>sealed</p>')

    // No sealed report: the refusal page, with the node's reason.
    vi.mocked(fetchSettlementReport).mockResolvedValueOnce({ kind: 'refused', why: 'no settlement report has been sealed yet' })
    await user.click(settlementButton)
    expect(await screen.findByRole('status')).toHaveTextContent(noReportNote('no settlement report has been sealed yet'))
    expect(await saved[1].text()).toContain('This node’s settlement report')
  })

  it('§3A sticky day headers: one per calendar day, tallying the whole day', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exch-day2-a',
          role_tag: 'ASKED',
          header_state: 'ok',
          properties: { outcome_corroboration: { state: 'PASS' } },
          has_issue: false,
          mine: { state: 'present', capsule_id: 'mine-day2-a' },
          theirs: { state: 'NOT_CHECKED', capsule_id: 'a'.repeat(64), peer_id: 'peer-1' },
          unilateral: false,
          timestamp: '2026-09-23T09:00:00Z'
        },
        {
          exchange_key: 'exch-day1-a',
          role_tag: 'ASKED',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: 'mine-day1-a' },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: '2026-09-22T09:00:00Z'
        },
        {
          exchange_key: 'exch-day1-b',
          role_tag: 'ASKED',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: 'mine-day1-b' },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: '2026-09-22T08:00:00Z'
        }
      ],
      row_count: 3,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-day2-a' })

    // One header for the newer day (1 exchange, unconfirmed) and one for
    // the older day (2 exchanges, unconfirmed) -- never a header per row.
    expect(screen.getByText('Wednesday 23 Sep · 1 exchange · 0 saved as confirmed')).toBeInTheDocument()
    expect(screen.getByText('Tuesday 22 Sep · 2 exchanges · 0 saved as confirmed')).toBeInTheDocument()
  })
})

describe('LedgerPageContent — Part B1: Integrity chain strip', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('replaces both contradictory sentences with the chain strip + four first-person stat cards, a zero rendered prominently', async () => {
    const { fetchPaneA, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      operator: null,
      witness_checkpoint_supplied: false,
      rows: [
        {
          capsule_id: 'c-1',
          timestamp: null,
          model_claimed: null,
          hardware_claimed: null,
          verify_ok: true,
          rungs: {},
          record: {}
        },
        {
          capsule_id: 'c-2',
          timestamp: null,
          model_claimed: null,
          hardware_claimed: null,
          verify_ok: true,
          rungs: {},
          record: {}
        }
      ],
      card: { checkpoint_count: null, continuity: 'unbroken', witnesses: [] }
    })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exch-closed-1',
          role_tag: 'ASKED',
          header_state: 'ok',
          properties: { outcome_corroboration: { state: 'PASS' } },
          has_issue: false,
          mine: { state: 'present', capsule_id: 'mine-1' },
          theirs: { state: 'present', capsule_id: 'theirs-1' },
          unilateral: false,
          timestamp: null
        },
        {
          exchange_key: 'exch-contradicted-1',
          role_tag: 'ASKED',
          header_state: 'issue',
          properties: { outcome_corroboration: { state: 'FAIL', text: 'reported outcomes disagree' } },
          has_issue: true,
          mine: { state: 'present', capsule_id: 'mine-2' },
          theirs: { state: 'present', capsule_id: 'theirs-2' },
          unilateral: false,
          timestamp: null
        }
      ],
      row_count: 2,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    // The four first-person stat cards, with real (non-literal) counts.
    expect(await screen.findByText('Sealed')).toBeInTheDocument()
    expect(screen.getByText('Confirmed by the other side')).toBeInTheDocument()
    expect(screen.getByText('Disagreements')).toBeInTheDocument()
    expect(screen.getByText('Sealed').closest('.panel-shell')).toHaveTextContent('2')
    // Every count carries its denominator: both exchange rows are the total.
    // (These fixture rows carry no signed record from the other side, so
    // neither the confirmed nor the disagreement gate counts them.)
    expect(await screen.findAllByText('0 of 2')).toHaveLength(2)

    // Both old contradictory sentences are gone.
    const bodyText = document.body.textContent ?? ''
    expect(bodyText).not.toMatch(/history is intact and registered with/i)
    expect(bodyText).not.toMatch(/no integrity fields available/i)

    // Item 4: each Integrity tile + the chain bar carries an (i) whose
    // aria-describedby holds the moved explanation.
    const sealedGlyph = screen.getByRole('button', { name: 'About Sealed' })
    expect(document.getElementById(sealedGlyph.getAttribute('aria-describedby') as string)).toHaveTextContent(
      INTEGRITY_TILE_INFO.sealed
    )
    const closedGlyph = screen.getByRole('button', { name: 'About Confirmed by the other side' })
    expect(document.getElementById(closedGlyph.getAttribute('aria-describedby') as string)).toHaveTextContent(
      INTEGRITY_TILE_INFO.confirmedByOtherSide
    )
    for (const label of ['Sealed', 'Confirmed by the other side', 'Disagreements']) {
      expect(screen.getByRole('button', { name: `About ${label}` })).toBeInTheDocument()
    }
    const chainGlyph = screen.getByRole('button', { name: 'About the coverage bar' })
    expect(document.getElementById(chainGlyph.getAttribute('aria-describedby') as string)).toHaveTextContent(
      CHAIN_BAR_INFO
    )
    // The heading stays on the face -- the (i) explains, never replaces. This
    // card reports no checkpoint count, so the strip says "not checked".
    expect(screen.getByText(/Your records · 2 sealed · checkpoints not checked/)).toBeInTheDocument()
    expect(screen.getByText('checkpoints not checked')).toBeInTheDocument()
  })

  it('renders the chain strip + stat cards even with no data, never the old "no integrity fields" fallback', async () => {
    // Empty payloads (set explicitly: mocks survive across tests): fetchPaneA
    // returns rows:[], card:null and fetchPaneCList returns rows:[] -- an
    // honest empty render, not a muted absence message.
    const { fetchPaneA, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({ rows: [], operator: null, witness_checkpoint_supplied: false, card: null })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [],
      row_count: 0,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(await screen.findByText('Sealed')).toBeInTheDocument()
    expect(screen.getByText('Confirmed by the other side')).toBeInTheDocument()
    expect(screen.getByText('Disagreements')).toBeInTheDocument()
    // No exchanges: "none yet", never a bare 0 with no denominator.
    expect(screen.getAllByText('none yet').length).toBeGreaterThanOrEqual(3)

    const bodyText = document.body.textContent ?? ''
    expect(bodyText).not.toMatch(/history is intact and registered with/i)
    expect(bodyText).not.toMatch(/no integrity fields available/i)
    expect(bodyText).not.toMatch(/no integrity data available/i)
  })
})

// A minimally-valid `StatusPayload` ([status-adapter.test.ts]'s own
// `PUBLIC_STATUS_PAYLOAD` shape) -- `useStatusQuery` is one shared mock for
// the whole render tree (Peers' `usePeerMeshStatusIndex` calls it too), so
// overriding its return value needs enough fields that `adaptStatusToDashboard`
// doesn't crash on an absent `serving_models`, not just the `owner` field
// this test cares about.
const BOUND_OWNER_STATUS_PAYLOAD = {
  node_id: 'node-t6-test',
  node_state: 'standby',
  model_name: 'test-model',
  serving_models: [],
  peers: [],
  models: [],
  gpus: [],
  my_vram_gb: 0,
  version: '0',
  owner: { status: 'verified', verified: true }
}

describe('LedgerPageContent — Integrity Close card', () => {
  it('says no agreed period yet, then counts inference and payment apart -- counts only, never an amount', async () => {
    const { fetchPaneA, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [
        { capsule_id: 'r1', kind: 'exchange' },
        { capsule_id: 'r2', kind: 'settlement_observation' },
        { capsule_id: 'r3', kind: 'settlement_observation' }
      ],
      operator: null,
      witness_checkpoint_supplied: false,
      card: { checkpoint_count: 0 }
    } as never)
    const paid = (key: string, state: string) => ({
      exchange_key: key,
      role_tag: 'ASKED',
      header_state: 'ok',
      properties: null,
      has_issue: false,
      mine: { state: 'present', capsule_id: null },
      theirs: { state: 'absent', capsule_id: null },
      unilateral: true,
      timestamp: null,
      settlement: {
        observed_by: 'payer',
        state,
        terms_digests: ['f'.repeat(64)],
        entries: [{ capsule_id: `${key}-s`, timestamp: null, phase: 'final_accounted', source: 'payer_asserted', segment: null, payment_hash: null, amount_msat: 21000 }],
        provider_book: 'not_available'
      }
    })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [paid('e1', 'settled'), paid('e2', 'no_settlement_seen')],
      row_count: 2,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: [],
      payments: 'on',
      settlement_unjoined: ['x'],
      settlement_missing_exchange_id: 1
    } as never)
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    const card = await screen.findByTestId('close-card')
    expect(within(card).getByText('none yet')).toBeInTheDocument()
    expect(within(card).getByText(/So far: 2 exchanges · 0 saved as confirmed/)).toBeInTheDocument()
    expect(within(card).getByText('2 paid · 1 settled by your wallet · provider’s book: not available')).toBeInTheDocument()
    expect(within(card).getByText('2 payment records not matched to an exchange here.')).toBeInTheDocument()
    // The recorded amount stays in the row's own entries: the card never
    // shows or adds one up.
    expect(card.textContent).not.toMatch(/msat|21000|total|balance/i)
    // Payment records are sealed like the rest, but are not exchanges.
    expect(await screen.findByText(/1 yours · 0 received · 2 payment records/)).toBeInTheDocument()
  })
})

describe('LedgerPageContent — Part T6: Integrity section completion', () => {
  afterEach(async () => {
    vi.clearAllMocks()
    // `mockReturnValue` survives `clearAllMocks` -- restore the shared
    // `useStatusQuery` mock explicitly so a later test/describe block never
    // inherits this block's override.
    const { useStatusQuery } = await import('@/features/network/api/use-status-query')
    vi.mocked(useStatusQuery).mockReturnValue({ data: undefined } as never)
  })

  it('step 1 reads "Off · your choice" and the attack it guards against when the node says no witness is set', async () => {
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: { checkpoint_count: 0, witness_configured: false }
    })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    const step = (await screen.findByTestId('setup-steps')).querySelector('[data-step="checkpoints"]') as HTMLElement
    expect(within(step).getByText('off · your choice')).toBeInTheDocument()
    expect(within(step).getByText('Guards against: rewrote the record')).toBeInTheDocument()
    expect(within(step).getByRole('link', { name: 'Turn on' })).toHaveAttribute('href', '/configuration/plugins')
  })

  it('shows the three-step setup checklist, in value order, on a bare node (host reports checkpoint_count 0)', async () => {
    // A real bare node's host reports `card: { checkpoint_count: 0 }` (build_pane_a
    // always supplies the card) -- genuinely none yet, so "not set up" copy.
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: { checkpoint_count: 0 }
    })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    await screen.findByText(/Have an outside witness hold your checkpoints/)
    expect(screen.getByText(/Bind your records to a key you own/)).toBeInTheDocument()
    expect(screen.getByText(/Get the other side’s record/)).toBeInTheDocument()
    expect(screen.getByText(/can only be checked against themselves/)).toBeInTheDocument()
    expect(screen.getByText(/your own claim about who you are, nothing more/)).toBeInTheDocument()
    expect(screen.getByText('Guards against: denying your own records')).toBeInTheDocument()
    expect(screen.getByText('Guards against: left something out')).toBeInTheDocument()
    expect(screen.getByText('mesh-llm auth init')).toBeInTheDocument()
  })

  it('Integrity reads a NULL card as "checkpoint status not reported", never a false "no checkpoint yet"', async () => {
    // `card: null` = the host did not report a count. Integrity must say so --
    // NOT "no checkpoint yet" (a false absence) and NOT the "not set up" body
    // that asserts none exists. Highest-cost tab for this bug. Set the mock
    // explicitly (a prior test overrides fetchPaneA; mocks don't auto-reset).
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: null
    })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    await screen.findByText(/Have an outside witness hold your checkpoints/)
    // The setup-step body is unique; the two negatives are the false-absence
    // strings that must NOT appear for a not-reported (null) card.
    expect(screen.getByText(/did not report its checkpoint status/)).toBeInTheDocument()
    expect(screen.queryByText(/can only be checked against themselves/)).not.toBeInTheDocument()
    expect(screen.queryByText(/no checkpoint yet/)).not.toBeInTheDocument()
    expect(screen.getAllByText('not checked').length).toBeGreaterThan(0)
  })

  it('flips step 1 to "witnessed" and shows the witness copy once a checkpoint exists', async () => {
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      operator: null,
      witness_checkpoint_supplied: true,
      rows: [],
      card: {
        checkpoint_count: 4,
        witnesses: [
          { ts_url: 'https://a.example', operated_by_producer: true, checked: true },
          { ts_url: 'https://b.example', operated_by_producer: false, checked: true }
        ],
        witness_status: [
          { name: 'a.example', url: 'https://a.example', state: 'latest', held_count: 4, checked_count: 4 },
          { name: 'c.example', url: 'https://c.example', state: 'pending', held_count: 0, checked_count: 0 }
        ],
        registered_no_later_than: '2026-09-10'
      }
    })

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(
      await screen.findByText('Held by 2 witnesses: a.example, b.example (1 not operated by this node)')
    ).toBeInTheDocument()
    const witnessList = screen.getByTestId('witness-list')
    expect(within(witnessList).getByText('holds the latest checkpoint')).toBeInTheDocument()
    expect(within(witnessList).getByText('c.example')).toBeInTheDocument()
    expect(within(witnessList).getByText('none held yet')).toBeInTheDocument()
    expect(screen.getByText(`witnessed no later than ${formatExchangeTimestamp('2026-09-10')}`)).toBeInTheDocument()
    // Step 1 no longer shows the "can only be checked against themselves" sentence once done.
    expect(screen.queryByText(/can only be checked against themselves/)).not.toBeInTheDocument()
    expect(screen.getByText('held by a witness')).toBeInTheDocument()
  })

  it('shows the once-per-node facts (retention, capture boundary, identity) exactly once, never per row', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(await screen.findByText(/^Retention:/)).toBeInTheDocument()
    expect(screen.getByText(/^Capture boundary:/)).toBeInTheDocument()
    expect(screen.getByText('Owner: not bound — not bound to a person.')).toBeInTheDocument()
  })

  it('renders a real bound identity fact from live status data, not the pane-a card', async () => {
    const { useStatusQuery } = await import('@/features/network/api/use-status-query')
    vi.mocked(useStatusQuery).mockReturnValue({ data: BOUND_OWNER_STATUS_PAYLOAD } as never)

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(await screen.findByText('Owner: linked (self-asserted) — not bound to a person.')).toBeInTheDocument()
    // The setup checklist's step 2 flips too -- same live owner data, saying
    // what binding established (UX §4).
    expect(screen.getByText('linked (self-asserted)')).toBeInTheDocument()
    expect(
      screen.getByText('Your records are signed by this node’s key, linked to your owner account (self-asserted).')
    ).toBeInTheDocument()
  })

  it('shows the default continuity sentence naming what would establish it', async () => {
    // Its own card: an earlier test's `mockResolvedValue` survives
    // `clearAllMocks`, and a reported checkpoint changes the sentence.
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({ rows: [], operator: null, witness_checkpoint_supplied: false, card: null })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(await screen.findByText('Continuity: not established. It needs a prior checkpoint for the next one to bind to.')).toBeInTheDocument()
    // Registration is explained once, in step 1 -- never repeated here (finding 7).
    expect(screen.queryByText(/^Registration is a separate step/)).not.toBeInTheDocument()
  })

  it('one checkpoint: continuity says so and what comes next (UX §4); the footer sits behind Details', async () => {
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: { checkpoint_count: 1, witnesses: [] }
    })
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(
      await screen.findByText(
        'Continuity: 1 checkpoint so far. The next one builds on it. A witness is what lets someone else check it too.'
      )
    ).toBeInTheDocument()
    // The node did not say whether a witness is set: step 1 says "not checked",
    // never "off", and there is no separate "Checkpointed locally" line.
    expect(screen.getAllByText('not checked').length).toBeGreaterThan(0)
    expect(screen.queryByText(/witness: off/)).not.toBeInTheDocument()
    expect(screen.queryByText(/off · your choice/)).not.toBeInTheDocument()
    const details = screen.getByTestId('integrity-details')
    expect(details.tagName).toBe('DETAILS')
    expect(details).not.toHaveAttribute('open')
    expect(within(details).getByText(/^Capture boundary: the plugin at this node’s serving boundary/)).toBeInTheDocument()
  })

  it('step 3 is a status with its denominator, carries no "Ask for their record" task, and the page says no "chain"', async () => {
    const { fetchPaneA, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: { checkpoint_count: 0 }
    })
    // Pushed halves arrive as `present-unverified` with the record attached;
    // a bare `present` only says they hold a record citing ours.
    const exchange = (key: string, theirs: PaneCRow['theirs']) => ({
      exchange_key: key,
      role_tag: 'ASKED',
      header_state: 'ok',
      properties: null,
      has_issue: false,
      mine: fixtureMineCell(`${key}-m`),
      theirs,
      unilateral: theirs.state === 'absent',
      timestamp: null
    })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        exchange('a', fixtureTheirsCell('agrees', { capsuleId: 'a'.repeat(64) })),
        exchange('b', fixtureTheirsCell('disagrees', { capsuleId: 'b'.repeat(64) })),
        exchange('c', { state: 'present', capsule_id: 'c'.repeat(64) }),
        exchange('d', { state: 'absent', capsule_id: null })
      ],
      row_count: 4,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    } as never)
    const user = userEvent.setup()
    const { container } = render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    // Step 3 and the tiles read the same gate: the agreeing and the
    // disagreeing pushed halves are held (2 of 4); the bare `present` row and
    // the absent one are not.
    const step = (await screen.findByText('2 of 4 received')).closest('li') as HTMLElement
    expect(within(step).getByText(/You hold both for 2 of 4/)).toBeInTheDocument()
    const tile = (label: string) => screen.getByText(label).closest('.panel-shell') as HTMLElement
    expect(tile('Confirmed by the other side')).toHaveTextContent('1 of 4')
    expect(tile('Disagreements')).toHaveTextContent('1 of 4')
    expect(within(step).getByRole('button', { name: 'See in Exchanges' })).toBeInTheDocument()
    expect(screen.queryByText(/ask for their record/i)).not.toBeInTheDocument()
    // The footer says what this page does and does not check.
    expect(screen.getByTestId('integrity-footer')).toHaveTextContent(
      'This page reads the node’s own status and doesn’t re-check it. Open an exchange to see checks redone in your browser.'
    )
    expect(container.textContent ?? '').not.toMatch(/\bchain\b/i)

    // "See in Exchanges" switches tabs.
    await user.click(within(step).getByRole('button', { name: 'See in Exchanges' }))
    expect(screen.getByRole('tab', { name: /exchanges/i })).toHaveAttribute('aria-selected', 'true')
  })

  it('a failed exchange list reads "not checked" on step 3 and both tiles, never "none yet"', async () => {
    const { fetchPaneA, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      rows: [],
      operator: null,
      witness_checkpoint_supplied: false,
      card: { checkpoint_count: 0 }
    })
    vi.mocked(fetchPaneCList).mockRejectedValue(new Error('pane c unavailable'))
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    const steps = await screen.findByTestId('setup-steps')
    const step3 = steps.querySelector('[data-step="ask_peer"]') as HTMLElement
    await waitFor(() => expect(within(step3).getByText('not checked')).toBeInTheDocument())
    expect(within(step3).queryByText('none yet')).not.toBeInTheDocument()
    const tile = (label: string) => screen.getByText(label).closest('.panel-shell') as HTMLElement
    expect(tile('Confirmed by the other side')).toHaveTextContent('not checked')
    expect(tile('Disagreements')).toHaveTextContent('not checked')
  })

  it('offers a range-wide "Save evidence file" action on Integrity', async () => {
    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))

    expect(await screen.findByRole('button', { name: /save evidence file/i })).toBeInTheDocument()
  })

  it('never renders "timestamped", "registered" or an ISO time anywhere on the Integrity section', async () => {
    const { fetchPaneA } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({
      operator: null,
      witness_checkpoint_supplied: true,
      rows: [],
      card: {
        checkpoint_count: 2,
        continuity: 'unbroken',
        witnesses: [{ operated_by_producer: false, checked: true }],
        registered_no_later_than: '2026-09-10'
      }
    })
    const { useStatusQuery } = await import('@/features/network/api/use-status-query')
    vi.mocked(useStatusQuery).mockReturnValue({ data: BOUND_OWNER_STATUS_PAYLOAD } as never)

    const user = userEvent.setup()
    const { container } = render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /integrity/i }))
    await screen.findByText(`witnessed no later than ${formatExchangeTimestamp('2026-09-10')}`)

    const sectionText = (container.textContent ?? '').toLowerCase()
    expect(sectionText).not.toMatch(/timestamped/)
    expect(sectionText).not.toMatch(/\bregistered\b/)
    expect(sectionText).not.toMatch(/\d{4}-\d\d-\d\dt\d\d:\d\d/)
  })
})

// ---------------------------------------------------------------------------
// windowed paging, sticky header, deep links,
// Next contradiction, keyboard map (v3 §2a).
// ---------------------------------------------------------------------------

const B3_BASE_TIMESTAMP = '2026-09-11T20:00:00.000Z'

/** Newest-first by construction -- index 0 is `B3_BASE_TIMESTAMP`, each
 *  later index one minute older -- so `sortStreamByTime` keeps index order
 *  stable and page N's rows are predictably `exch-<N*50>..exch-<N*50+49>`. */
function makeManyPaneCRows(count: number, contradictedIndexes: ReadonlySet<number> = new Set()) {
  return Array.from({ length: count }, (_, i) => {
    const contradicted = contradictedIndexes.has(i)
    return {
      exchange_key: `exch-${i}`,
      role_tag: 'ASKED',
      header_state: contradicted ? 'issue' : 'ok',
      properties: {
        outcome_corroboration: { state: contradicted ? 'FAIL' : 'PASS' }
      },
      has_issue: contradicted,
      mine: { state: 'present', capsule_id: `mine-${i}` },
      theirs: { state: 'present', capsule_id: `theirs-${i}` },
      unilateral: false,
      timestamp: new Date(new Date(B3_BASE_TIMESTAMP).getTime() - i * 60_000).toISOString()
    }
  })
}

function b3PaneCPayload(rows: ReturnType<typeof makeManyPaneCRows>) {
  return {
    rows,
    row_count: rows.length,
    default_sort: '',
    filters: [],
    next_after_seq: null,
    archived_segments: []
  }
}

describe('LedgerPageContent — Part B3: windowed paging + sticky header', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  // Renders 120 rows and pages through them: about 5 s on a 4-vCPU box, which
  // is the default timeout, so it gets its own.
  it('windows into pages of 50 with an honest full-range banner, Older/Newer paging the rest', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(120)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    // Page 1: newest 50 (exch-0..exch-49), never exch-50.
    expect(await screen.findByRole('group', { name: 'Exchange exch-0' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Exchange exch-49' })).toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Exchange exch-50' })).not.toBeInTheDocument()

    // L-K — the full-range count states its own span, never a bare number.
    expect(screen.getByText(/Showing 50 of 120 exchanges/)).toBeInTheDocument()
    expect(
      screen.getByText('Not shown here: exchanges outside this range. Counts above are for the full range.')
    ).toBeInTheDocument()

    const newerButton = screen.getByRole('button', { name: 'Newer exchanges' })
    expect(newerButton).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Older exchanges' }))
    expect(await screen.findByRole('group', { name: 'Exchange exch-50' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Exchange exch-99' })).toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Exchange exch-0' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Newer exchanges' }))
    expect(await screen.findByRole('group', { name: 'Exchange exch-0' })).toBeInTheDocument()
  }, 20_000)

  it('the YOUR RECORD / THEIR RECORD column header is a single sticky header, never repeated per row', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(5)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    await screen.findByRole('group', { name: 'Exchange exch-0' })
    expect(screen.getAllByText('YOUR RECORD')).toHaveLength(1)
    expect(screen.getAllByText('THEIR RECORD, AS GIVEN TO YOU')).toHaveLength(1)
    // Look finding 5: one page scroll -- the list is never its own scroll box,
    // and no ancestor clips with `overflow-hidden` (which would break sticky).
    const list = screen.getByTestId('exchange-list')
    expect(screen.getByText('YOUR RECORD').parentElement?.className).toMatch(/\bsticky\b/)
    for (let el: HTMLElement | null = list; el; el = el.parentElement) {
      expect(el.className).not.toMatch(/overflow-(y-)?(auto|scroll|hidden)|max-h-/)
    }
  })

  it('a deep-linked exchange key jumps to its page, highlights the row, and expands its checks inline', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(120)))

    render(<LedgerPageContent focusExchangeKey="exch-75" />, { wrapper: makeWrapper() })

    // Auto-selects the Exchanges tab -- no manual click needed.
    const row = await screen.findByLabelText('Exchange exch-75')
    expect(row).toHaveTextContent('mine-75')
    // Page 2 (exch-50..exch-99), never page 1's exch-0.
    expect(screen.queryByRole('group', { name: 'Exchange exch-0' })).not.toBeInTheDocument()

    expect(row).toHaveAttribute('aria-current', 'true')
    expect(row).toHaveAttribute('data-highlighted', 'true')

    // Expands the same full-detail checks view inline a click would --
    // never a dialog.
    const checksRegion = await screen.findByRole('region', { name: /Security checks for exch-75/ })
    expect(checksRegion).toHaveAccessibleName(/exch-75/)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  // finding 1 side effect: a
  // CONTRADICTED right-cell now requires a genuine `theirsRecompute` fetch
  // this browser ran (`exchange-row-state.ts`), which lives in per-row
  // component state, never in the page-level `allRows` list `jumpToNext
  // Contradiction` scans. `makeManyPaneCRows`'s old `contradictedIndexes`
  // knob drove `outcome_corroboration: FAIL`, a signal the fix correctly
  // stopped trusting -- so it can no longer produce a page-level
  // "contradicted" row at all. Documented here rather than deleted: "Next
  // contradiction" is honestly unreachable until live per-row fetch results
  // are lifted to shared page state (a real follow-on, not silently
  // dropped).
  it('Next contradiction ▸ stays absent even over data that used to (dishonestly) trigger it', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(120, new Set([90]))))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-0' })

    expect(screen.queryByRole('button', { name: 'Next contradiction ▸' })).not.toBeInTheDocument()
  })

  it('Next contradiction ▸ is absent when nothing is contradicted', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(3)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-0' })

    expect(screen.queryByRole('button', { name: 'Next contradiction ▸' })).not.toBeInTheDocument()
  })

  it('a twin-sized atomic group never splits a page boundary (component-level smoke; pure-fn coverage in exchange-pages.test.ts)', async () => {
    // Plain (non-bracket) rows -- this re-confirms 50 rows/page holds at
    // the component level for ordinary singleton groups; the load-bearing
    // multi-row-bracket invariant itself is unit-tested against a
    // synthetic 3-row group in exchange-pages.test.ts, and the REAL
    // bracket rendering is covered by the
    // twin-bracket describe block below.
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(51)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    expect(await screen.findByRole('group', { name: 'Exchange exch-49' })).toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Exchange exch-50' })).not.toBeInTheDocument()
  })

  it('keyboard map: j/k moves the row cursor, o toggles content inline, c reveals Checks inline, / focuses search', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(3)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-0' })

    const rowAt = (exchangeKey: string) => screen.getByLabelText(`Exchange ${exchangeKey}`)
    expect(rowAt('exch-0')).toHaveAttribute('data-focused', 'true')

    await user.keyboard('j')
    expect(rowAt('exch-1')).toHaveAttribute('data-focused', 'true')
    expect(rowAt('exch-0')).not.toHaveAttribute('data-focused')

    await user.keyboard('k')
    expect(rowAt('exch-0')).toHaveAttribute('data-focused', 'true')

    await user.keyboard('/')
    expect(screen.getByLabelText('Search exchanges')).toHaveFocus()
    await user.tab() // leave the search box so `o`/`c` aren't swallowed by isTypingTarget

    // `o` toggles Toggle ① content inline --
    // these fixture rows carry no evidence_outcome, so the their-content side
    // honestly degrades to the never-asked sub-state (L-C).
    await user.keyboard('o')
    expect(await screen.findByText('Not compared: they aren’t expected to keep the text of what was said.')).toBeInTheDocument()
    await user.keyboard('o')
    expect(screen.queryByText('Not compared: they aren’t expected to keep the text of what was said.')).not.toBeInTheDocument()

    await user.keyboard('c')
    expect(await screen.findByRole('region', { name: /Security checks for exch-0/ })).toBeInTheDocument()
  })

  it('Escape closes whichever expansion is open', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(3)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-0' })

    await user.keyboard('c')
    expect(await screen.findByRole('region', { name: /Security checks for exch-0/ })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('region', { name: /Security checks/ })).not.toBeInTheDocument()

    await user.keyboard('o')
    expect(await screen.findByText('Not compared: they aren’t expected to keep the text of what was said.')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByText('Not compared: they aren’t expected to keep the text of what was said.')).not.toBeInTheDocument()

    // Escape with nothing expanded is a no-op -- doesn't error, doesn't
    // swallow the event (nothing else to assert here beyond "it didn't throw").
    await user.keyboard('{Escape}')
  })

  it('keyboard shortcuts never fire while typing in the search box (e.g. typing "exch" never toggles anything)', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(b3PaneCPayload(makeManyPaneCRows(3)))

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findByRole('group', { name: 'Exchange exch-0' })

    await user.click(screen.getByLabelText('Search exchanges'))
    // "exch" matches every exchange_key here (they all start with "exch-"),
    // so the row stays mounted to assert against -- the point is that the
    // 'c' it contains never toggles Checks while typing.
    await user.keyboard('exch')

    expect(screen.getByLabelText('Exchange exch-0')).toHaveAttribute('data-focused', 'true')
    expect(screen.queryByRole('region', { name: /Security checks/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// a real twin bracket sourced from the payload
// (not the synthetic ExchangeRowGroup used in the pure-fn/paging tests
// above), and the "Twins only" filter actually filtering by it now that
// rows can carry a real `twin_bracket_id`.
// ---------------------------------------------------------------------------

const TWIN_BASE_TIMESTAMP = '2026-09-14T12:00:00.000Z'

function twinPaneCRow(i: number, overrides: Partial<ReturnType<typeof makeManyPaneCRows>[number]> = {}) {
  return {
    exchange_key: `twin-exch-${i}`,
    role_tag: 'ASKED',
    header_state: 'ok',
    properties: { outcome_corroboration: { state: 'PASS' } },
    has_issue: false,
    mine: { state: 'present', capsule_id: `twin-mine-${i}` },
    theirs: { state: 'present', capsule_id: `twin-theirs-${i}` },
    unilateral: false,
    timestamp: new Date(new Date(TWIN_BASE_TIMESTAMP).getTime() - i * 1_000).toISOString(),
    twin_bracket_id: 'twin-abc',
    ...overrides
  }
}

function twinBracketPayload() {
  // Two adjacent twin rows (newest, indices 0/1) plus two ordinary rows
  // further back in time -- the bracket must render, and the plain rows
  // must render exactly as ordinary rows alongside it.
  const plainRows = makeManyPaneCRows(2).map((row, i) => ({
    ...row,
    timestamp: new Date(new Date(TWIN_BASE_TIMESTAMP).getTime() - (10 + i) * 1_000).toISOString()
  }))
  const rows = [twinPaneCRow(0), twinPaneCRow(1), ...plainRows]
  return b3PaneCPayload(rows as ReturnType<typeof makeManyPaneCRows>)
}

describe('LedgerPageContent — real twin bracket + Twins-only filter', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('brackets two adjacent rows sharing a real twin_bracket_id with a TWIN header, and renders the disclosure sentence', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(twinBracketPayload())

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    expect(await screen.findByTestId('twin-bracket-twin-abc')).toHaveTextContent('Same request, two machines · twin-abc')
    expect(screen.getByRole('group', { name: 'Exchange twin-exch-0' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Exchange twin-exch-1' })).toBeInTheDocument()
    expect(
      screen.getByText('A client marked these two requests as one pair.')
    ).toBeInTheDocument()
    // Never a computed verdict.
    expect(screen.getByText('not adjudicated')).toBeInTheDocument()
  })

  it('a lone row carrying a bracket id whose twin is absent from the payload renders as an ordinary row, never a half-bracket', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(
      b3PaneCPayload([twinPaneCRow(0)] as ReturnType<typeof makeManyPaneCRows>)
    )

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    expect(await screen.findByRole('group', { name: 'Exchange twin-exch-0' })).toBeInTheDocument()
    expect(screen.queryByText(/Side-by-side check/)).not.toBeInTheDocument()
  })

  it('"Sent to two machines" actually filters to bracket rows now that a real bracket id exists', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneCList).mockResolvedValue(twinBracketPayload())

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    // Before filtering: both the bracket and the plain rows are visible.
    expect(await screen.findByRole('group', { name: 'Exchange twin-exch-0' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Exchange exch-0' })).toBeInTheDocument()

    await user.click(screen.getByLabelText('Filter exchanges'))
    const stateSection = (await screen.findByText('State')).closest('section')
    if (!stateSection) throw new Error('State filter section not found')
    await user.click(within(stateSection).getByRole('button', { name: 'None' }))
    await user.click(within(stateSection).getByLabelText(/Sent to two machines,/))

    expect(await screen.findByRole('group', { name: 'Exchange twin-exch-0' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Exchange twin-exch-1' })).toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Exchange exch-0' })).not.toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Exchange exch-1' })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// A served exchange with no other side (a chat this node served from its own
// console) is LOCAL: badged so, and in no open count.
// ---------------------------------------------------------------------------

describe('LedgerPageContent — a served exchange with no other side', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('is badged "No other side", and the state filter counts it there, not under "Waiting for theirs"', async () => {
    const { fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    const served = (key: string, counterparty: string | null) => ({
      exchange_key: key,
      role_tag: 'SERVED',
      header_state: 'absent',
      properties: null,
      has_issue: false,
      counterparty,
      mine: { state: 'present-unverified', capsule_id: `${key}-mine`, role: 'served' },
      theirs: { state: 'absent', capsule_id: null },
      unilateral: true,
      timestamp: '2026-10-05T22:39:00Z'
    })
    vi.mocked(fetchPaneCList).mockResolvedValue(
      b3PaneCPayload([served('local-exch', null), served('remote-exch', 'key:2b4600')] as unknown as ReturnType<
        typeof makeManyPaneCRows
      >)
    )

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))

    const local = await screen.findByRole('group', { name: 'Exchange local-exch' })
    expect(within(local).getByText('No other side')).toBeInTheDocument()
    expect(within(local).queryByText('Waiting for theirs')).not.toBeInTheDocument()
    const remote = screen.getByRole('group', { name: 'Exchange remote-exch' })
    expect(within(remote).getByText('Waiting for theirs')).toBeInTheDocument()

    await user.click(screen.getByLabelText('Filter exchanges'))
    const stateSection = (await screen.findByText('State')).closest('section')
    if (!stateSection) throw new Error('State filter section not found')
    expect(within(stateSection).getByLabelText(/^Waiting for theirs, 1 /)).toBeInTheDocument()
    expect(within(stateSection).getByLabelText(/^No other side, 1 /)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Peers: a peer's twin pairs, as facts (how many, how many answers differed,
// whether a referee ruled), so a peer whose twin answers differed does not
// read clean on Peers. Never a judgement word.
// ---------------------------------------------------------------------------

describe('LedgerPageContent — twin pairs on Peers', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  function paneBPeer(peerId: string) {
    return {
      peer_id: peerId,
      node: { state: 'present', text: peerId, peer_id: peerId, member_kind: 'member', exchange_count: 3 },
      rung: { state: 'present', text: 'full_bilateral', rung: 'full_bilateral', distinct_rungs: ['full_bilateral'] },
      role: {
        state: 'present',
        text: 'you_to_them · 3',
        role: 'you_to_them',
        you_to_them_count: 3,
        them_to_you_count: 0,
        exchange_count: 3
      },
      history: { state: 'NOT_CHECKED', text: null },
      served: { state: 'NOT_CHECKED', text: null },
      pair: { state: 'absent', text: null, verified: 0, failed: 0, missing: 0, details: [] },
      verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } },
      asked: { state: 'absent', text: null, count: 0 },
      exchange_count: 3,
      first_seen: null,
      last_seen: null
    }
  }

  function twinHalf(i: number, counterparty: string, otherRow: string) {
    return {
      exchange_key: `${counterparty}-${i}`,
      role_tag: 'ASKED',
      counterparty,
      header_state: 'ok',
      properties: null,
      has_issue: false,
      mine: { state: 'present', capsule_id: `${counterparty}-${i}-mine` },
      theirs: { state: 'present', capsule_id: `${counterparty}-${i}-theirs` },
      unilateral: false,
      timestamp: '2026-10-05T21:00:00Z',
      twin_bracket_id: `b${i}`,
      twin: { bracket_id: `b${i}`, same_answer: false, other_row: otherRow }
    }
  }

  it('answers that merely differed byte for byte are not a finding: Swapped the model stays Not tested and no inferred line is drawn', async () => {
    const { fetchPaneB, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneB).mockResolvedValue({
      rows: [paneBPeer('node:adversary'), paneBPeer('node:other')],
      peer_count: 2
    } as unknown as Awaited<ReturnType<typeof fetchPaneB>>)
    vi.mocked(fetchPaneCList).mockResolvedValue(
      b3PaneCPayload(
        [1, 2, 3].flatMap((i) => [
          twinHalf(i, 'node:adversary', `key:second-${i}`),
          twinHalf(i, 'key:second', `node:adversary-${i}`)
        ]) as unknown as ReturnType<typeof makeManyPaneCRows>
      )
    )

    const user = userEvent.setup()
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /peers/i }))

    expect((await screen.findAllByText('Not tested')).length).toBe(2)
    expect(screen.queryByText(/answers differed/)).not.toBeInTheDocument()
    expect(document.querySelectorAll('[data-peer-twins="true"]')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// A peer known only from our own records: the key this node knows for it
// comes from the plugin's peer-key route, which merges the host's announced
// keys with the operator's CAPSULES_PEER_KEYS. On a host with no
// plugin_keys.v1 the configured key is all there is; the line claims no source.
// ---------------------------------------------------------------------------

describe('LedgerPageContent — a peer known only from your records', () => {
  const NODE = 'c'.repeat(64)
  async function renderNodeOnlyPeer(key: string | null) {
    const { fetchPaneB } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneB).mockResolvedValue({
      rows: [
        {
          peer_id: 'node:cccccccccccccccc',
          identity: { signing_key_id: null, endpoint_id: null, node_id: NODE },
          exchange_count: 1,
          last_seen: null
        }
      ],
      peer_count: 1
    } as never)
    const { announcedKeyFor } = await import('@/features/capsules/api/evidenceRequestClient')
    vi.mocked(announcedKeyFor).mockResolvedValue(key)
    render(<LedgerPageContent />, { wrapper: makeWrapper() })
    return announcedKeyFor
  }

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('a history check that passes in the peer drawer is remembered like the Exchanges row’s', async () => {
    await renderNodeOnlyPeer(null)
    const user = userEvent.setup()
    await user.click(await screen.findByLabelText(/^Open peer inspector for /))
    await user.click(await screen.findByRole('button', { name: 'Ask a peer for their history' }))
    expect(await screen.findByText(/Their history checks out/)).toBeInTheDocument()
    const stored = JSON.parse(window.localStorage.getItem(HISTORY_MEMORY_KEY) ?? '{}')
    expect(stored[NODE]).toMatchObject({ kind: 'verified', checkpoints: 2 })
  })

  it('names the signing key this node knows for it (here only configured), claiming no source', async () => {
    const announcedKeyFor = await renderNodeOnlyPeer('e'.repeat(64))
    expect(
      await screen.findByText(`Known from your records · its signing key ${'e'.repeat(16)} is known to this node`)
    ).toBeInTheDocument()
    expect(announcedKeyFor).toHaveBeenCalledWith(NODE)
    expect(document.body.textContent).not.toMatch(/announced|no signing key linked/)
  })

  it('with no key known (no plugin_keys.v1 and none configured), says no signed record yet', async () => {
    await renderNodeOnlyPeer(null)
    expect(await screen.findByText('Known from your records · no signed record from them yet')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// The plain-verdict pass: names before hex, asks that persist, the intro line
// ---------------------------------------------------------------------------

describe('LedgerPageContent — the plain-verdict pass on Exchanges', () => {
  const PEER = 'c'.repeat(64)

  async function oneAskableRow() {
    const { fetchPaneA, fetchPaneB, fetchPaneCList } = await import('@/features/capsules/api/sidecarClient')
    vi.mocked(fetchPaneA).mockResolvedValue({ rows: [], operator: null, witness_checkpoint_supplied: false, card: null })
    vi.mocked(fetchPaneB).mockResolvedValue({ rows: [], peer_count: 0 })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [
        {
          exchange_key: 'exch-askable',
          role_tag: 'ASKED',
          header_state: 'issue',
          properties: null,
          has_issue: true,
          counterparty: `node:${'c'.repeat(16)}`,
          mine: { state: 'present', capsule_id: 'mine-askable' },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: '2026-09-08T08:03:00Z'
        }
      ],
      row_count: 1,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    })
    const { fetchCapsuleLedger } = await import('@/features/capsules/api/client')
    vi.mocked(fetchCapsuleLedger).mockResolvedValue({
      records: [
        {
          capsule_id: 'mine-askable',
          effect: { request_digest: 'a'.repeat(64), response_digest: 'b'.repeat(64) },
          model_attestation: {
            compute_attestation: {
              'x-mesh-poc-v1': {
                role: 'requested',
                client_nonce: 'nonce-askable',
                serving_provenance: { served_by_node_id: PEER }
              }
            }
          }
        }
      ],
      nodePubKeyPem: null
    } as never)
    return { fetchPaneCList }
  }

  async function openExchanges() {
    const user = userEvent.setup()
    const view = render(<LedgerPageContent />, { wrapper: makeWrapper() })
    await user.click(screen.getByRole('tab', { name: /exchanges/i }))
    await screen.findAllByRole('button', { name: 'Ask for their history' })
    return { user, ...view }
  }

  afterEach(async () => {
    const { useStatusQuery } = await import('@/features/network/api/use-status-query')
    vi.mocked(useStatusQuery).mockReturnValue({ data: undefined } as never)
    vi.clearAllMocks()
    cleanup()
  })

  it('says once, with one colon, that no client marked a pair', async () => {
    const { fetchPaneCList } = await oneAskableRow()
    const list = await vi.mocked(fetchPaneCList).getMockImplementation()?.()
    vi.mocked(fetchPaneCList).mockResolvedValue({ ...(list as object), referee: { twins_marked: false } } as never)
    await openExchanges()
    expect(screen.getByTestId('twins-unmarked')).toHaveTextContent(
      'Side-by-side check — No ruling yet: no client marked these as a pair.'
    )
    expect(screen.getByTestId('twins-unmarked').textContent?.match(/:/g)).toHaveLength(1)
  })

  it('opens with one line saying what a row is and what Confirmed means', async () => {
    await oneAskableRow()
    await openExchanges()
    expect(
      screen.getByText('Each exchange leaves two signed records, one per side. Confirmed means both say the same thing.')
    ).toBeInTheDocument()
  })

  it('names the other node by its hostname, then its short id', async () => {
    const { useStatusQuery } = await import('@/features/network/api/use-status-query')
    vi.mocked(useStatusQuery).mockReturnValue({
      data: { ...BOUND_OWNER_STATUS_PAYLOAD, peers: [{ id: 'cccccccccc', hostname: 'Ethans-Mac-Mini.local' }] }
    } as never)
    await oneAskableRow()
    await openExchanges()
    // The event line names the node our record names, its full id as the title.
    const named = screen.getByText('Ethans-Mac-Mini (cccccccccc)')
    expect(named).toHaveAttribute('title', PEER)
  })

  it('a verified history result is remembered per peer, and shown after a reload with when it was checked', async () => {
    await oneAskableRow()
    const first = await openExchanges()
    await first.user.click(screen.getByRole('button', { name: 'Ask for their history' }))
    expect(await screen.findByText(/^✓ Their history checks out · 2 checkpoints/)).toBeInTheDocument()
    first.unmount()

    // A fresh page, no ask sent: the remembered result shows, with its time.
    await oneAskableRow()
    await openExchanges()
    expect(await screen.findByText(/^✓ Their history checks out · 2 checkpoints/)).toBeInTheDocument()
    expect(document.querySelector('[data-history-checked]')?.textContent).toMatch(/checked /)
    // Its witness standing came back with it.
    expect(document.querySelector('[data-history-witness="witnessed"]')).not.toBeNull()
    const { askForHistory } = await import('@/features/capsules/api/evidenceRequestClient')
    expect(askForHistory).toHaveBeenCalledTimes(1)
  })

  it('a history remembered before its witness standing was kept says the standing was not recorded, never ✓', async () => {
    await oneAskableRow()
    window.localStorage.setItem(
      HISTORY_MEMORY_KEY,
      JSON.stringify({ [PEER]: { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 2 } })
    )
    await openExchanges()
    expect(await screen.findByText(/^Their history checked against their own signatures · 2 checkpoints/)).toBeInTheDocument()
    const line = document.querySelector('[data-history-reply-verified]') as HTMLElement
    expect(line).toHaveAttribute('data-history-reply-verified', 'false')
    expect(line).toHaveAttribute('data-history-witness', 'not_recorded')
    expect(screen.getByRole('button', { name: 'About their history' })).toHaveAccessibleDescription(
      expect.stringContaining('Its witness standing was not recorded, so it could be a private copy')
    )
    expect(screen.queryByText(/✓ Their history checks out/)).not.toBeInTheDocument()
  })

  it('a remembered history shows once, on that peer’s newest row, never on its older rows', async () => {
    const { fetchPaneCList } = await oneAskableRow()
    const row = (key: string, capsuleId: string, timestamp: string) => ({
      exchange_key: key,
      role_tag: 'ASKED',
      header_state: 'issue',
      properties: null,
      has_issue: true,
      mine: { state: 'present', capsule_id: capsuleId },
      theirs: { state: 'absent', capsule_id: null },
      unilateral: true,
      timestamp
    })
    vi.mocked(fetchPaneCList).mockResolvedValue({
      rows: [row('exch-older', 'mine-older', '2026-09-01T08:00:00Z'), row('exch-newer', 'mine-newer', '2026-09-08T08:00:00Z')],
      row_count: 2,
      default_sort: '',
      filters: [],
      next_after_seq: null,
      archived_segments: []
    } as never)
    const record = (capsuleId: string) => ({
      capsule_id: capsuleId,
      effect: { request_digest: 'a'.repeat(64), response_digest: 'b'.repeat(64) },
      model_attestation: {
        compute_attestation: {
          'x-mesh-poc-v1': { role: 'requested', client_nonce: `n-${capsuleId}`, serving_provenance: { served_by_node_id: PEER } }
        }
      }
    })
    const { fetchCapsuleLedger } = await import('@/features/capsules/api/client')
    vi.mocked(fetchCapsuleLedger).mockResolvedValue({
      records: [record('mine-older'), record('mine-newer')],
      nodePubKeyPem: null
    } as never)
    window.localStorage.setItem(
      HISTORY_MEMORY_KEY,
      JSON.stringify({ [PEER]: { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 2, witness: 'witnessed' } })
    )
    await openExchanges()
    expect(await screen.findAllByText(/^✓ Their history checks out · 2 checkpoints/)).toHaveLength(1)
    const newer = screen.getByLabelText('Exchange exch-newer')
    const older = screen.getByLabelText('Exchange exch-older')
    expect(within(newer).getByText(/^✓ Their history checks out/)).toBeInTheDocument()
    expect(within(older).queryByText(/^✓ Their history checks out/)).not.toBeInTheDocument()
  })

  it('after an ask brings back a record, the page reads its panes again so the row comes from the node', async () => {
    const { fetchPaneCList } = await oneAskableRow()
    const { judgeAskReply } = await import('@/features/capsules/lib/ask-for-record')
    vi.mocked(judgeAskReply).mockResolvedValueOnce({
      kind: 'record',
      at: '2026-09-28T23:00:00Z',
      evidence: { status: 'found', idMatch: true, signatureOk: true, peerRecord: {}, fetch: () => {} }
    })
    const { user } = await openExchanges()
    const before = vi.mocked(fetchPaneCList).mock.calls.length
    await user.click(screen.getByRole('button', { name: 'Ask for their record' }))
    await vi.waitFor(() => expect(vi.mocked(fetchPaneCList).mock.calls.length).toBeGreaterThan(before))
  })

  it('an ask that gets no record back does not read the panes again', async () => {
    const { fetchPaneCList } = await oneAskableRow()
    const { user } = await openExchanges()
    const before = vi.mocked(fetchPaneCList).mock.calls.length
    await user.click(screen.getByRole('button', { name: 'Ask for their record' }))
    expect(await screen.findByText(/The ask didn’t go through/)).toBeInTheDocument()
    expect(vi.mocked(fetchPaneCList).mock.calls.length).toBe(before)
  })
})

