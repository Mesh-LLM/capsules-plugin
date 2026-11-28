// The receipt on a row, each case rendered from a real bundle: the
// agent-action-capsule strict vector `incomplete-producer-selected` (a
// producer-selected bundle, the shape the plugin's receipt routes serve) and
// the composed/v1 vector `agree-with-checkpoints` (two copies that agree). The
// bytes are the vectors' own, copied unchanged.
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ReceiptPanel } from '@/features/capsules/components/ReceiptPanel'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { receiptPath } from '@/features/capsules/api/receiptClient'
import { NOT_DRAWN_LINES, checkReceiptBundle, receiptRequest, receiptView } from '@/features/capsules/lib/receipt-view'
import composedAgree from '@/features/capsules/lib/receipt-fixtures/composed-agree.bundle.json'
import producerSelected from '@/features/capsules/lib/receipt-fixtures/producer-selected.bundle.json'
// A payer's deal receipt as the plugin's own route cuts it: the bundle
// `deal_receipt::tests::a_paid_exchange_gives_a_bundle_of_exactly_its_four_deal_records`
// writes with DEAL_RECEIPT_BUNDLE_OUT set (Mesh-LLM/capsules-plugin#376).
import meshPayerDeal from '@/features/capsules/lib/receipt-fixtures/mesh-payer-deal.bundle.json'
// A provider's own receipt as the plugin's `provider-receipt-bundle` route cuts
// it (Mesh-LLM/capsules-plugin#134): the served exchange record and its two
// payee legs, copied unchanged from capsule-viewer's
// tests/testdata/receipt/mesh-provider-selected.bundle.json (capsule-viewer#390).
import meshProviderSelected from '@/features/capsules/lib/receipt-fixtures/mesh-provider-selected.bundle.json'

const EXCHANGE_RECORD = 'ab'.repeat(32)

const payerRow = {
  role_tag: 'ASKED',
  mine: { state: 'ok', capsule_id: EXCHANGE_RECORD },
  settlement: { observed_by: 'payer', state: 'settled', terms_digests: [], entries: [] }
} as unknown as PaneCRow

const providerRow = {
  role_tag: 'SERVED',
  mine: { state: 'ok', capsule_id: null },
  provider_settlement: {
    observed_by: 'provider',
    state: 'settled',
    terms_digests: [],
    entries: [],
    exchange_ids: ['ex-1']
  }
} as unknown as PaneCRow

/** Answer the receipt route with `body`, and remember the path asked. */
function routeAnswers(body: unknown, ok = true, status = 200) {
  const fetchSpy = vi.fn().mockResolvedValue({ ok, status, json: async () => body } as Response)
  vi.stubGlobal('fetch', fetchSpy)
  return fetchSpy
}

/** The same SubtleCrypto with Ed25519 import refused, as a browser without it
 *  does (the runtime probes `importKey` for `NotSupportedError`). */
function withoutEd25519() {
  const real = globalThis.crypto.subtle
  const subtle = {
    digest: real.digest.bind(real),
    importKey: async () => {
      throw Object.assign(new Error('Ed25519 is not supported'), { name: 'NotSupportedError' })
    }
  }
  vi.stubGlobal('crypto', { subtle, getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto) })
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function check() {
  await userEvent.click(screen.getByRole('button', { name: 'Check receipt' }))
}

describe('ReceiptPanel', () => {
  it('shows "your receipt only" for the payer receipt, with every count over its denominator', async () => {
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: JSON.stringify(meshPayerDeal) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    const label = await screen.findByText('Receipt: your receipt only')
    expect(label).toHaveAttribute('data-receipt-case', 'your receipt only')
    // 4 deal records, each bound to the signed checkpoint.
    expect(screen.getByText(/4 of 4 records in the receipt are tied to a signed checkpoint/)).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0][0])).toContain(
      `/api/plugins/capsules/http/deal-receipt-bundle?capsule_id=${EXCHANGE_RECORD}`
    )
  })

  it('shows "your receipt only" for the provider receipt, asked by the host exchange id', async () => {
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: JSON.stringify(meshProviderSelected) })
    render(<ReceiptPanel row={providerRow} />)
    await check()
    await screen.findByText('Receipt: your receipt only')
    expect(screen.getByText(/of 3 records in the receipt are tied to a signed checkpoint/)).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0][0])).toContain('http/provider-receipt-bundle?exchange_id=ex-1')
  })

  // A bundle that verifies but that no viewer receipt module draws, such as
  // two agreeing copies that are not a deal or a provider's receipt: the
  // not-drawn lines (Sherlock2 on #398), never a case, an error or a verdict.
  it.each([
    ['two agreeing copies that are no receipt', composedAgree, payerRow],
    ['a generic producer-selected bundle on a provider row', producerSelected, providerRow]
  ])('shows the not-drawn lines for %s, with "Save bundle"', async (_name, bundle, row) => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(bundle) })
    render(<ReceiptPanel row={row} />)
    await check()
    expect(await screen.findByText(NOT_DRAWN_LINES.join(' '))).toHaveAttribute('data-receipt-case', 'not-drawn')
    expect(screen.getByRole('button', { name: 'Save bundle' })).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
    expect(screen.queryByText(/did not verify/)).not.toBeInTheDocument()
  })

  it('shows "no record" for a refusal from the route, not an error', async () => {
    routeAnswers({ state: 'refused', why: 'this node holds no deal for that exchange' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('Receipt: no record')).toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
  })

  it('says it cannot check the receipt in a browser without Ed25519, with no verdict', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    withoutEd25519()
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await waitFor(() => expect(screen.getByText(/this browser can't check the receipt/)).toBeInTheDocument())
    expect(screen.getByText(/offline viewer/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/did not verify/)).not.toBeInTheDocument()
  })

  it('does not call a tampered bundle a receipt', async () => {
    const tampered = JSON.parse(JSON.stringify(producerSelected))
    tampered.records[0].capsule_id = 'f'.repeat(64)
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(tampered) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('shows a route failure as a load error, never as a case', async () => {
    routeAnswers({}, false, 500)
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/could not be loaded here/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('draws nothing for rows that are not a paid exchange this node can name', () => {
    const rows = [
      { role_tag: 'ASKED', mine: { capsule_id: EXCHANGE_RECORD }, settlement: null },
      { role_tag: 'ASKED', mine: { capsule_id: EXCHANGE_RECORD }, settlement: { state: 'terms_only' } },
      { role_tag: 'ASKED', mine: { capsule_id: null }, settlement: { state: 'settled' } },
      { role_tag: 'SERVED', mine: {}, provider_settlement: { state: 'settled', exchange_ids: ['a', 'b'] } }
    ] as unknown as PaneCRow[]
    for (const row of rows) {
      const { container } = render(<ReceiptPanel row={row} />)
      expect(container).toBeEmptyDOMElement()
      cleanup()
    }
  })
})

describe('ReceiptPanel states', () => {
  it('shows a refusal that is not "no record" as "no receipt yet:" with the route\'s reason word for word', async () => {
    routeAnswers({ state: 'refused', why: 'no signed checkpoint covers the deal yet' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('no receipt yet: no signed checkpoint covers the deal yet')).toBeInTheDocument()
    expect(screen.queryByText(/Receipt: no record/)).not.toBeInTheDocument()
    expect(screen.queryByText(/holds no sealed deal/)).not.toBeInTheDocument()
  })

  it('shows the provider route\'s own refusal, with no payer-only sentence', async () => {
    const why = 'this node holds no single served record for that exchange'
    routeAnswers({ state: 'refused', why })
    render(<ReceiptPanel row={providerRow} />)
    await check()
    expect(await screen.findByText(why)).toBeInTheDocument()
    expect(screen.queryByText(/sealed deal/)).not.toBeInTheDocument()
  })

  it.each([
    ['this node noted no payment received for that exchange', false],
    ['this node holds no single served record for that exchange', true],
    ['this node holds no deal for that exchange', true],
    ['the deal has no report yet', false],
    ['the payload of deal record abc is not kept', false]
  ])('maps the refusal "%s" (no record: %s)', async (why, noRecord) => {
    const view = await receiptView({ kind: 'refused', why })
    expect(view.kind).toBe(noRecord ? 'no_record' : 'no_receipt_yet')
  })

  it('lets the owner ask again after a load error', async () => {
    routeAnswers({}, false, 500)
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await screen.findByText(/could not be loaded here/)
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(meshPayerDeal) })
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }))
    expect(await screen.findByText('Receipt: your receipt only')).toBeInTheDocument()
  })

  it('announces its result in a live status region and keeps the button mounted', async () => {
    routeAnswers({ state: 'refused', why: 'the deal has no report yet' })
    render(<ReceiptPanel row={payerRow} />)
    const button = screen.getByRole('button', { name: 'Check receipt' })
    await userEvent.click(button)
    const status = screen.getByRole('status')
    await waitFor(() => expect(status).toHaveTextContent('no receipt yet: the deal has no report yet'))
    expect(button).toBeInTheDocument()
  })

  it('shows a bundle served as an object, not as its text, as a load error', async () => {
    routeAnswers({ state: 'bundle', bundle: producerSelected })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/could not be loaded here/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('reads text that is not JSON as did-not-verify, not a load error', async () => {
    routeAnswers({ state: 'bundle', bundle: '{not json' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
  })

  it('reads a bundle the runtime cannot read as did-not-verify, not a load error', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify({ not: 'a bundle' }) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
  })

  it('offers "Save bundle" in the can\'t-check and did-not-verify states, saving the bundle served', async () => {
    const created: Blob[] = []
    const urlStub = {
      createObjectURL: (blob: Blob) => (created.push(blob), 'blob:x'),
      revokeObjectURL: () => {}
    }
    vi.stubGlobal(
      'URL',
      Object.assign(function () {}, urlStub)
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    withoutEd25519()
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await userEvent.click(await screen.findByRole('button', { name: 'Save bundle' }))
    // The bytes the node served, unchanged.
    expect(await created[0].text()).toBe(JSON.stringify(producerSelected))
    cleanup()
    vi.unstubAllGlobals()
    vi.stubGlobal(
      'URL',
      Object.assign(function () {}, urlStub)
    )

    const tampered = { ...producerSelected, records: [{ ...producerSelected.records[0], capsule_id: 'f'.repeat(64) }] }
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(tampered) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await userEvent.click(await screen.findByRole('button', { name: 'Save bundle' }))
    expect(await created[1].text()).toBe(JSON.stringify(tampered))
  })

  it('does not offer "Save bundle" for a receipt that checked', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(meshPayerDeal) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await screen.findByText('Receipt: your receipt only')
    expect(screen.queryByRole('button', { name: 'Save bundle' })).not.toBeInTheDocument()
  })

  it('says it cannot check where SHA-256 is unavailable (an insecure origin), with no verdict', async () => {
    vi.stubGlobal('crypto', undefined)
    expect((await checkReceiptBundle(JSON.stringify(producerSelected))).kind).toBe('cannot_check')
  })

  it('reads anything the runtime throws on as did-not-verify', async () => {
    expect((await checkReceiptBundle('null')).kind).toBe('did_not_verify')
  })
})

describe('the receipt check (capsule-viewer\'s receipt export, #376)', () => {
  it('checks a payer\'s deal receipt with the viewer\'s unilateral receipt module', async () => {
    const view = await checkReceiptBundle(JSON.stringify(meshPayerDeal))
    expect(view).toMatchObject({
      kind: 'checked',
      case: 'one_sided',
      module: 'capsuleviewer.receipt.unilateral/v0',
      records: { total: 4, tied: 4 }
    })
  })

  it('checks a provider\'s own receipt with the viewer\'s provider module (capsule-viewer#390)', async () => {
    const view = await checkReceiptBundle(JSON.stringify(meshProviderSelected))
    expect(view).toMatchObject({
      kind: 'checked',
      case: 'one_sided',
      module: 'capsuleviewer.receipt.provider/v0',
      records: { total: 3 }
    })
  })

  it('places a verified bundle no receipt module draws as not drawn, keeping its bytes', async () => {
    const bundleText = JSON.stringify(producerSelected)
    expect(await checkReceiptBundle(bundleText)).toEqual({ kind: 'not_drawn', bundleText })
  })

  it('shows the payer\'s deal receipt on the row in the viewer\'s words', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(meshPayerDeal) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('Receipt: your receipt only')).toBeInTheDocument()
    expect(screen.getByText(/4 of 4 records in the receipt are tied to a signed checkpoint\./)).toBeInTheDocument()
  })
})

describe('receiptRequest', () => {
  it('names the payer route by the exchange record and the provider route by the host exchange id', () => {
    expect(receiptRequest(payerRow)).toEqual({ side: 'payer', capsuleId: EXCHANGE_RECORD })
    expect(receiptRequest(providerRow)).toEqual({ side: 'provider', exchangeId: 'ex-1' })
    expect(receiptPath({ side: 'provider', exchangeId: 'a b' })).toBe('http/provider-receipt-bundle?exchange_id=a%20b')
  })
})
