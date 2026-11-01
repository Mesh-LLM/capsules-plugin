// "Save receipt page" on a row: what it asks the node, and the page it saves.
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { SaveReceiptPage } from '@/features/capsules/components/SaveReceiptPage'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { NO_PAID_DEAL_WHY } from '@/features/capsules/lib/saved-pages'
import producerSelected from '@/features/capsules/lib/receipt-fixtures/producer-selected.bundle.json'
import { embeddedBundle } from '@/lib/test/open-saved-page'

const payerRow = {
  role_tag: 'ASKED',
  mine: { state: 'ok', capsule_id: 'ab'.repeat(32) },
  settlement: { observed_by: 'payer', state: 'settled', terms_digests: [], entries: [] }
} as unknown as PaneCRow
const freeRow = { role_tag: 'ASKED', mine: { state: 'ok', capsule_id: 'ab'.repeat(32) } } as unknown as PaneCRow

function routeAnswers(body: unknown, ok = true, status = 200) {
  const fetchSpy = vi.fn(async (_url: string) => ({ ok, status, json: async () => body }) as unknown as Response)
  vi.stubGlobal('fetch', fetchSpy)
  return fetchSpy
}

/** Captures what the page hands the browser to save. */
function capture() {
  const saved: { name: string; blob: Blob }[] = []
  let current: Blob | undefined
  vi.stubGlobal(
    'URL',
    Object.assign(function () {}, {
      createObjectURL: (blob: Blob) => ((current = blob), 'blob:x'),
      revokeObjectURL: () => {}
    })
  )
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    saved.push({ name: this.download, blob: current! })
  })
  return saved
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('SaveReceiptPage', () => {
  it('saves a page that embeds the bundle text the node served, unchanged', async () => {
    const served = JSON.stringify(producerSelected)
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: served })
    const saved = capture()
    render(<SaveReceiptPage exchangeKey="ex-1" row={payerRow} />)
    await userEvent.click(screen.getByRole('button', { name: 'Save receipt page' }))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(String(fetchSpy.mock.calls[0][0])).toContain('http/deal-receipt-bundle?capsule_id=')
    expect(saved[0].name).toMatch(/^mesh-receipt-ex-1-\d{8}T\d{6}\.html$/)
    const html = await saved[0].blob.text()
    expect(Buffer.from(embeddedBundle(html)).toString('utf8')).toBe(served)
  })

  it('saves the "no record" page for a row with no paid deal, asking the node nothing', async () => {
    const fetchSpy = routeAnswers({})
    const saved = capture()
    render(<SaveReceiptPage exchangeKey="ex-2" row={freeRow} />)
    await userEvent.click(screen.getByRole('button', { name: 'Save receipt page' }))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(fetchSpy).not.toHaveBeenCalled()
    const note = JSON.parse(Buffer.from(embeddedBundle(await saved[0].blob.text())).toString('utf8'))
    expect(note).toEqual({ source: 'dashboard', case: 'no_record', why: NO_PAID_DEAL_WHY })
  })

  it('carries the node\'s refusal word for word, as "no record" or "no receipt yet"', async () => {
    for (const [why, kind] of [
      ['this node holds no deal for that exchange', 'no_record'],
      ['the deal has no report yet', 'no_receipt_yet']
    ]) {
      routeAnswers({ state: 'refused', why })
      const saved = capture()
      render(<SaveReceiptPage exchangeKey="ex-3" row={payerRow} />)
      await userEvent.click(screen.getByRole('button', { name: 'Save receipt page' }))
      await waitFor(() => expect(saved).toHaveLength(1))
      const note = JSON.parse(Buffer.from(embeddedBundle(await saved[0].blob.text())).toString('utf8'))
      expect(note).toEqual({ source: 'dashboard', case: kind, why })
      cleanup()
      vi.unstubAllGlobals()
      vi.restoreAllMocks()
    }
  })

  it('saves nothing when the route fails, and says so', async () => {
    routeAnswers({}, false, 500)
    const saved = capture()
    render(<SaveReceiptPage exchangeKey="ex-4" row={payerRow} />)
    await userEvent.click(screen.getByRole('button', { name: 'Save receipt page' }))
    expect(await screen.findByRole('status')).toHaveTextContent(/^Could not save the page: /)
    expect(saved).toHaveLength(0)
  })
})
