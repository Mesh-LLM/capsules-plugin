// Tier 2: the History page built from what live nodes' `history-page` route
// served (Mesh-LLM/capsules-plugin#122). `scripts/e2e-two-node.sh` saves each
// route body while the two nodes run and then runs this file with
// E2E_HISTORY_PAGES naming the directory it saved them in:
//
//   history-page-fresh.json      the requester before its first checkpoint
//   history-page-requester.json  the requester once it has checkpoints
//   history-page-provider.json   the provider, sharing its Service History,
//                                once it has a checkpoint on a period boundary
//
// Each body is taken as the Evidence page takes it (`servedHistoryFrom`, the
// step `fetchServedHistory` runs on the route's body, which refuses a card
// signed under another key), built into the page with `historyPage`, and the
// page is opened offline.
// Skipped without E2E_HISTORY_PAGES, like the Rust tier 2 checks without
// their data directories.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { servedHistoryFrom } from '@/features/capsules/api/client'
import { historyPage } from '@/features/capsules/lib/saved-pages'
import { embeddedBundle, openSavedPage, savedBytes } from '@/lib/test/open-saved-page'

const dir = process.env.E2E_HISTORY_PAGES
const SAVED = '2026-10-31T00:00:00Z'

type Served = { form: string; outcome: string; reply: string; node_key_id: string }

const served = (name: string): Served => JSON.parse(readFileSync(path.join(dir!, `history-page-${name}.json`), 'utf8')) as Served

// The page a person saves from this route body, and what they see opening it.
async function saveAndOpen(body: Served) {
  const taken = servedHistoryFrom(body)
  expect(taken.replyText).toBe(body.reply)
  const { html } = historyPage(taken.replyText, SAVED, taken.form)
  // The page carries the served bytes as they are.
  expect(Buffer.from(embeddedBundle(html)).equals(Buffer.from(body.reply, 'utf8'))).toBe(true)
  const opened = await openSavedPage(html)
  expect(opened.requested).toEqual([])
  // And hands them back unchanged.
  expect((await savedBytes(opened.dom)).equals(Buffer.from(body.reply, 'utf8'))).toBe(true)
  return { ...opened, form: taken.form }
}

describe.skipIf(!dir)('the History page from a live node’s history-page reply, opened offline', () => {
  it('verifies a history card under the node’s own key', async () => {
    const body = served('requester')
    expect(body).toMatchObject({ form: 'history_card/1', outcome: 'answered' })
    const { text, form } = await saveAndOpen(body)
    expect(form).toBe('history_card')
    expect(text).toContain(
      `Checked against the node’s own key when this page opened: the history card matches its digest, and every checkpoint is signed by key ${body.node_key_id}`
    )
    expect(text).toMatch(/Checked: All \d+ checkpoints verify/)
    expect(text).not.toContain('Failed: ')
  })

  it('verifies the card inside a Service History under the node’s own key', async () => {
    const body = served('provider')
    expect(body).toMatchObject({ form: 'service_history/1', outcome: 'answered' })
    const { text, form } = await saveAndOpen(body)
    expect(form).toBe('service_history')
    expect(text).toContain('Service History')
    expect(text).toContain(
      `the history card inside the Service History matches its digest, and every checkpoint is signed by key ${body.node_key_id}`
    )
    expect(text).toContain('Checked: The history card inside matches its digest.')
    expect(text).not.toContain('Failed: ')
  })

  it('shows a node with no checkpoint as declining, and nothing it could not check', async () => {
    const body = served('fresh')
    expect(body).toMatchObject({ form: 'history_card/1', outcome: 'refused' })
    const { text, form } = await saveAndOpen(body)
    expect(form).toBe('history_card')
    expect(text).toContain('The node declined to answer')
    expect(text).not.toContain('matches its digest')
    expect(text).not.toContain('could not check its answer')
  })
})
