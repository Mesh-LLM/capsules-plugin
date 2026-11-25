// What a saved receipt page runs (Mesh-LLM/capsules-plugin#96, #376), bundled
// as one IIFE into every saved receipt page (`saved-pages.ts`). It checks the
// page's own embedded bundle, offline, in the reader's browser, and draws it
// with capsule-viewer's receipt export: the viewer's lines (the row's case,
// the records tied, the runtime's line) and then the receipt itself, top line
// first. Every word is the viewer's. The page is the node's own record saved
// for anyone to check, so both calls take carrier "page": the viewer's banner
// says so and drops the owner's words (capsule-viewer#395, #396).
import { receiptPageLines, renderReceipt } from '@action-state-group/capsule-viewer/receipt'

const PAGE = { carrier: 'page' } as const
import { checkUnmoduledBundle, receiptLines } from '@/features/capsules/lib/receipt-view'

export type ReceiptPageLines = {
  /** The page's style for the first line: `ok` only for a receipt stamped by
   *  both, `warn` for one side's own receipt, `bad` for one not checked. */
  tone: 'ok' | 'warn' | 'bad'
  lines: string[]
}

/** Check `bundleText` and draw the receipt into `host` (emptied unless the
 *  receipt checked and a receipt module draws it), once; give the lines the
 *  page shows above it. A bundle no receipt module draws (the provider's
 *  served half, until capsule-viewer#390) gets the row's own check and no
 *  drawing. */
export async function receiptPage(bundleText: string, host: HTMLElement): Promise<ReceiptPageLines> {
  // The viewer reads an unreadable bundle as did_not_verify itself; anything
  // it throws comes after the bundle verified (drawing it), so it is no
  // verdict: the page's script says it could not check its receipt.
  const result = await renderReceipt(bundleText, host, PAGE)
  if (result.kind === 'no_module') {
    host.replaceChildren()
    const lines = receiptLines(await checkUnmoduledBundle(bundleText), PAGE)
    // checkUnmoduledBundle gives only views receiptLines answers.
    return lines ?? { tone: 'bad', lines: [] }
  }
  // Every result but no_module has lines.
  return receiptPageLines(result, PAGE) ?? { tone: 'bad', lines: [] }
}
