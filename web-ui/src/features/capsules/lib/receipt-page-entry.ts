// What a saved receipt page runs (Mesh-LLM/capsules-plugin#96, #376), bundled
// as one IIFE into every saved receipt page (`saved-pages.ts`). It checks the
// page's own embedded bundle, offline, in the reader's browser, and draws it
// with capsule-viewer's receipt export: the viewer's lines (the row's case,
// the records tied, the runtime's line) and then the receipt itself, top line
// first. Every word is the viewer's.
import { VERIFICATION_BANNER_LINES } from '@aac-browser'
import { receiptPageLines, renderReceipt, type ReceiptResult } from '@action-state-group/capsule-viewer/receipt'
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
  let result: ReceiptResult
  try {
    result = await renderReceipt(bundleText, host)
  } catch {
    host.replaceChildren()
    result = { kind: 'did_not_verify', line: VERIFICATION_BANNER_LINES.refused }
  }
  if (result.kind === 'no_module') {
    host.replaceChildren()
    const lines = receiptLines(await checkUnmoduledBundle(bundleText))
    // checkUnmoduledBundle gives only views receiptLines answers.
    return lines ?? { tone: 'bad', lines: [] }
  }
  // Every result but no_module has lines.
  return receiptPageLines(result) ?? { tone: 'bad', lines: [] }
}
