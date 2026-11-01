// What the saved receipt page shows about its own embedded bundle when it
// opens (Mesh-LLM/capsules-plugin#96). `saved-pages.ts` inlines this file, so
// the page runs the Exchanges row's own check (`receipt-view.ts`) and says
// what the row says, offline, in the reader's browser.
import {
  RECEIPT_CANNOT_CHECK,
  RECEIPT_CANNOT_CHECK_POINTER,
  RECEIPT_DID_NOT_VERIFY,
  checkReceiptBundle,
  receiptLabel
} from '@/features/capsules/lib/receipt-view'

export type ReceiptPageLines = {
  /** The page's style for the first line: `ok` only for a receipt stamped by
   *  both, `warn` for one side's own receipt, `bad` for one not checked. */
  tone: 'ok' | 'warn' | 'bad'
  lines: string[]
}

export async function receiptPageLines(bundleText: string): Promise<ReceiptPageLines> {
  const view = await checkReceiptBundle(bundleText)
  if (view.kind === 'checked') {
    return {
      tone: view.case === 'both' ? 'ok' : 'warn',
      lines: [
        `Receipt: ${receiptLabel(view)}`,
        `${view.records.tied} of ${view.records.total} records in the receipt are tied to a signed checkpoint.`,
        view.runtimeLine
      ]
    }
  }
  if (view.kind === 'cannot_check') {
    return { tone: 'bad', lines: [`${RECEIPT_CANNOT_CHECK}. ${RECEIPT_CANNOT_CHECK_POINTER}`] }
  }
  // checkReceiptBundle gives no other kind; anything else is not a receipt.
  return { tone: 'bad', lines: [`${RECEIPT_DID_NOT_VERIFY}.`, ...(view.kind === 'did_not_verify' ? [view.line] : [])] }
}
