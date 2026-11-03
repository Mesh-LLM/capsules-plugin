// The owner's receipt bundles for one paid exchange (Mesh-LLM/capsules-plugin
// #96, #134). The plugin serves them as Evidence Bundles and draws nothing;
// this page fetches one and checks it in the browser (`lib/receipt-view.ts`).
//
//   http/deal-receipt-bundle?capsule_id=<64 hex>   the payer's receipt; the id
//       is the EXCHANGE RECORD's capsule id (`deal_receipt::ReceiptArgs`), not
//       the host's exchange id.
//   http/provider-receipt-bundle?exchange_id=<id>  the provider's receipt; the
//       id is the host's exchange id (`provider_receipt::ProviderReceiptArgs`).
//
// Both answer `{"state": "bundle", "bundle": "<the bundle's JSON text>"}` or
// `{"state": "refused", "why": ...}`. The bundle comes as text so the receipt
// page can embed the exact bytes the node served. A refusal is the node's own state (no sealed deal, no
// checkpoint yet), so it is carried as data, never thrown. Fetching can make
// the node sign a new checkpoint, so the caller fetches on a click, not on
// render.
import { getPluginJson } from '@/plugin-host/host'

export const PAYER_RECEIPT_ROUTE = 'http/deal-receipt-bundle'
export const PROVIDER_RECEIPT_ROUTE = 'http/provider-receipt-bundle'

/** Which receipt, and the id its route names the exchange by. */
export type ReceiptRequest = { side: 'payer'; capsuleId: string } | { side: 'provider'; exchangeId: string }

export type ReceiptFetch =
  /** `bundleText` is the bundle as the node served it, unchanged. */
  | { kind: 'bundle'; bundleText: string }
  | { kind: 'refused'; why: string }
  /** The route failed or answered something this page does not know: not a
   *  statement about the exchange. */
  | { kind: 'unavailable'; message: string }

export function receiptPath(request: ReceiptRequest): string {
  return request.side === 'payer'
    ? `${PAYER_RECEIPT_ROUTE}?capsule_id=${encodeURIComponent(request.capsuleId)}`
    : `${PROVIDER_RECEIPT_ROUTE}?exchange_id=${encodeURIComponent(request.exchangeId)}`
}

export async function fetchReceipt(request: ReceiptRequest): Promise<ReceiptFetch> {
  let answer: unknown
  try {
    answer = await getPluginJson<unknown>(receiptPath(request))
  } catch (error) {
    return {
      kind: 'unavailable',
      message: error instanceof Error ? error.message : String(error)
    }
  }
  const body = answer as {
    state?: unknown
    bundle?: unknown
    why?: unknown
  } | null
  if (body?.state === 'refused')
    return {
      kind: 'refused',
      why: typeof body.why === 'string' ? body.why : ''
    }
  if (body?.state === 'bundle' && typeof body.bundle === 'string') {
    return { kind: 'bundle', bundleText: body.bundle }
  }
  return {
    kind: 'unavailable',
    message: 'the receipt route answered something this page does not know'
  }
}
