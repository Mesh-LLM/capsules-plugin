// The receipt on an Exchanges row: which of three cases a node's receipt
// bundle is, read from what the agent-action-capsule runtime verified in this
// browser. Nothing here is computed from the bundle beyond the runtime's own
// results: no score, no amounts.
//
// Every receipt is checked and drawn by capsule-viewer's receipt export: the
// payer's deal receipt (capsule-viewer #383, Mesh-LLM/capsules-plugin#376) and
// the provider's own receipt for an exchange it served or was paid for (capsule-viewer#390, #465,
// Mesh-LLM/capsules-plugin#398). Every receipt word on the row is the viewer's
// own (its pack, which Sherlock2 passed on capsule-viewer#387 and #459), except
// the lines for a verified bundle no viewer module draws (`not_drawn`), which
// are Sherlock2's words on #398.
//
// Producer-selected bundles (these receipts) read INCOMPLETE by design: the
// log is not shown whole. The runtime renders them when the browser has
// WebCrypto Ed25519 and refuses them, on purpose, when it does not; that
// refusal is surfaced as "can't check here", never as a verdict.
import {
  checkReceipt,
  receiptLabel as viewerReceiptLabel,
  receiptPageLines,
  type ReceiptResult
} from '@action-state-group/capsule-viewer/receipt'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { ReceiptFetch, ReceiptRequest } from '@/features/capsules/api/receiptClient'

/** The row's lead-in for a refusal that can change; the route's own reason follows. */
export const RECEIPT_NOT_YET = 'no receipt yet:'
/** The route's refusals that mean there is no record at all
 *  (`deal_receipt::Refusal::NoDeal`, `provider_receipt::Refusal::NoExchange`).
 *  The route sends no code, only these words; every other refusal is a state
 *  that can change (a report or checkpoint still to come, a payment not noted). */
export const NO_RECORD_REASONS: readonly string[] = [
  'this node holds no deal for that exchange',
  'this node holds no single served record for that exchange'
]

/** The bundle, checked in this browser. `case` is only ever one of the two a
 *  verified bundle can be; "no record" is the route's refusal. */
export type CheckedReceipt = {
  kind: 'checked'
  case: 'both' | 'one_sided'
  /** The viewer's receipt module that draws it. */
  module: string
  /** The runtime's own banner line for the state it reached. */
  runtimeLine: string
  /** Records in the bundle, and how many of them are tied to a log position. */
  records: { total: number; tied: number }
}

export type ReceiptView =
  | CheckedReceipt
  /** The route's refusal that means this node holds no deal / served record. */
  | { kind: 'no_record'; why: string }
  /** Any other refusal (no report yet, no checkpoint yet, ...): the route's
   *  own reason, word for word. */
  | { kind: 'no_receipt_yet'; why: string }
  /** `bundleText` is kept so the owner can save it and check it elsewhere. */
  | { kind: 'cannot_check'; bundleText: string }
  | { kind: 'did_not_verify'; line: string; bundleText: string }
  /** The bundle verified, but no viewer receipt module draws it. Not a
   *  verdict and not an error; `bundleText` is kept so the owner can save it. */
  | { kind: 'not_drawn'; bundleText: string }
  /** The route failed: not a statement about the exchange or the bundle. */
  | { kind: 'error'; message: string }

/** Check the bundle in `bundleText` (its JSON text, as served) with the
 *  viewer's receipt check and place it in a case. */
export async function checkReceiptBundle(bundleText: string): Promise<ReceiptView> {
  let result: ReceiptResult
  try {
    result = await checkReceipt(bundleText)
  } catch (error) {
    // The viewer reads an unreadable bundle as did_not_verify itself;
    // anything it throws comes after the bundle verified, so it is no
    // verdict on the bundle: the row says the receipt could not be loaded.
    return { kind: 'error', message: error instanceof Error ? error.message : String(error) }
  }
  return viewOfResult(result, bundleText)
}

/** The row's view of the viewer's result. */
export function viewOfResult(result: ReceiptResult, bundleText: string): ReceiptView {
  switch (result.kind) {
    case 'checked':
      return {
        kind: 'checked',
        case: result.both ? 'both' : 'one_sided',
        module: result.module,
        runtimeLine: result.runtimeLine,
        records: { total: result.records.total, tied: result.records.tied }
      }
    case 'cannot_check':
      return { kind: 'cannot_check', bundleText }
    case 'did_not_verify':
      return { kind: 'did_not_verify', line: result.line, bundleText }
    case 'no_module':
      return { kind: 'not_drawn', bundleText }
  }
}

/** The lines for a bundle that verified but no viewer module draws
 *  (Sherlock2 on #398), the same on the row and on a saved page. The
 *  viewer's provider module draws a served, failed or no-response exchange
 *  (capsule-viewer#465), so this is the fallback for anything else. */
export const NOT_DRAWN_LINES: readonly string[] = [
  'No receipt is drawn for this exchange here.',
  'This page checked the bundle: it is unchanged. Save bundle keeps it, with any payment record it holds.'
]

/** A route's refusal, by its words: "no record", or a state that can change. */
export function refusalView(why: string): { kind: 'no_record' | 'no_receipt_yet'; why: string } {
  return { kind: NO_RECORD_REASONS.includes(why) ? 'no_record' : 'no_receipt_yet', why }
}

/** Fetch result to the view; a route refusal is "no record", a route failure
 *  is an error line, neither is a verdict on the bundle. */
export async function receiptView(fetched: ReceiptFetch): Promise<ReceiptView> {
  if (fetched.kind === 'refused') return refusalView(fetched.why)
  if (fetched.kind === 'unavailable') return { kind: 'error', message: fetched.message }
  return checkReceiptBundle(fetched.bundleText)
}

/** Which receipt route a row can ask, or null when it is not a paid exchange
 *  this node can name. Payer: an ASKED row with a payer book, named by the
 *  row's own record. Provider: a SERVED or FAILED row with a provider book
 *  covering exactly one exchange id (a provider paid for an exchange that
 *  failed holds its half too: u1578 E and F, #399). */
export function receiptRequest(row: PaneCRow): ReceiptRequest | null {
  if (row.role_tag === 'ASKED' && row.settlement && row.settlement.state !== 'terms_only' && row.mine.capsule_id) {
    return { side: 'payer', capsuleId: row.mine.capsule_id }
  }
  // Terms accepted with no invoice is not a paid exchange: it has no deal.
  const book = row.provider_settlement
  const ids = book?.state === 'terms_only' ? undefined : book?.exchange_ids
  const ownHalf = row.role_tag === 'SERVED' || row.role_tag === 'FAILED'
  if (ownHalf && ids?.length === 1 && ids[0]) return { side: 'provider', exchangeId: ids[0] }
  return null
}

/** The viewer's result for a checked view, cannot-check or did-not-verify
 *  view, so the row's words are the viewer's own. */
function resultOf(view: ReceiptView): ReceiptResult | null {
  if (view.kind === 'checked') {
    return {
      kind: 'checked',
      module: view.module,
      both: view.case === 'both',
      runtimeLine: view.runtimeLine,
      records: view.records
    }
  }
  if (view.kind === 'cannot_check') return { kind: 'cannot_check' }
  if (view.kind === 'did_not_verify') return { kind: 'did_not_verify', line: view.line }
  return null
}

/** The case's label for a view (the viewer's words), or null where the view
 *  is not one of the three cases. */
export function receiptLabel(view: ReceiptView): string | null {
  if (view.kind === 'no_record') return viewerReceiptLabel({ kind: 'no_record' })
  if (view.kind !== 'checked') return null
  return viewerReceiptLabel(resultOf(view)!)
}

/** The viewer's lines for a checked, cannot-check or did-not-verify view, and
 *  their tone; the not-drawn lines, in the neutral `muted` tone, for a
 *  not-drawn view; null for any other
 *  view. For a checked view the first line is
 *  "Receipt: <label>", the second the records tied, the third the runtime's.
 *  The Exchanges row passes no carrier (the owner's words); a saved page
 *  passes `carrier: 'page'`, so one side's own receipt reads "this node's
 *  receipt only" (capsule-viewer#395). */
export function receiptLines(
  view: ReceiptView,
  options?: { readonly carrier?: 'page' }
): { tone: 'ok' | 'warn' | 'bad' | 'muted'; lines: string[] } | null {
  // Neutral, not a case's tone: the bundle verified (Sherlock2 on #398).
  if (view.kind === 'not_drawn') return { tone: 'muted', lines: [...NOT_DRAWN_LINES] }
  const result = resultOf(view)
  return result ? receiptPageLines(result, options) : null
}
