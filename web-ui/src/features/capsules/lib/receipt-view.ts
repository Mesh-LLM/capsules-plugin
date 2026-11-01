// The receipt on an Exchanges row: which of three cases a node's receipt
// bundle is, read from what the agent-action-capsule runtime verified in this
// browser. Nothing here is computed from the bundle beyond the runtime's own
// results: no score, no amounts. Wording is the set Sherlock2 reviewed on
// Mesh-LLM/capsules-plugin#96.
//
// Producer-selected bundles (these receipts) read INCOMPLETE by design: the
// log is not shown whole. The runtime renders them when the browser has
// WebCrypto Ed25519 and refuses them, on purpose, when it does not; that
// refusal is surfaced as "can't check here", never as a verdict.
import {
  Sha256UnavailableError,
  bundleVerified,
  buildVerifiedBundleContext,
  verificationBanner,
  VERIFICATION_BANNER_LINES,
  type ComposedResult,
  type VerifiedBundleContext
} from '@aac-browser'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { ReceiptFetch, ReceiptRequest } from '@/features/capsules/api/receiptClient'

export const RECEIPT_BOTH = 'stamped by both'
export const RECEIPT_ONE_SIDED = 'your receipt only'
export const RECEIPT_NONE = 'no record'
export const RECEIPT_CANNOT_CHECK = "this browser can't check the receipt"
export const RECEIPT_CANNOT_CHECK_POINTER =
  'Open the bundle in the offline viewer (capsule-viewer) to check it; this page shows no verdict for it.'
export const RECEIPT_NOT_YET = 'no receipt yet:'
/** The route's refusals that mean there is no record at all
 *  (`deal_receipt::Refusal::NoDeal`, `provider_receipt::Refusal::NoExchange`).
 *  The route sends no code, only these words; every other refusal is a state
 *  that can change (a report or checkpoint still to come, a payment not noted). */
export const NO_RECORD_REASONS: readonly string[] = [
  'this node holds no deal for that exchange',
  'this node holds no single served record for that exchange'
]
export const RECEIPT_DID_NOT_VERIFY = 'the receipt did not verify: do not rely on it'

/** The bundle, checked in this browser. `case` is only ever one of the two a
 *  verified bundle can be; "no record" is the route's refusal. */
export type CheckedReceipt = {
  kind: 'checked'
  case: 'both' | 'one_sided'
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
  /** The route failed: not a statement about the exchange or the bundle. */
  | { kind: 'error'; message: string }

/** A composed/v1 block that failed, or a carried copy whose own completeness
 *  claims failed. The runtime's page gate does not read either (the composed
 *  status and each member's claims are reported apart), so this page does. */
export function composedFailed(context: VerifiedBundleContext): boolean {
  return context.extensions.some((extension) => {
    const composed = extension.composed
    if (!composed) return false
    if (composed.malformed || composed.status === 'fail') return true
    return composed.members.some(
      (m) =>
        m.bundle !== undefined &&
        [m.bundle.graphClosure, m.bundle.intervalCoverage, m.bundle.perRecordMembership].some(
          (c) => c.status === 'fail'
        )
    )
  })
}

/** `both` only when the bundle carries a composed/v1 block the runtime
 *  verified in full: two artifact copies, every join derived to `agree` as
 *  declared, and every copy pair corroborating on declared custody. Every
 *  other verified bundle is the holder's own copy. A node cannot seal two
 *  halves yet (no `ec:deal-reconcile@1`), so this is unreachable from the
 *  plugin's routes today. */
export function receiptCase(context: VerifiedBundleContext): 'both' | 'one_sided' {
  if (composedFailed(context)) return 'one_sided'
  const composed = context.extensions
    .map((extension) => extension.composed)
    .find((result): result is Extract<ComposedResult, { malformed: false }> => result?.malformed === false)
  if (!composed || composed.status !== 'pass') return 'one_sided'
  const artifacts = composed.members.filter((member) => member.outcome === 'artifact')
  const joined =
    composed.joins.length > 0 && composed.joins.every((j) => j.derived === 'agree' && j.result === 'derived_matches')
  const corroborated =
    composed.corroboration.length > 0 && composed.corroboration.every((c) => c.result === 'corroborating')
  return artifacts.length === 2 && joined && corroborated ? 'both' : 'one_sided'
}

/** Check the bundle in `bundleText` (its JSON text, as served) with the
 *  runtime and place it in a case. The saved receipt page runs this same
 *  function on its embedded bytes (`receipt-page-verify.ts`). */
export async function checkReceiptBundle(bundleText: string): Promise<ReceiptView> {
  try {
    return await checkReceiptBundleUnguarded(bundleText)
  } catch {
    // Anything the runtime throws while reading the bundle, or text that is
    // not JSON, is a bundle it could not read.
    return { kind: 'did_not_verify', line: VERIFICATION_BANNER_LINES.refused, bundleText }
  }
}

async function checkReceiptBundleUnguarded(bundleText: string): Promise<ReceiptView> {
  const bundle: unknown = JSON.parse(bundleText)
  let context: VerifiedBundleContext
  try {
    context = await buildVerifiedBundleContext(bundle)
  } catch (error) {
    if (error instanceof Sha256UnavailableError) return { kind: 'cannot_check', bundleText }
    // The runtime could not read the bundle: it did not verify, which is not
    // a route failure.
    return { kind: 'did_not_verify', line: VERIFICATION_BANNER_LINES.refused, bundleText }
  }
  // No strict result: this browser has no Ed25519, so the runtime refuses a
  // producer-selected bundle (verification-page.ts bundleVerified).
  if (context.strict === undefined) return { kind: 'cannot_check', bundleText }
  const banner = verificationBanner(context, [])
  if (!bundleVerified(context.verification) || banner.state === 'failed' || composedFailed(context)) {
    return {
      kind: 'did_not_verify',
      line: banner.state === 'failed' ? banner.line : VERIFICATION_BANNER_LINES.refused,
      bundleText
    }
  }
  const records = (bundle as { records?: unknown }).records
  const total = Array.isArray(records) ? records.length : 0
  return {
    kind: 'checked',
    case: receiptCase(context),
    runtimeLine: banner.line,
    records: { total, tied: Math.max(0, total - banner.uncheckpointed) }
  }
}

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
 *  row's own record. Provider: a SERVED row with a provider book covering
 *  exactly one exchange id. */
export function receiptRequest(row: PaneCRow): ReceiptRequest | null {
  if (row.role_tag === 'ASKED' && row.settlement && row.settlement.state !== 'terms_only' && row.mine.capsule_id) {
    return { side: 'payer', capsuleId: row.mine.capsule_id }
  }
  // Terms accepted with no invoice is not a paid exchange: it has no deal.
  const book = row.provider_settlement
  const ids = book?.state === 'terms_only' ? undefined : book?.exchange_ids
  if (row.role_tag === 'SERVED' && ids?.length === 1 && ids[0]) return { side: 'provider', exchangeId: ids[0] }
  return null
}

/** The case's label for a view, or null where the view is not one of the
 *  three cases. */
export function receiptLabel(view: ReceiptView): string | null {
  if (view.kind === 'no_record') return RECEIPT_NONE
  if (view.kind !== 'checked') return null
  return view.case === 'both' ? RECEIPT_BOTH : RECEIPT_ONE_SIDED
}
