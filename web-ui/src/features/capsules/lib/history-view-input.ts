// The saved History page's check result, as the shared History view takes it
// (`history-view/v0`, capsule-viewer docs/design/history-view.md). The view
// draws and never verifies: everything it shows comes from what
// `verifyHistoryReply` established, and a slot it cannot fill stays "not
// checked". Pure data in, data out, so the page script and the tests share it.
import type { HistoryVerdict } from '@/features/capsules/lib/history-verify'
import type { HistorySharing } from '@/features/capsules/api/client'

export type HistoryPageContext = {
  /** The key the node signed its answer with (the route's `node_key_id`). */
  nodeKeyId: string
  /** When the page was saved, RFC 3339: the sharing settings are read then. */
  savedAt: string
  sharing: HistorySharing
  /** The tool that built the page, named in the view's "How this was checked". */
  builtBy: string
}

type CheckStatus = 'pass' | 'fail' | 'not_run'

// The verifier's check ids, under the view's closed list.
const CHECK_ID: Record<string, string> = {
  readable: 'readable',
  refusal: 'refusal',
  artifact_digest: 'artifact_digest',
  card_digest: 'card_digest',
  card: 'card_digest',
  checkpoints: 'checkpoint_signatures',
  chain: 'checkpoint_chain',
  consistency: 'consistency',
  anchor: 'anchor',
  period_counts: 'period_counts',
  envelope_signature: 'envelope_signature',
  key_is_nodes: 'key_is_node',
  request_binding: 'reply_bound',
  witness_receipts: 'witness'
}

const NOT_CHECKED = { state: 'not_checked' } as const

export function historyViewInput(verdict: HistoryVerdict, context: HistoryPageContext) {
  const checks: { id: string; status: CheckStatus }[] = []
  for (const check of verdict.checks) {
    const id = CHECK_ID[check.id]
    // A check the view has no words for would be refused; the verifier's own
    // ids are all mapped (see the test), so this only guards a future id.
    if (!id) continue
    // The verifier's `card` failure is a card_digest failure after that
    // check passed: the failure wins.
    const seen = checks.find((c) => c.id === id)
    if (!seen) checks.push({ id, status: check.status })
    else if (check.status === 'fail') seen.status = 'fail'
  }
  // The chain check covers the consistency proofs it runs.
  if (verdict.verified && !checks.some((c) => c.id === 'consistency')) checks.push({ id: 'consistency', status: 'pass' })
  const rows = verdict.verified
    ? verdict.checkpoints.map((c) => ({
        kind: 'checkpoint' as const,
        cut_at: c.time,
        log_size: c.size,
        anchor: c.anchor,
        signature: 'pass' as const,
        witness: NOT_CHECKED,
        second_signature: NOT_CHECKED
      }))
    : []
  const periods = verdict.verified
    ? verdict.counts?.map((p) => ({
        from: p.from,
        to: p.to,
        cells: p.cells.map((c) => (c.value.startsWith('withheld') ? { what: c.what, withheld: true as const } : { what: c.what, value: c.value }))
      }))
    : undefined
  return {
    view: 'history-view/v0' as const,
    kind: 'checkpoint' as const,
    surface: 'neutral' as const,
    reader: 'recipient' as const,
    holder: { node: verdict.keyId ?? context.nodeKeyId },
    audience: { kind: 'anyone' as const },
    built_at: context.savedAt,
    checked: { where: 'page' as const, by: context.builtBy },
    outcome:
      verdict.kind === 'answered'
        ? { kind: 'answered' as const }
        : verdict.kind === 'refused'
          ? { kind: 'refused' as const, reason: verdict.reason ?? 'unknown' }
          : { kind: 'unreadable' as const },
    rows,
    checks,
    ...(periods && periods.length ? { periods } : {}),
    sharing: context.sharing
  }
}
