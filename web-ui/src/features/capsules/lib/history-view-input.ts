// The saved History page's check result, as the shared History view takes it
// (`history-view/v0`, capsule-viewer docs/design/history-view.md). The view
// draws and never verifies: everything it shows comes from what
// `verifyHistoryReply` established, and a slot it cannot fill stays "not
// checked". Pure data in, data out, so the page script and the tests share it.
import type { HistoryVerdict, WitnessSlot } from '@/features/capsules/lib/history-verify'
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
export const CHECK_ID: Record<string, string> = {
  readable: 'readable',
  refusal: 'refusal',
  artifact_digest: 'artifact_digest',
  card_digest: 'card_digest',
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

// The view's limits on node-supplied text (it refuses longer input).
const clamp = (text: string, max: number): string => (text.length > max ? text.slice(0, max) : text)

// A count under the floor is the view's `withheld`. A count withheld only so
// that another cannot be worked out (`complementary`) may itself be 5 or more,
// so it is not drawn as "fewer than" anything.
function cell(what: string, value: string) {
  if (value.startsWith('withheld (below')) return { what: clamp(what, 200), withheld: true as const }
  return { what: clamp(what, 200), value: clamp(value.startsWith('withheld') ? 'withheld' : value, 40) }
}

const NOT_CHECKED = { state: 'not_checked' } as const

// The witness check's `values`, for the one case the list can name: the reader's witness list time-stamped every
// checkpoint but one, and the answer holds no registered receipt for that one (none or stubs only), wherever it
// sits. Any other reason a slot reads "not checked" (no list, a receipt without a time, an algorithm this browser
// cannot check) is not "not registered", and two or more open checkpoints are not named, so the line stays bare.
// `at` is the checkpoint's own signed cut time, which the view requires to equal the row's.
// The row's slot, without the verifier's own `unregistered` note: the view takes only a state and what a pass says.
function slotOf(slot: WitnessSlot | undefined) {
  if (!slot) return NOT_CHECKED
  return slot.state === 'not_checked' ? NOT_CHECKED : slot
}

function unregisteredOne(verdict: HistoryVerdict): { n: number; at: string } | undefined {
  const cps = verdict.checkpoints
  if (cps.length < 2) return undefined
  const open = cps.flatMap((c, i) => (c.witness?.state === 'passed' ? [] : [i]))
  const [i] = open
  const slot = i === undefined ? undefined : cps[i]?.witness
  if (open.length !== 1 || slot?.state !== 'not_checked' || slot.unregistered !== true) return undefined
  return { n: i! + 1, at: cps[i!]!.time }
}

export function historyViewInput(verdict: HistoryVerdict, context: HistoryPageContext) {
  // A witness check that fails is drawn in its slots, never as a reason to hide the rows.
  const onlyWitnessFailed = verdict.kind === 'answered' && !verdict.checks.some((c) => c.status === 'fail' && c.id !== 'witness_receipts')
  const drawn = verdict.verified || onlyWitnessFailed
  const checks: { id: string; status: CheckStatus; values?: { n: number; at: string } }[] = []
  for (const check of verdict.checks) {
    const id = CHECK_ID[check.id]
    // A check the view has no words for would be refused; the verifier's own
    // ids are all mapped (see the test), so this only guards a future id.
    if (!id) continue
    // A later failure of a check that passed before (a Service History's card
    // shape after its digest) wins.
    const seen = checks.find((c) => c.id === id)
    const values = id === 'witness' && check.status === 'not_run' && drawn ? unregisteredOne(verdict) : undefined
    if (!seen) checks.push(values ? { id, status: check.status, values } : { id, status: check.status })
    else if (check.status === 'fail') seen.status = 'fail'
  }
  // The chain check covers the consistency proofs it runs.
  if (drawn && !checks.some((c) => c.id === 'consistency')) checks.push({ id: 'consistency', status: 'pass' })
  const rows = drawn
    ? verdict.checkpoints.map((c) => ({
        kind: 'checkpoint' as const,
        cut_at: c.time,
        log_size: c.size,
        anchor: c.anchor,
        signature: 'pass' as const,
        witness: slotOf(c.witness),
        second_signature: NOT_CHECKED
      }))
    : []
  const periods = drawn
    ? verdict.counts?.map((p) => ({
        from: p.from,
        to: p.to,
        cells: p.cells.map((c) => cell(c.what, c.value))
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
          ? { kind: 'refused' as const, reason: clamp(verdict.reason || 'unknown', 200) }
          : { kind: 'unreadable' as const },
    rows,
    checks,
    ...(periods && periods.length ? { periods } : {}),
    sharing: context.sharing
  }
}
