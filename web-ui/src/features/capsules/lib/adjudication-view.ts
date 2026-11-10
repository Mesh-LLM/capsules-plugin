// The words the page uses for a referee's verdict: on the twin bracket, on a
// judged node's row, on the referee's own row, and in the verdict record.
// Pure, so each sentence is unit-testable. A verdict is the referee's signed
// judgment, shown as it was sealed; the page never computes one.
import type {
  DeliveredAdjudication,
  IssuedAdjudication,
  VerdictRecordJson,
  VerdictWire
} from '@/features/capsules/api/sidecarTypes'

export type ParsedVerdict =
  | { kind: 'corroborated' }
  | { kind: 'contradicted'; party: string }
  | { kind: 'inconclusive' }
  | { kind: 'not_comparable' }

/** The rulings a referee seals: `corroborated`, `contradicted:<node>`,
 *  `inconclusive`, `not_comparable` (sampled answers; never a disagreement).
 *  Anything else is not read as a verdict. */
export function parseVerdict(wire: VerdictWire | null | undefined): ParsedVerdict | null {
  if (wire === 'corroborated') return { kind: 'corroborated' }
  if (wire === 'inconclusive') return { kind: 'inconclusive' }
  if (wire === 'not_comparable') return { kind: 'not_comparable' }
  if (typeof wire === 'string' && wire.startsWith('contradicted:') && wire.length > 'contradicted:'.length) {
    return { kind: 'contradicted', party: wire.slice('contradicted:'.length) }
  }
  return null
}

/** Never a full 64-hex id on the page face: the first 10 characters. */
export function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 10)}…` : id
}

/** On a judged node's exchange row. */
export function deliveredVerdictLine(adjudication: DeliveredAdjudication): string | null {
  const verdict = parseVerdict(adjudication.verdict)
  if (verdict === null) return null
  const referee = `A referee (node ${shortId(adjudication.referee_node_id)})`
  if (verdict.kind === 'corroborated') return `${referee} found this answer corroborated.`
  if (verdict.kind === 'inconclusive') return `${referee} couldn’t decide between the two answers.`
  if (verdict.kind === 'not_comparable') return `${referee} found the two answers can’t be compared: they were sampled.`
  return adjudication.about_this_node
    ? `${referee} found your answer contradicted.`
    : `${referee} found the other answer (node ${shortId(verdict.party)}) contradicted.`
}

/** On the referee node's row for the call it answered. */
export function issuedVerdictLine(issued: IssuedAdjudication): string | null {
  const verdict = parseVerdict(issued.verdict)
  if (verdict === null) return null
  const answers = issued.halves.length === 2 ? 'the two answers' : 'the answers'
  switch (verdict.kind) {
    case 'corroborated':
      return `You judged ${answers}: corroborated.`
    case 'contradicted':
      return `You judged ${answers}: node ${shortId(verdict.party)}'s answer contradicted.`
    case 'inconclusive':
      return `You judged ${answers}: inconclusive.`
    case 'not_comparable':
      return `You judged ${answers}: not comparable, because they were sampled.`
  }
}

export type VerdictRecordFacts = {
  verdict: ParsedVerdict | null
  halves: string[]
  refereeCapsuleId: string | null
}

/** The facts the verdict record itself holds, read off its sealed block. */
export function verdictRecordFacts(record: VerdictRecordJson): VerdictRecordFacts {
  const attestation = (record.capsule.model_attestation ?? null) as Record<string, unknown> | null
  const compute = (attestation?.compute_attestation ?? null) as Record<string, unknown> | null
  const block = (compute?.adjudication ?? null) as Record<string, unknown> | null
  const text = (key: string): string | null => (typeof block?.[key] === 'string' ? (block[key] as string) : null)
  const halves = [text('half_a_capsule_id'), text('half_b_capsule_id')].filter((id): id is string => id !== null)
  return {
    verdict: parseVerdict(text('verdict')),
    halves,
    refereeCapsuleId: text('referee_capsule_id')
  }
}

/** The margin rule: the default `split_margin_threshold`, in nats (#282). */
export const SPLIT_MARGIN_RULE = 4.41

/** The threshold a verdict was judged by, in nats, read off its sealed
 *  `split_margin` block; null when the block holds none (the referee was not
 *  asked, or the record predates the block). */
export function verdictMarginThreshold(record: VerdictRecordJson): number | null {
  const attestation = (record.capsule.model_attestation ?? null) as Record<string, unknown> | null
  const compute = (attestation?.compute_attestation ?? null) as Record<string, unknown> | null
  const block = (compute?.adjudication ?? null) as Record<string, unknown> | null
  const margin = (block?.split_margin ?? null) as Record<string, unknown> | null
  const nats = typeof margin?.threshold === 'string' ? Number(margin.threshold) : NaN
  return Number.isFinite(nats) ? nats : null
}

function natsText(nats: number): string {
  return String(Number(nats.toFixed(6)))
}

/** The line a verdict shows for the referee margin it was judged by: always
 *  when the record seals one, with a warning when it was below the rule; null
 *  when the record carries none. */
export function marginVerdictLine(record: VerdictRecordJson): { text: string; lowered: boolean } | null {
  const threshold = verdictMarginThreshold(record)
  if (threshold === null) return null
  if (threshold >= SPLIT_MARGIN_RULE) return { text: `Judged at referee margin ${natsText(threshold)} nats.`, lowered: false }
  return {
    text: `Judged at a lowered referee margin: ${natsText(threshold)} nats, below the ${SPLIT_MARGIN_RULE} default. Honest nodes can be named wrong at this setting.`,
    lowered: true
  }
}

/** The page notice when this node's referee margin is below the rule. */
export function loweredMarginNotice(
  margin: { threshold: string; rule: string; lowered: boolean } | null | undefined
): string | null {
  if (!margin?.lowered) return null
  const nats = Number(margin.threshold)
  if (!Number.isFinite(nats)) return null
  const rule = Number(margin.rule)
  return `This node’s referee margin is lowered to ${natsText(nats)} nats (the default is ${natsText(Number.isFinite(rule) ? rule : SPLIT_MARGIN_RULE)}). It names a node wrong on a closer split, so honest nodes can be accused. Change it under Configuration › Plugins.`
}

/** Whether the plugin could check the verdict: the referee's signature, and
 *  this node's chain recording it. */
export function verdictSignatureText(record: VerdictRecordJson): string {
  if (record.legacy) {
    return 'Legacy, unverified: an earlier run of this node recorded this verdict. This node has no referee now and doesn’t check who signed it. Treat it as unconfirmed.'
  }
  if (record.verify_ok) {
    const held =
      record.recorded_as === 'issued'
        ? 'this node issued it and its log records it'
        : record.recorded_as === 'received'
          ? 'it was delivered to this node and its log records it'
          : 'this node’s log records it'
    return `The referee’s signature checks on this node, and ${held}.`
  }
  if (record.signature_error) {
    return `The referee’s signature doesn’t check on this node (${record.signature_error}). Treat this verdict as unconfirmed.`
  }
  return 'This node couldn’t confirm this verdict: its signature doesn’t check, or its log doesn’t record it. Treat it as unconfirmed.'
}

/** The verdict in one sentence, for the record dialog. */
export function verdictSentence(verdict: ParsedVerdict | null): string {
  if (verdict === null) return 'The record holds no verdict this page can read.'
  switch (verdict.kind) {
    case 'corroborated':
      return 'Verdict: corroborated. The referee found the answers agree.'
    case 'contradicted':
      return `Verdict: contradicted. The referee found node ${shortId(verdict.party)}’s answer wrong.`
    case 'inconclusive':
      return 'Verdict: inconclusive. The referee couldn’t decide between the answers.'
    case 'not_comparable':
      return 'Verdict: not comparable. The answers were sampled, so they can’t be compared; this is never a disagreement.'
  }
}
