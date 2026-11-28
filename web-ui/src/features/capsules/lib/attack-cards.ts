// The three attack cards at the top of the Evidence tab (Steven's "Evidence Tab Redesign"): the three
// ways a stranger can cheat, how each would show up here, and whether any did. Pure: every number is
// one the page already reads (pane A rows and card, pane C rows, their right-cell states, the twin
// facts); a number with no source today reads "not checked", never a guess.
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { deriveRightCellState } from '@/features/capsules/lib/exchange-row-state'
import { parseVerdict } from '@/features/capsules/lib/adjudication-view'
import type { WitnessState } from '@/features/capsules/lib/integrity-view'
import type { PageRole } from '@/features/capsules/lib/tooltip-copy'

export type AttackTone = 'good' | 'warn' | 'bad' | 'muted'

export type AttackRow = { label: string; value: string; tone?: AttackTone }

export type AttackCard = {
  id: 'rewrote' | 'left_out' | 'swapped'
  title: string
  summary: string
  badge: string
  tone: AttackTone
  rows: readonly AttackRow[]
  /** The link under the rows, and where it goes. */
  action: { label: string; target: 'integrity' | 'peers' | 'exchanges' } | null
}

export type AttackCardInputs = {
  records: number
  /** Records an own checkpoint covers; `null` when the node reports no coverage. */
  covered: number | null
  witness: WitnessState
  rows: readonly PaneCRow[]
  /** The page's role (#388): a node that only sells reads the swapped-model
   *  card from the seller's side. */
  role?: PageRole | null
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

function witnessValue(state: WitnessState): { value: string; tone: AttackTone } {
  switch (state) {
    case 'latest':
      return { value: 'held', tone: 'good' }
    case 'earlier':
      return { value: 'held up to an earlier checkpoint', tone: 'warn' }
    case 'pending':
      return { value: 'on · none held yet', tone: 'warn' }
    case 'off':
    case 'unknown':
      return { value: 'off · only you can check', tone: 'warn' }
  }
}

/** One entry per pair (the two rows of a pair carry the same bracket id): the verdict THIS node asked for and
 *  holds as a sealed record, or `null`. Another node's ask (a verdict delivered to this node) and a verdict this
 *  node issued as a referee are never read here, and no mismatch is inferred from the two answers. */
function askedVerdicts(rows: readonly PaneCRow[]): ReadonlyMap<string, string | null> {
  const pairs = new Map<string, string | null>()
  for (const row of rows) {
    const bracket = row.twin?.bracket_id
    if (!bracket) continue
    const recorded = row.twin?.referee_row
    const verdict = recorded?.state === 'adjudicated' ? recorded.verdict : null
    if (!pairs.has(bracket) || (pairs.get(bracket) === null && verdict !== null)) pairs.set(bracket, verdict)
  }
  return pairs
}

export function buildAttackCards(input: AttackCardInputs): readonly AttackCard[] {
  const { records, covered, witness, rows, role = null } = input
  const states = rows.map((row) => deriveRightCellState(row).kind)
  // Rows with a counterparty by the page's own right-cell state: a half the door refused is one even though no record arrived.
  const withCounterparty = states.filter((kind) => kind !== 'open_not_asked').length
  const closed = states.filter((kind) => kind === 'closed').length
  const differ = states.filter((kind) => kind === 'contradicted').length
  const received = states.filter((kind) => kind === 'closed' || kind === 'contradicted').length

  const pairs = askedVerdicts(rows)
  const verdicts = [...pairs.values()].map((wire) => parseVerdict(wire))
  // Checked: a ruling on the answers. "Inconclusive" is checked, not caught; "not comparable" is no check at all.
  const checked = verdicts.filter((verdict) => verdict && verdict.kind !== 'not_comparable').length
  const caught = verdicts.filter((verdict) => verdict?.kind === 'contradicted').length
  const checkedLine = checked === 0 ? 'not checked' : `${caught} caught · ${checked} checked`

  const witnessRow = witnessValue(witness)
  const rewrote: AttackCard = {
    id: 'rewrote',
    title: 'Rewrote the record',
    summary: 'Someone changes what was said after the fact.',
    // A result, not a search (Sherlock2): the records a signed checkpoint covers, out of all sealed.
    badge: records === 0 || covered === null ? 'not checked' : `${covered}/${records} unchanged`,
    tone: records === 0 || covered === null ? 'muted' : covered === records ? 'good' : 'warn',
    rows: [
      { label: 'Sealed when it happened', value: `${records}` },
      {
        label: 'In a signed checkpoint',
        value: covered === null ? 'not reported' : `${covered}/${records}`,
        tone: covered === null ? 'muted' : covered === records ? 'good' : 'warn'
      },
      { label: 'Held by an outside witness', value: witnessRow.value, tone: witnessRow.tone }
    ],
    action: witness === 'off' || witness === 'unknown' ? { label: 'Turn on a witness', target: 'integrity' } : null
  }

  const leftOut: AttackCard = {
    id: 'left_out',
    title: 'Left something out',
    summary: 'A peer’s story of an exchange differs from yours, or skips it.',
    badge:
      differ > 0
        ? `${differ} of ${withCounterparty} differ`
        : withCounterparty === 0
          ? 'no peer record yet'
          : `${closed}/${withCounterparty} matched`,
    tone: differ > 0 ? 'bad' : withCounterparty === 0 ? 'muted' : closed === withCounterparty ? 'good' : 'warn',
    rows: [
      {
        label: 'Their signed record received',
        value: `${received}/${withCounterparty}`,
        tone: received === withCounterparty && withCounterparty > 0 ? 'good' : 'muted'
      },
      {
        label: 'Same request, answer, model',
        value: `${closed}/${withCounterparty}`,
        tone: closed === withCounterparty && withCounterparty > 0 ? 'good' : 'muted'
      },
      { label: 'Their full history compared', value: 'not checked', tone: 'muted' }
    ],
    action: { label: 'Ask a peer for their history', target: 'peers' }
  }

  const swapped: AttackCard = {
    id: 'swapped',
    title: 'Swapped the model',
    summary:
      role === 'selling'
        ? 'A buyer’s referee checks whether your answers came from the model you advertised.'
        : 'A peer serves a cheaper model or quant than it advertised.',
    badge: checked === 0 ? 'not checked' : `${caught} caught · ${checked} checked`,
    tone: caught > 0 ? 'bad' : checked === 0 ? 'muted' : 'good',
    rows: [
      { label: 'Same request to two machines', value: plural(pairs.size, 'pair'), tone: pairs.size > 0 ? undefined : 'muted' },
      { label: 'Referee re-answered', value: checkedLine, tone: caught > 0 ? 'bad' : checked === 0 ? 'muted' : 'good' }
    ],
    action: caught > 0 ? { label: 'Open the verdict', target: 'exchanges' } : null
  }

  return [rewrote, leftOut, swapped]
}
