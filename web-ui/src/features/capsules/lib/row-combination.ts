// One hover for a whole exchange row: what the state badge and the chips say
// together (the tooltip assessment's combinations A1-A18). Pure, so each
// combination is unit-testable. It reads only what the row already shows:
// the gate's state, the chip results, whose record is held and the row's age.
import type { EntryRowChipMark } from '@/features/capsules/lib/entry-row-chips'
import type { RightCellStateKind } from '@/features/capsules/lib/exchange-row-state'

export type RowCombinationInput = {
  state: RightCellStateKind
  /** `SERVED` or `ASKED`. */
  roleTag: string
  /** A served row that holds this node's book as the provider of a paid
   *  exchange: another node asked for it. */
  servedForPay?: boolean
  yoursHeld: boolean
  /** The node's records have loaded and this row's own record isn't among
   *  them, so it is missing, not still loading (#388). */
  ownRecordMissing?: boolean
  marks: { content: EntryRowChipMark; sig: EntryRowChipMark; inclusion: EntryRowChipMark; registered: EntryRowChipMark }
  /** The door refused their record for naming another server or model. */
  refusedAtTheDoor: boolean
  /** The other side's node, short, when our record names one to ask. */
  askPeer?: string | null
}

/** #388: the records have loaded and this one isn't among them: why, and
 *  what the operator can do. */
export const OWN_RECORD_MISSING =
  'Your record of this exchange isn’t among the records this node returned, so nothing about your side is checked here. Reload the page; if it stays, save the evidence file and check this node’s storage.'

export const WITNESS_HOLDS_IT = ' A witness you don’t run also holds your checkpoint.'

export function rowCombinationText(input: RowCombinationInput): string {
  const { state, marks } = input
  if (!input.yoursHeld) return 'Only their record exists; there is nothing of yours to compare it with.'
  if (marks.content === '✗' || marks.sig === '✗') {
    return 'Your own copy fails its checks, so neither side can rely on it, whatever the badge says. Save the evidence file and check this node’s storage.'
  }
  const witnessed = marks.registered === '✓' ? WITNESS_HOLDS_IT : ''
  if (marks.content === '–' && marks.sig === '–') {
    return input.ownRecordMissing
      ? OWN_RECORD_MISSING
      : 'Your record isn’t loaded on this page yet, so nothing about your side is checked here.'
  }
  switch (state) {
    case 'closed':
      // On a SERVED row this node served them: a Confirmed record is signed
      // with the key the requesting node announced and names this node as its
      // server (#412); transport is never checked, so never "sent" (Sherlock2's
      // ruling, buzz 60d4b649).
      return marks.inclusion === '✓' || marks.inclusion === '◐'
        ? input.roleTag === 'SERVED'
          ? `Both records agree and check out: yours is unchanged and signed; the node you served signed its own record with the key it announced, and it names you as the node that served it, with the same request, answer and model weights.${witnessed}`
          : `Both records agree and check out: yours is unchanged and signed, and theirs is signed, from the node that served you, with the same request, answer and model weights.${witnessed}`
        : `Confirmed by them; your record is newer than your last checkpoint and the next one will cover it.${witnessed}`
    case 'contradicted':
      return input.refusedAtTheDoor
        ? 'Their signed record says another server or another model handled your request, so your node refused it. Use Compare to see the difference.'
        : `Your record checks out, and their signed record disagrees with it, or doesn’t match its own id. Use Compare to see where.${witnessed}`
    case 'open_not_held':
      return 'Your record is sealed and checks out; their record hasn’t arrived. It comes on its own only if their node sends records (on by default, unless its operator turned it off), so ask for it on this row.'
    case 'open_not_given':
      return 'Your record is sealed and checks out; their record hasn’t arrived, and nothing they sent names it by its id. Ask for it on this row.'
    case 'open_not_asked':
      if (input.askPeer) return `Their record hasn’t arrived. You can ask ${input.askPeer} for it.`
      if (input.roleTag !== 'SERVED') return 'Your record doesn’t name who answered, so there is no one to ask.'
      return input.servedForPay
        ? 'You served this for pay to another node; which node paid isn’t recorded, so there is no one to ask.'
        : 'You served this yourself; your record is all there is.'
    case 'open_asked':
      return 'You asked for their record and no verified answer has come back yet.'
    case 'open_refused':
      return 'They declined to share their record and signed the refusal; the refusal is on your record.'
    case 'open_absent':
      return 'They say they have no record of this exchange. That is their statement, not something checked here.'
  }
}
