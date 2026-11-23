import type { SettlementReportStatus } from '@/features/capsules/api/client'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'

// The page header's Reports group (Mesh-LLM/capsules-plugin#96, #339): one
// entry per grade of the evidencebook-report skill
// (evidencebook-skills `skills/evidencebook-report/SKILL.md`), in the skill's
// own grade words. No score, grade letter or percentage.

/** Grade 1. A narration is an agent reading sealed records; the dashboard has
 *  no agent, so a plain line says where narration comes from (Sherlock2, Q2 on
 *  #96; a line, not a button that does nothing: Sherlock2 on #339). */
export const NARRATION_NEEDS_AGENT =
  'Narrated: ask your agent, with the evidencebook-report skill, to read your sealed records. This dashboard has no agent, so it narrates nothing.'

/** Grade 2: the node's latest sealed report, checked against its seal when
 *  the node hands it over (`settlement_report.rs`). */
export const SEALED_LABEL = 'EvidenceBook report (sealed and checked)'

/** Grade 3: the History page here, and each paid exchange's receipt on its row. */
export const STAMPED_LABEL = 'Stamped: History page'

/** What the row says after saving the sealed report: when it was sealed and
 *  the day it reports up to, so a stale report shows as stale. */
export function sealedNote(sealedAt: string | null, date: string | null): string {
  return `Saved the EvidenceBook report sealed ${sealedAt ? formatExchangeTimestamp(sealedAt) : 'at an unrecorded time'}, reporting up to ${date ?? 'an unrecorded day'}. It matched its seal when the node handed it over.`
}

/** What the row says when the node has no sealed report to give. Nothing is
 *  saved: the honest refusal is the reason, in words (Sherlock2 on #339). */
export function noReportNote(why: string): string {
  return `No report to give: ${why}.`
}

/** What the sealed-report button says before it is pressed, from
 *  `settlement-report/status`; `null` when the node did not say. */
export function reportStatusLine(status: SettlementReportStatus): string | null {
  if (status.kind === 'not_ready') return `No report yet: ${status.why}.`
  if (status.kind === 'ready') {
    return status.sealedAt
      ? `A report is ready: sealed ${formatExchangeTimestamp(status.sealedAt)}, reporting up to ${status.date ?? 'an unrecorded day'}. It is checked against its seal when you save it.`
      : 'A report is ready; when it was sealed is not recorded. It is checked against its seal when you save it.'
  }
  return null
}
