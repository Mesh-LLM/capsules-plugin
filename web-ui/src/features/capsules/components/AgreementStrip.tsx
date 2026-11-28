// The service evidence agreement on an exchange row (docs/AGREEMENTS.md).
// Chips are HoverChips (spans), never buttons: the row's button count is
// pinned.
import { StatusBadge } from '@/components/ui/StatusBadge'
import type { AgreementCoverage } from '@/features/capsules/api/sidecarTypes'
import { HoverChip } from '@/features/capsules/components/HoverChip'
import { agreementView } from '@/features/capsules/lib/agreement-view'
import { AGREEMENT_SIDE_TOOLTIP, AGREEMENT_SPEND_TOOLTIP } from '@/features/capsules/lib/tooltip-copy'

export function AgreementStrip({
  agreement,
  paid,
  servedForPay = false
}: {
  agreement: AgreementCoverage | undefined
  paid: boolean
  /** This node served the exchange for pay: the payer's cap isn't shown. */
  servedForPay?: boolean
}) {
  const view = agreementView(agreement, paid, servedForPay)
  if (!view) return null
  return (
    <div
      aria-label="service evidence agreement"
      className="flex flex-wrap items-center gap-2 text-xs"
      data-agreement-coverage={view.coverageKey}
      role="group"
    >
      {view.label !== null ? (
        <HoverChip census={`agreement_coverage:${view.coverageKey}`} label={view.tooltip}>
          <span>
            <StatusBadge size="caption" tone={view.tone}>
              {view.label}
            </StatusBadge>
          </span>
        </HoverChip>
      ) : null}
      {view.finding ? (
        <HoverChip census={`agreement_finding:${view.finding.key}`} label={view.finding.tooltip}>
          <span>
            <StatusBadge size="caption" tone="muted">
              {view.finding.label}
            </StatusBadge>
          </span>
        </HoverChip>
      ) : null}
      {view.side ? (
        <HoverChip census="agreement:side" label={AGREEMENT_SIDE_TOOLTIP}>
          <span className="text-fg-dim">{view.side}</span>
        </HoverChip>
      ) : null}
      {view.count ? <span className="font-mono tabular-nums text-fg-dim">{view.count}</span> : null}
      {view.spend ? (
        <>
          <span className="font-mono tabular-nums text-fg-dim">{view.spend}</span>
          <HoverChip census="agreement:spend_cap" label={AGREEMENT_SPEND_TOOLTIP}>
            <span className="text-fg-faint">spend cap: agent-origin assertion</span>
          </HoverChip>
        </>
      ) : null}
    </div>
  )
}
