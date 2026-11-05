// One row of the Peers table. Each column answers one way a stranger could
// cheat (rewrote the record, left something out, swapped the model) with one
// badge, never blended into one paragraph. A row with exchange history opens
// the `PeerInspector` drawer. No online badge, latency or Route-to-chat button
// here: those are Network's job.
import { useState } from 'react'
import { TableCell, TableRow } from '@/components/ui/table'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { PeerInspector } from '@/features/capsules/components/PeerInspector'
import type { HistoryOutcome } from '@/features/capsules/lib/ask-for-history'
import type { PeerMeshStatus } from '@/features/capsules/lib/peer-mesh-status'
import {
  ALL_PEER_TABLE_COLUMNS,
  isShownAttention,
  peerIdentityAliases,
  unlinkedNodeId,
  type PeerBadge,
  type PeerTableColumnKey,
  type PeerTableRowView
} from '@/features/capsules/lib/peer-row-view'
import { HoverChip } from '@/features/capsules/components/HoverChip'
import { PEER_PAYMENTS_TOOLTIP } from '@/features/capsules/lib/tooltip-copy'

export type PeerTableRowProps = {
  view: PeerTableRowView
  meshStatus: PeerMeshStatus | null
  /** Columns toggle (the Peers table toolbar): the Peer and Open cells are
   *  never hideable. */
  visibleColumns?: ReadonlySet<PeerTableColumnKey>
  /** How the page names this peer (`peer-names.ts`): hostname, then short
   *  id. Defaults to the row's own id. */
  name?: string
  /** Where the drawer's "Open in Exchanges" and "Open the verdict" go. */
  onOpenExchanges?: () => void
  /** Asks this peer's node for its history (see `PeerInspector`). */
  onAskHistory?: (nodeId: string) => Promise<HistoryOutcome>
}

function Badge({ badge }: { badge: PeerBadge }) {
  return (
    <StatusBadge size="caption" tone={badge.tone}>
      {badge.text}
    </StatusBadge>
  )
}

export function PeerTableRow({
  view,
  meshStatus,
  visibleColumns = ALL_PEER_TABLE_COLUMNS,
  name,
  onOpenExchanges,
  onAskHistory
}: PeerTableRowProps) {
  const shownName = name ?? view.displayId
  const [inspectorOpen, setInspectorOpen] = useState(false)
  const inspectable = view.row !== null
  const openInspector = () => setInspectorOpen(true)
  const nodeId = view.row ? peerIdentityAliases(view.row).nodeId : null
  const { facts } = view
  // The two states with no column of their own; a disagreement and a differing
  // answer are the Left-something-out and Swapped columns.
  const attention = view.attention.filter(isShownAttention)

  return (
    <>
      <TableRow
        aria-label={inspectable ? `Open peer inspector for ${shownName}` : undefined}
        className={
          inspectable
            ? 'cursor-pointer align-top outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent'
            : 'align-top'
        }
        onClick={inspectable ? openInspector : undefined}
        onKeyDown={
          inspectable
            ? (event) => {
                if (event.target !== event.currentTarget || (event.key !== 'Enter' && event.key !== ' ')) return
                event.preventDefault()
                openInspector()
              }
            : undefined
        }
        tabIndex={inspectable ? 0 : undefined}
      >
        <TableCell>
          <div className="flex flex-col items-start gap-1.5">
            <span className="truncate font-mono text-sm font-medium text-foreground" title={view.displayId}>
              {shownName}
            </span>
            {nodeId || facts.actedAsReferee ? (
              <span className="font-mono text-fg-faint text-xs" data-peer-node="true">
                {nodeId ? `node ${nodeId.slice(0, 10)}…` : null}
                {nodeId && facts.actedAsReferee ? ' ' : null}
                {facts.actedAsReferee ? '· acted as referee' : null}
              </span>
            ) : null}
            {/* A node known only from your own records says so, and names the key this node was told it signs with. */}
            {view.row && unlinkedNodeId(view.row) ? (
              <span className="font-mono text-fg-faint text-xs">{view.aliasLine}</span>
            ) : null}
            {view.payments ? (
              <HoverChip census="peer:payments" label={PEER_PAYMENTS_TOOLTIP}>
                <span className="text-xs text-fg-dim" data-peer-payments="true">
                  Payments: {view.payments}
                </span>
              </HoverChip>
            ) : null}
            {attention.map((item) => (
              <HoverChip census={`peer_attention:${item.key}`} key={item.key} label={item.tooltip}>
                <span>
                  <StatusBadge size="caption" tone={item.tone}>
                    {item.label}
                  </StatusBadge>
                </span>
              </HoverChip>
            ))}
          </div>
        </TableCell>
        {visibleColumns.has('exchanges') ? (
          <TableCell className="text-xs text-fg-dim">
            {view.exchangeCount}
            {view.failedCount > 0 ? ` · ${view.failedCount} failed` : ''}
          </TableCell>
        ) : null}
        {visibleColumns.has('rewrote') ? (
          <TableCell>
            <Badge badge={facts.rewrote} />
          </TableCell>
        ) : null}
        {visibleColumns.has('leftOut') ? (
          <TableCell>
            <Badge badge={facts.leftOut} />
          </TableCell>
        ) : null}
        {visibleColumns.has('swapped') ? (
          <TableCell>
            <div className="flex flex-col items-start gap-1">
              <Badge badge={facts.swapped} />
              {/* The denominator always travels with the count. */}
              {facts.swapped.checked > 0 ? <span className="text-fg-faint text-xs">{facts.swapped.tally}</span> : null}
            </div>
          </TableCell>
        ) : null}
        {visibleColumns.has('period') ? <TableCell className="text-xs text-fg-dim">{view.period}</TableCell> : null}
        <TableCell className="text-xs">
          {inspectable ? (
            <button
              className="text-accent-text underline underline-offset-2"
              onClick={(event) => {
                event.stopPropagation()
                openInspector()
              }}
              type="button"
            >
              Open
            </button>
          ) : null}
        </TableCell>
      </TableRow>
      {view.row ? (
        <PeerInspector
          facts={facts}
          meshStatus={meshStatus}
          name={name}
          onAskHistory={onAskHistory}
          onClose={() => setInspectorOpen(false)}
          onOpenExchanges={onOpenExchanges}
          open={inspectorOpen}
          row={view.row}
        />
      ) : null}
    </>
  )
}
