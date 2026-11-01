// The pages the Exchanges tab saves for an outside party (the History and
// Settlement pages, and each exchange's receipt page): one .html file each,
// opened with no account, no server and no network (Mesh-LLM/capsules-plugin#96,
// Steven's 10-29 ruling).
//
// Each page embeds the bundle it shows as base64 of the exact bytes the node
// served (`#mesh-bundle`), so a verifier can take the bytes out unchanged: the
// page's "Save the JSON" link does it, and so does reading the base64 by hand.
// The page checks its own bundle when it opens, with the same code the tests
// run (`history-page-entry.ts` or `receipt-page-verify.ts`, inlined), and shows
// its content only from a bundle that checked. Whatever the page could not
// check, it lists as not checked.
import { historyViewStyles } from '@action-state-group/capsule-viewer/history-view'
import type { HistorySharing } from '@/features/capsules/api/client'
import type { HistoryPageContext } from '@/features/capsules/lib/history-view-input'
import verifierSource from '@/features/capsules/lib/history-page-entry.ts?iife'
import receiptVerifierSource from '@/features/capsules/lib/receipt-page-verify.ts?iife'

/** The id of the script that holds the bundle, base64 of the served bytes. */
export const BUNDLE_ELEMENT_ID = 'mesh-bundle'

/** The id of the script that holds what the History page needs besides the
 *  bundle: the node's key, its sharing settings and when they were read. */
export const CONTEXT_ELEMENT_ID = 'mesh-context'

/** The tool named in the History page's "How this was checked". */
export const BUILT_BY = 'capsules-plugin web-ui'

export type SavedPage = { fileName: string; html: string }

const escapeHtml = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

export const toBase64 = (text: string): string => {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}

// `</script` inside the inlined verifier would end its script element early.
const inlineScript = (code: string): string => code.replace(/<\/script/gi, '<\\/script')

const STYLE = `
:root{color-scheme:light dark;--fg:#1b1d21;--muted:#5b616b;--bg:#fff;--line:#d9dce1;--ok:#14663b;--bad:#a4281d;--warn:#7a5200}
@media (prefers-color-scheme:dark){:root{--fg:#e8eaee;--muted:#a3a9b3;--bg:#16181c;--line:#33373e;--ok:#5fcf90;--bad:#ff8f84;--warn:#e6b85c}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:46rem;margin:0 auto}h1{font-size:1.4rem;margin:0 0 .25rem}h2{font-size:1rem;margin:1.5rem 0 .5rem}
p,li{margin:.25rem 0}.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
ul{padding-left:1.25rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:.25rem .5rem;text-align:left}
button{font:inherit;padding:.25rem .75rem}code{font-family:ui-monospace,monospace;font-size:.9em;overflow-wrap:anywhere}
`

/** What the Settlement page says when the node has no sealed settlement report
 *  to give, before the node's own reason: the refusal, never an empty page. */
export const SETTLEMENT_REFUSAL_WORDS =
  'This node gave no settlement report, so there are no figures to show, and none are made up.'

// The page's own script: reads the embedded bytes, checks them, and draws the
// result with textContent only (nothing from the bundle is ever parsed as HTML).
const RUNTIME = `
(function(){
  var bytes=Uint8Array.from(atob(document.getElementById('${BUNDLE_ELEMENT_ID}').textContent.trim()),function(c){return c.charCodeAt(0)});
  var text=new TextDecoder().decode(bytes);
  var out=document.getElementById('result');
  function el(tag,cls,t){var e=document.createElement(tag);if(cls)e.className=cls;if(t!==undefined)e.textContent=t;return e}
  document.getElementById('save-json').addEventListener('click',function(){
    var url=URL.createObjectURL(new Blob([bytes],{type:'application/json'}));
    var a=document.createElement('a');a.href=url;a.download=document.body.getAttribute('data-json-name');document.body.appendChild(a);a.click();a.remove();
    setTimeout(function(){URL.revokeObjectURL(url)},0)});
  var kind=document.body.getAttribute('data-kind');
  if(kind==='receipt'){
    CapsulesSavedPage.receiptPageLines(text).then(function(r){
      r.lines.forEach(function(line,i){out.appendChild(el('p',i===0?r.tone:'muted',line))})},
      function(){out.appendChild(el('p','bad','This page could not check its receipt, so it shows none of it.'))});
    return}
  if(kind==='receipt-note'){
    var note;try{note=JSON.parse(text)}catch(e){note=null}
    if(note&&note.source==='dashboard'&&(note.case==='no_record'||note.case==='no_receipt_yet')&&typeof note.why==='string'){
      out.appendChild(el('p','warn',note.case==='no_record'?'Receipt: no record':'No receipt yet'));
      out.appendChild(el('p',null,'Its reason: '+note.why));
      out.appendChild(el('p','muted','This page holds no evidence from the node.'))}
    else out.appendChild(el('p','bad','This page could not read its own note, so it shows nothing.'));
    return}
  if(kind==='settlement-refusal'){
    var doc;try{doc=JSON.parse(text)}catch(e){doc=null}
    if(doc&&doc.source==='dashboard'&&doc.reason==='no_report'&&doc.words===${JSON.stringify(SETTLEMENT_REFUSAL_WORDS)}&&typeof doc.why==='string'){
      out.appendChild(el('p','warn','No report: this page holds no evidence from the node.'));
      out.appendChild(el('p',null,doc.words));
      out.appendChild(el('p',null,'Its reason: '+doc.why))}
    else out.appendChild(el('p','bad','This page could not read its own note, so it shows nothing.'));
    return}
  var context=JSON.parse(document.getElementById('${CONTEXT_ELEMENT_ID}').textContent);
  function draw(verdict){CapsulesSavedPage.renderHistoryView(CapsulesSavedPage.historyViewInput(verdict,context),out)}
  CapsulesSavedPage.verifyHistoryReply(text).then(draw,function(){draw({kind:'unreadable',verified:false,checks:[{id:'readable',status:'fail',detail:''}],checkpoints:[]})});
})();
`

type Shell = {
  title: string
  kind: 'history' | 'settlement-refusal' | 'receipt' | 'receipt-note'
  intro: string
  bundleText: string
  jsonName: string
  /** What the saved bytes are, in a sentence. */
  inside: string
  /** The History page's context; the Settlement page has none. */
  context?: HistoryPageContext
}

/** The checker a page inlines: the one for the bundle it carries; a note
 *  carries no evidence and needs none. */
function verifierFor(kind: Shell['kind']): string {
  if (kind === 'history') return verifierSource
  if (kind === 'receipt') return receiptVerifierSource
  return ''
}

function shell({ title, kind, intro, bundleText, jsonName, inside, context }: Shell): string {
  const evidence = kind === 'history' || kind === 'receipt'
  const verifier = verifierFor(kind)
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}${kind === 'history' ? historyViewStyles : ''}</style>
</head>
<body data-kind="${kind}" data-json-name="${escapeHtml(jsonName)}">
<main>
${kind === 'history' ? '' : `<h1>${escapeHtml(title)}</h1>\n<p class="muted">${escapeHtml(intro)}</p>`}
<div id="result"></div>
<h2>${evidence ? 'The file inside' : 'The note inside'}</h2>
<p class="muted">${escapeHtml(inside)}</p>
<p><button id="save-json" type="button">${evidence ? 'Save the JSON' : 'Save the note'}</button> <code>${escapeHtml(jsonName)}</code></p>
</main>
<script type="application/octet-stream" id="${BUNDLE_ELEMENT_ID}" data-encoding="base64">${toBase64(bundleText)}</script>
${kind === 'history' ? `<script type="application/json" id="${CONTEXT_ELEMENT_ID}">${JSON.stringify(context).replace(/</g, '\\u003c')}</script>` : ''}
${verifier ? `<script>${inlineScript(verifier)}</script>` : ''}
<script>${RUNTIME}</script>
</body>
</html>
`
}

const stamp = (when: string): string => when.replace(/[^0-9TZ]/g, '').slice(0, 15)

/** The History page: what this node answers a stranger who asks for its
 *  history, as the node served it (`replyText`, unchanged). */
export function historyPage(
  replyText: string,
  savedAt: string,
  node: { nodeKeyId: string; sharing: HistorySharing }
): SavedPage {
  const name = `mesh-history-${stamp(savedAt)}`
  return {
    fileName: `${name}.html`,
    html: shell({
      title: 'This node’s history',
      kind: 'history',
      intro: '',
      bundleText: replyText,
      jsonName: `${name}.json`,
      inside: 'This page carries the exact bytes the node served, below. Save them to check them with your own tools.',
      context: { nodeKeyId: node.nodeKeyId, savedAt, sharing: node.sharing, builtBy: BUILT_BY }
    })
  }
}


/** The Settlement page when the node has no sealed report to give: a note
 *  with the node's own reason (`settlement-report`'s refusal), word for word. */
export function settlementPage(savedAt: string, why: string): SavedPage {
  const name = `mesh-settlement-${stamp(savedAt)}`
  const refusal = `${JSON.stringify({ source: 'dashboard', reason: 'no_report', words: SETTLEMENT_REFUSAL_WORDS, why })}\n`
  return {
    fileName: `${name}.html`,
    html: shell({
      title: 'This node’s settlement report',
      kind: 'settlement-refusal',
      intro: 'Saved ' + savedAt + '.',
      bundleText: refusal,
      jsonName: `${name}.json`,
      inside: 'Written by this dashboard when you saved the page. It is not from the node, and it holds no evidence.'
    })
  }
}

/** The node's sealed EvidenceBook settlement report, as `settlement-report`
 *  served it after `book report check` said it matches its seal: capsulectl's
 *  own page, which embeds its bundle, renders only from the verified bundle,
 *  and gives the bundle back from its JSON element. Handed over unchanged. */
export function sealedSettlementPage(page: string, savedAt: string): SavedPage {
  return { fileName: `mesh-settlement-${stamp(savedAt)}.html`, html: page }
}

/** What the receipt page carries: the bundle the node served, or the reason
 *  there is none (the node's refusal, word for word, or that the dashboard
 *  names no paid deal for the exchange). */
export type ReceiptSource =
  | { kind: 'bundle'; bundleText: string }
  | { kind: 'no_record' | 'no_receipt_yet'; why: string }

/** Why a receipt page holds no record for an exchange with no invoice (a
 *  free exchange, or terms only): no deal is sealed for it. */
export const NO_PAID_DEAL_WHY = 'this exchange was not paid, so this node sealed no deal for it'

/** Why a paid exchange's page holds no receipt yet when the row cannot name
 *  its deal (`receiptRequest` gives none: a provider book over more than one
 *  exchange, or a payer row without its own record). */
export const UNNAMED_DEAL_WHY = 'this exchange was paid, but this node cannot yet name the one deal it belongs to'

/** One exchange's receipt page (Steven's 10-29 ruling, item 1): the receipt
 *  bundle as the node served it, checked by the page when it opens, or a
 *  note saying why there is none. */
export function receiptPage(source: ReceiptSource, exchangeKey: string, savedAt: string): SavedPage {
  const name = `mesh-receipt-${exchangeKey.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 64)}-${stamp(savedAt)}`
  const intro = `This node’s own receipt for exchange ${exchangeKey}. Saved ${savedAt}.`
  if (source.kind === 'bundle') {
    return {
      fileName: `${name}.html`,
      html: shell({
        title: 'Receipt for one exchange',
        kind: 'receipt',
        intro,
        bundleText: source.bundleText,
        jsonName: `${name}.json`,
        inside: 'This page carries the exact bytes the node served, below. Save them to check them with your own tools.'
      })
    }
  }
  const note = `${JSON.stringify({ source: 'dashboard', case: source.kind, why: source.why })}\n`
  return {
    fileName: `${name}.html`,
    html: shell({
      title: 'Receipt for one exchange',
      kind: 'receipt-note',
      intro,
      bundleText: note,
      jsonName: `${name}.json`,
      inside: 'Written by this dashboard when you saved the page. It is not from the node, and it holds no evidence.'
    })
  }
}
