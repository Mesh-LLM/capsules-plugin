import { webcrypto } from 'node:crypto'
import { JSDOM } from 'jsdom'
import { BUNDLE_ELEMENT_ID } from '@/features/capsules/lib/saved-pages'

/** A saved page as a person opens it: no server, no network. jsdom runs the
 *  page's own scripts; the only thing given to it is the platform (`crypto`,
 *  text codecs) a browser has and jsdom lacks. `requested` lists every fetch
 *  or XHR the page tried. */
export async function openSavedPage(html: string) {
  const requested: string[] = []
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    url: 'file:///saved/page.html',
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>
      Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true })
      w.TextEncoder = TextEncoder
      w.TextDecoder = TextDecoder
      w.fetch = (url: string) => {
        requested.push(String(url))
        return Promise.reject(new Error('offline'))
      }
      w.XMLHttpRequest = function () {
        requested.push('xhr')
      }
    }
  })
  // The page checks its bundle asynchronously.
  for (let i = 0; i < 200 && !dom.window.document.querySelector('#result')?.childElementCount; i++) await new Promise((r) => setTimeout(r, 10))
  return { dom, requested, text: dom.window.document.querySelector('main')?.textContent ?? '' }
}

/** The bytes a saved page embeds as its bundle. */
export function embeddedBundle(html: string): Uint8Array {
  const match = new RegExp(`id="${BUNDLE_ELEMENT_ID}"[^>]*>([^<]*)<`).exec(html)
  return Uint8Array.from(atob(match![1]), (c) => c.charCodeAt(0))
}

/** Click the page's save button and return the bytes it hands the viewer. */
export async function savedBytes(dom: JSDOM): Promise<Buffer> {
  let saved: Blob | undefined
  dom.window.URL.createObjectURL = (blob: Blob | MediaSource) => {
    saved = blob as Blob
    return 'blob:x'
  }
  dom.window.URL.revokeObjectURL = () => {}
  ;(dom.window.document.getElementById('save-json') as HTMLButtonElement).click()
  return Buffer.from(await saved!.arrayBuffer())
}
