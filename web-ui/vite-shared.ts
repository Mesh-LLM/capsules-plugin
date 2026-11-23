// Resolution and plugins that the build (vite.config.ts) and the dev harness
// (vite.dev.config.ts) must agree on. The page imports `@cll-browser`,
// `@aac-browser` and `?iife` modules, so a config without them cannot load it;
// keeping them here is what stops the two configs drifting apart.
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { PluginOption } from 'vite'
import { build } from 'vite'

const dirname = path.dirname(fileURLToPath(import.meta.url))
const cllBrowser = path.resolve(dirname, 'node_modules/@action-state-group/cll/dist/browser.js')
const aacBrowser = path.resolve(dirname, 'node_modules/@action-state-group/agent-action-capsule/dist/browser.js')

export const sharedAliases = {
  '@': path.resolve(dirname, './src'),
  // The cll package's `browser` condition, named directly: the saved History
  // page bundles the same file (saved-pages.ts), and a test under node
  // must not pick the package's node build.
  '@cll-browser': cllBrowser,
  // The agent-action-capsule runtime's browser entry (its package `browser`
  // condition), named directly for the same reason.
  '@aac-browser': aacBrowser
}

/**
 * `import code from './x.ts?iife'` is `x.ts` bundled on its own as one
 * self-contained script (an IIFE exposing its exports on `globalThis[name]`),
 * as text. A saved page embeds it so it can verify its own bundle on open,
 * offline, with the same code the tests run.
 */
export function inlineIife(): PluginOption {
  const suffix = '?iife'
  return {
    name: 'capsules:inline-iife',
    enforce: 'pre',
    async resolveId(source, importer, options) {
      if (!source.endsWith(suffix)) return null
      const resolved = await this.resolve(source.slice(0, -suffix.length), importer, { ...options, skipSelf: true })
      return resolved ? `${resolved.id}${suffix}` : null
    },
    async load(id) {
      if (!id.endsWith(suffix)) return null
      const file = id.slice(0, -suffix.length)
      const result = await build({
        configFile: false,
        logLevel: 'silent',
        resolve: { alias: sharedAliases },
        build: {
          write: false,
          minify: true,
          target: 'es2022',
          lib: { entry: file, formats: ['iife'], name: 'CapsulesSavedPage', fileName: () => 'saved-page.js' }
        }
      })
      const outputs = (Array.isArray(result) ? result : [result]).flatMap((r) => ('output' in r ? r.output : []))
      const chunk = outputs.find((o) => o.type === 'chunk')
      if (!chunk || chunk.type !== 'chunk') throw new Error(`could not bundle ${file}`)
      this.addWatchFile(file)
      return `export default ${JSON.stringify(chunk.code)}`
    }
  }
}
