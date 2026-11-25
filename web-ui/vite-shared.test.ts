// Guards that the build and the dev harness resolve the Evidence page the same
// way (#344): both configs must carry every shared alias and the ?iife plugin.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import buildConfig from './vite.config.ts'
import devConfig from './vite.dev.config.ts'
import { sharedAliases } from './vite-shared.ts'

const pluginNames = (c: { plugins?: unknown }) =>
  (c.plugins as { name?: string }[]).flat(Infinity as 1).map((p) => p?.name)

describe.each([
  ['build', buildConfig],
  ['dev', devConfig]
])('%s config', (_n, config) => {
  it('uses the shared aliases', () => {
    expect(config.resolve?.alias).toBe(sharedAliases)
    expect(sharedAliases.map((a) => String(a.find))).toEqual(
      expect.arrayContaining(['@', '@cll-browser', '@aac-browser', String(/^@action-state-group\/agent-action-capsule$/)])
    )
  })
  it('has the capsules:inline-iife plugin', () => {
    expect(pluginNames(config)).toContain('capsules:inline-iife')
  })
})

// The alias hands capsule-viewer the web UI's own agent-action-capsule, so the
// two pins must name the same version, and vitest must send capsule-viewer
// through Vite for the alias to reach it (#376).
describe('the one runtime', () => {
  const pkg = (file: string) => JSON.parse(readFileSync(file, 'utf8')) as { dependencies: Record<string, string> }
  it('is the version capsule-viewer depends on', () => {
    const viewer = pkg('node_modules/@action-state-group/capsule-viewer/package.json')
    expect(pkg('package.json').dependencies['@action-state-group/agent-action-capsule']).toBe(
      viewer.dependencies['@action-state-group/agent-action-capsule']
    )
  })
  it('reaches capsule-viewer in vitest', () => {
    expect((buildConfig as { test?: { server?: { deps?: { inline?: unknown } } } }).test?.server?.deps?.inline).toContain(
      '@action-state-group/capsule-viewer'
    )
  })
})
