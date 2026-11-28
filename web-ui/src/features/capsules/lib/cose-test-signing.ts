// Test-only signing for records: a producer's COSE_Sign1 over a record's
// `capsule_id`, as `producer-signature.ts` checks it. Imported by tests only.
import { ed25519 } from '@noble/curves/ed25519'

export const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

/** A COSE_Sign1 (EdDSA, attached payload) over `payload`, as the producer
 *  signs a record's `capsule_id`. */
export function coseSign1(payload: Uint8Array, secret: Uint8Array): string {
  const protectedHeader = Uint8Array.of(0xa1, 0x01, 0x27)
  const sigStructure = Uint8Array.of(
    0x84,
    0x6a,
    ...new TextEncoder().encode('Signature1'),
    0x43,
    ...protectedHeader,
    0x40,
    0x58,
    payload.length,
    ...payload
  )
  const sig = ed25519.sign(sigStructure, secret)
  return hex(
    Uint8Array.of(0xd2, 0x84, 0x43, ...protectedHeader, 0xa0, 0x58, payload.length, ...payload, 0x58, 0x40, ...sig)
  )
}

/** `body` signed by `secret`: its `key_id` names that key and `signature`
 *  covers its 64-hex `capsule_id`. */
export function signedBy(body: Record<string, unknown>, secret: Uint8Array): Record<string, unknown> {
  const id = String(body.capsule_id)
  const bytes = Uint8Array.from(id.match(/../g) ?? [], (b) => Number.parseInt(b, 16))
  return { ...body, key_id: hex(ed25519.getPublicKey(secret)), signature: coseSign1(bytes, secret) }
}
