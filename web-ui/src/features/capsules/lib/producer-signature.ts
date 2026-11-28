// A record's producer signature, checked under a key this node was told the
// producer signs with -- never under a key the record or its sender names
// for itself. Shared by "Ask them for their record" (`ask-for-record.ts`) and
// THE gate's SERVED-row check (`exchange-row-state.ts`).
import { verifyCoseSign1 } from '@/features/capsules/lib/cose'

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

export function hexBytes(hex: string): Uint8Array | null {
  if (!/^([0-9a-f]{2})+$/i.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

/** The announced key's bytes, when the item names that same key. */
export function announcedKeyBytes(namedKeyId: unknown, announcedKeyId: string | null): Uint8Array | null {
  const named = str(namedKeyId)?.toLowerCase()
  if (!announcedKeyId || named !== announcedKeyId.toLowerCase()) return null
  const key = hexBytes(announcedKeyId)
  return key && key.length === 32 ? key : null
}

/** A record's producer signature: a COSE_Sign1 over its own 32-byte
 *  `capsule_id`, under the key this node was told the peer signs with. A
 *  record naming any other key, or a peer with no announced key, fails. */
export function producerSignatureVerifies(record: Record<string, unknown>, announcedKeyId: string | null): boolean {
  const envelope = hexBytes(str(record.signature) ?? '')
  const key = announcedKeyBytes(record.key_id, announcedKeyId)
  const id = hexBytes(str(record.capsule_id) ?? '')
  if (!envelope || !key || !id) return false
  const result = verifyCoseSign1(envelope, key)
  return result.verified && result.payload.length === id.length && result.payload.every((b, i) => b === id[i])
}
