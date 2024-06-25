import { CryptoBox, KeyAlgs } from '@hyperledger/aries-askar-shared'
import type { KeyAlgorithm } from './types'

const CBOX_NONCE_LENGTH = 24

export const askarGetRandomValues = (buffer: Uint8Array): Uint8Array => {
  const genCount = Math.ceil(buffer.length / CBOX_NONCE_LENGTH)
  const buf = new Uint8Array(genCount * CBOX_NONCE_LENGTH)
  for (let i = 0; i < genCount; i++) {
    const randomBytes = CryptoBox.randomNonce()
    buf.set(randomBytes, CBOX_NONCE_LENGTH * i)
  }
  buffer.set(buf.subarray(0, buffer.length))
  return buffer
}

// TODO: this needs a proper conversion
export const cryptoAlgorithmToAskarAlgorithm = (algorithm: KeyAlgorithm) =>
  algorithm.name === 'ECDSA'
    ? KeyAlgs.EcSecp256r1
    : ((algorithm.namedCurve ? algorithm.namedCurve : algorithm.name) as KeyAlgs)

export const askarAlgorithmToCryptoAlgorithm = (algorithm: KeyAlgs): KeyAlgorithm => {
  switch (algorithm) {
    case KeyAlgs.EcSecp256r1:
      return { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } }
    default:
      throw new Error(`Unsupported askar algorithm: ${algorithm}`)
  }
}
