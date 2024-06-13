import type * as core from 'webcrypto-core'
import { getCryptoKey, setCryptoKey } from './storage'
import { Key, type KeyAlgs, CryptoBox } from '@hyperledger/aries-askar-shared'

const CBOX_NONCE_LENGTH = 24

export const askarKeySign = (key: core.CryptoKey, data: ArrayBuffer) => {
  const internalKey = getCryptoKey(key)
  const signature = internalKey.signMessage({
    message: new Uint8Array(data),
  })

  return signature
}

export const askarKeyVerify = (key: core.CryptoKey, data: ArrayBuffer, signature: ArrayBuffer) => {
  const internalKey = getCryptoKey(key)

  const isVerified = internalKey.verifySignature({
    message: new Uint8Array(data),
    signature: new Uint8Array(signature),
  })

  return isVerified
}

export const askarKeyGenerate = (algorithm: string) => {
  const key = Key.generate(algorithm as KeyAlgs)

  // We add a key twice into the WeakStorage as a key can only have one type.
  // Maybe in the future we can just store the bytes for the public and a reference
  // for the secret/private key
  const publicKey = setCryptoKey(key, 'public', true)
  const secretKey = setCryptoKey(key, 'secret')

  return { publicKey, privateKey: secretKey }
}

export const askarKeyGetPublicBytes = (key: core.CryptoKey) => {
  const cKey = getCryptoKey(key)

  return cKey.publicBytes
}

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
