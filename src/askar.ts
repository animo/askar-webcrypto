import type * as core from 'webcrypto-core'
import { getCryptoKey, setCryptoKey } from './storage'
import { Key, type KeyAlgs } from '@hyperledger/aries-askar-shared'

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
  const cKey = setCryptoKey(key)

  return { publicKey: cKey, privateKey: cKey }
}
