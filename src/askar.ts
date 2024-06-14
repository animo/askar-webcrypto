import type * as core from 'webcrypto-core'
import { getCryptoKey, setCryptoKey } from './storage'
import { Key, type KeyAlgs, CryptoBox, Jwk } from '@hyperledger/aries-askar-shared'
import type { EcKeyGenParams, EcKeyImportParams, JsonWebKey, KeyFormat, KeyUsage } from './types'

const CBOX_NONCE_LENGTH = 24

export const askarKeySign = ({
  key,
  data,
}: {
  key: core.CryptoKey
  data: ArrayBuffer
}) => {
  const internalKey = getCryptoKey(key)
  const signature = internalKey.signMessage({
    message: new Uint8Array(data),
  })

  return signature
}

export const askarKeyVerify = ({
  key,
  data,
  signature,
}: {
  key: core.CryptoKey
  data: ArrayBuffer
  signature: ArrayBuffer
}) => {
  const internalKey = getCryptoKey(key)

  const isVerified = internalKey.verifySignature({
    message: new Uint8Array(data),
    signature: new Uint8Array(signature),
  })

  return isVerified
}

export const askarKeyGenerate = ({
  extractable,
  algorithm,
  keyUsages,
}: {
  algorithm: EcKeyGenParams
  extractable: boolean
  keyUsages: KeyUsage[]
}) => {
  const key = Key.generate(cryptoAlgorithmToAskarAlgorithm(algorithm))

  const publicKey = setCryptoKey({
    askarKey: key,
    extractable,
    // Filter out properties that are not possible for the public key
    keyUsages: keyUsages.filter((u) => u !== 'sign'),
    keyType: 'public',
  })

  const secretKey = setCryptoKey({
    askarKey: key,
    keyType: 'private',
    keyUsages,
    extractable,
  })

  return { publicKey, privateKey: secretKey }
}

export const askarKeyGetPublicBytes = (key: core.CryptoKey) => {
  const cKey = getCryptoKey(key)

  return cKey.publicBytes
}

export const askarKeyFromPublicBytes = ({
  algorithm,
  keyData,
  extractable,
  keyUsages,
}: {
  algorithm: EcKeyImportParams
  keyData: Uint8Array
  format: KeyFormat
  extractable: boolean
  keyUsages: KeyUsage[]
}) => {
  const publicKey = Key.fromPublicBytes({
    algorithm: cryptoAlgorithmToAskarAlgorithm(algorithm),
    publicKey: keyData,
  })

  return setCryptoKey({
    askarKey: publicKey,
    extractable,
    keyUsages,
    keyType: 'public',
  })
}

export const askarKeyFromSecretBytes = ({
  algorithm,
  keyData,
  extractable,
  keyUsages,
}: {
  algorithm: EcKeyImportParams
  keyData: Uint8Array
  format: KeyFormat
  extractable: boolean
  keyUsages: KeyUsage[]
}) => {
  const privateKey = Key.fromSecretBytes({
    algorithm: cryptoAlgorithmToAskarAlgorithm(algorithm),
    secretKey: keyData,
  })

  return setCryptoKey({
    askarKey: privateKey,
    extractable,
    keyUsages,
    keyType: 'private',
  })
}

export const askarExportKeyToJwk = (key: core.CryptoKey) => {
  const askarKey = getCryptoKey(key)

  if (key.type === 'public') return askarKey.jwkPublic
  if (key.type === 'private' || key.type === 'secret') {
    return askarKey.jwkSecret
  }

  throw new Error(`key.type '${key.type}' is not a string of 'public'/'private'/'secret'`)
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

export const askarKeyFromJwk = ({
  keyData,
  keyUsages,
  extractable,
}: {
  keyData: JsonWebKey
  keyUsages: KeyUsage[]
  extractable: boolean
}) => {
  const askarKey = Key.fromJwk({ jwk: new Jwk(keyData) })
  try {
    askarKey.secretBytes
    return setCryptoKey({
      askarKey,
      keyUsages,
      extractable,
      keyType: 'private',
    })
  } catch {
    return setCryptoKey({
      askarKey,
      keyUsages,
      extractable,
      keyType: 'public',
    })
  }
}

// TODO: this needs a proper conversion
const cryptoAlgorithmToAskarAlgorithm = (algorithm: EcKeyGenParams) =>
  (algorithm.namedCurve ? algorithm.namedCurve : algorithm.name) as KeyAlgs
