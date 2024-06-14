import type { Jwk } from '@hyperledger/aries-askar-shared'
import type * as core from 'webcrypto-core'

export type CryptoKeyPair = {
  publicKey: core.CryptoKey
  privateKey: core.CryptoKey
}

export type EcdsaParams = {
  name: 'ECDSA'
  hash: { name: 'SHA-256' | 'SHA-384' | 'SHA-512' }
}

export type EcKeyGenParams = {
  name: 'ECDSA'
  namedCurve: 'P-256'
}

export type EcKeyImportParams = {
  name: 'ECDSA'
  namedCurve: 'P-256'
}

export type KeyUsage = 'sign' | 'verify'
export type KeyFormat = 'jwk' | 'pkcs8' | 'spki' | 'raw'
export type KeyType = 'private' | 'public' | 'secret'

// TODO
export type JsonWebKey = Jwk

export type HashAlgorithm = { name: 'SHA-1' }
