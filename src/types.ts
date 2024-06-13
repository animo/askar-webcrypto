import type { CryptoKey } from 'webcrypto-core'

export type CryptoKeyPair = {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export type EcdsaParams = {
  name: 'ECDSA'
  hash: { name: 'SHA-256' | 'SHA-384' | 'SHA-512' }
}

export type EcKeyGenParams = {
  name: 'ECDSA'
  namedCurve: 'p-256'
}

export type KeyUsage = 'sign' | 'verify'
export type KeyFormat = 'jwk' | 'pkcs8' | 'spki' | 'raw'
export type KeyType = 'private' | 'public' | 'secret'

// TODO
export type JsonWebKey = unknown

export type HashAlgorithm = { name: 'SHA-1' }
