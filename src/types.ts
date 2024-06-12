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
