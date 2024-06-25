import type { Jwk } from '@hyperledger/aries-askar-shared'
import type { AskarCryptoKey } from './CryptoKey'

export type CryptoKeyPair = {
  publicKey: AskarCryptoKey
  privateKey: AskarCryptoKey
}

export type EcdsaParams = {
  name: 'ECDSA'
  hash: { name: 'SHA-256' | 'SHA-384' | 'SHA-512' }
}

// TODO: imporove name of `KeySignParams`
export type KeySignParams = EcdsaParams

export type EcKeyGenParams = {
  name: 'ECDSA'
  namedCurve: 'P-256'
  hash?: { name: 'SHA-256' }
}

export type KeyAlgorithm = EcKeyGenParams

export type EcKeyImportParams = {
  name: 'ECDSA'
  namedCurve: 'P-256'
  hash?: { name: 'SHA-256' }
}

export type KeyImportParams = EcKeyImportParams

export type KeyUsage = 'sign' | 'verify'
export type KeyFormat = 'jwk' | 'pkcs8' | 'spki' | 'raw'
export type KeyType = 'private' | 'public' | 'secret'

// TODO
export type JsonWebKey = Jwk

export type HashAlgorithm = { name: 'SHA-1' }
