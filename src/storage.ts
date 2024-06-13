import * as core from 'webcrypto-core'
import { type Key as AskarKey, KeyAlgs } from '@hyperledger/aries-askar-shared'
import type { KeyType, KeyUsage } from './types'

const keyStorage = new WeakMap<core.CryptoKey, AskarKey>()

export function getCryptoKey(key: core.CryptoKey) {
  const res = keyStorage.get(key)
  if (!res) {
    throw new core.OperationError('Cannot get CryptoKey from secure storage')
  }
  return res
}

export function setCryptoKey(askarKey: AskarKey, keyType: KeyType, extractable = false) {
  const webCryptoAlgorithm = askarAlgorithmToWebCryptoAlgorithm(askarKey.algorithm)

  const keyUsage: KeyUsage[] = []
  if (keyType === 'public') keyUsage.push('verify')
  if (keyType === 'secret' || keyType === 'private') keyUsage.push('sign')

  const key = core.CryptoKey.create(webCryptoAlgorithm, keyType, extractable, keyUsage)

  Object.freeze(key)

  keyStorage.set(key, askarKey)

  return key
}

const askarAlgorithmToWebCryptoAlgorithm = (alg: KeyAlgs) => {
  switch (alg) {
    case KeyAlgs.Ed25519:
      return { name: KeyAlgs.Ed25519.toString() }

    case KeyAlgs.EcSecp256r1:
      return {
        name: 'ECDSA',
        namedCurve: KeyAlgs.EcSecp256r1.toString(),
        hash: { name: 'SHA-256' },
      }

    default:
      throw new Error(`Unsupported algorithm to convert: ${alg}`)
  }
}
