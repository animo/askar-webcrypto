import * as core from 'webcrypto-core'
import { type Key as AskarKey, KeyAlgs } from '@hyperledger/aries-askar-shared'

const keyStorage = new WeakMap<core.CryptoKey, AskarKey>()

export function getCryptoKey(key: core.CryptoKey) {
  const res = keyStorage.get(key)
  if (!res) {
    throw new core.OperationError('Cannot get CryptoKey from secure storage')
  }
  return res
}

export function setCryptoKey(value: AskarKey) {
  const webCryptoAlgorithm = askarAlgorithmToWebCryptoAlgorithm(value.algorithm)
  const key = core.CryptoKey.create(webCryptoAlgorithm, 'secret', false, ['sign', 'verify'])

  Object.freeze(key)

  keyStorage.set(key, value)

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
