import assert, { equal } from 'node:assert'
import { describe, it } from 'node:test'

import type { Crypto } from '../../src'
import type { CryptoKeyPair } from '../../src'

export const generateAsymmetricKeyTests = (crypto: Crypto, algorithms: Array<Record<string, unknown>>) =>
  algorithms.map(generateAsymmetricKeyTest(crypto))

const genTestName = (algorithm: Record<string, unknown>) =>
  Object.values(algorithm)
    .flatMap((v) => (typeof v === 'object' ? Object.values(v as Record<string, unknown>) : [v]))
    .join('::')

const generateAsymmetricKeyTest = (crypto: Crypto) => (algorithm: Record<string, unknown>) =>
  describe(genTestName(algorithm), async () => {
    it('generate', async () => {
      const key = (await crypto.subtle.generateKey(algorithm as unknown as AlgorithmIdentifier, false, [
        'sign',
        'verify',
      ])) as CryptoKeyPair

      equal(key.publicKey.type, 'public')
      equal(key.privateKey.type, 'private')
    })

    it('sign', async () => {
      const message = Buffer.from('Hello World!')

      const key = (await crypto.subtle.generateKey(algorithm as unknown as AlgorithmIdentifier, false, [
        'sign',
        'verify',
      ])) as CryptoKeyPair

      const signature = await crypto.subtle.sign(algorithm as unknown as AlgorithmIdentifier, key.privateKey, message)

      assert(signature)
    })

    it('verify', async () => {
      const message = Buffer.from('Goodbye World!')

      const key = (await crypto.subtle.generateKey(algorithm as unknown as AlgorithmIdentifier, false, [
        'sign',
        'verify',
      ])) as CryptoKeyPair

      const signature = await crypto.subtle.sign(algorithm as unknown as AlgorithmIdentifier, key.privateKey, message)

      const isValid = await crypto.subtle.verify(
        algorithm as unknown as AlgorithmIdentifier,
        key.publicKey,
        signature,
        message
      )

      assert(isValid)
    })
  })
