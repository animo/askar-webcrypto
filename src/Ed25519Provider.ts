import * as core from 'webcrypto-core'
import type { CryptoKeyPair, EcKeyGenParams, KeySignParams, KeyUsage } from './types'
import { AskarCryptoKey, assertIsAskarCryptoKey } from './CryptoKey'

export class Ed25519Provider extends core.Ed25519Provider {
  public async onSign(algorithm: KeySignParams, key: AskarCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    assertIsAskarCryptoKey(key)
    return key.sign(algorithm, data)
  }

  public async onVerify(
    algorithm: KeySignParams,
    key: AskarCryptoKey,
    signature: ArrayBuffer,
    data: ArrayBuffer
  ): Promise<boolean> {
    assertIsAskarCryptoKey(key)
    return key.verify(algorithm, signature, data)
  }

  public async onGenerateKey(
    algorithm: EcKeyGenParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKeyPair> {
    const privateKey = AskarCryptoKey.create(algorithm, 'private', extractable, keyUsages)

    // Create a public key from the private as internally they refer to the same key
    const publicKey = new AskarCryptoKey({
      askarKey: privateKey.askarKey,
      extractable,
      algorithm,
      usages: keyUsages,
      type: 'public',
    })

    return {
      publicKey,
      privateKey,
    }
  }
}
