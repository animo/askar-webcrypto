import * as core from 'webcrypto-core'
import { askarKeyGenerate, askarKeySign, askarKeyVerify } from './askar'
import type { CryptoKeyPair } from './types'

export class Ed25519Provider extends core.Ed25519Provider {
  public async onSign(_algorithm: string, key: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return askarKeySign(key, data)
  }

  public async onVerify(
    _algorithm: string,
    key: core.CryptoKey,
    signature: ArrayBuffer,
    data: ArrayBuffer
  ): Promise<boolean> {
    return askarKeyVerify(key, data, signature)
  }

  public async onGenerateKey(
    algorithm: { name: string },
    _extractable: boolean,
    _keyUsages: string[]
  ): Promise<CryptoKeyPair> {
    return askarKeyGenerate(algorithm.name)
  }
}
