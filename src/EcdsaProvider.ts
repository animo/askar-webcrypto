import * as core from 'webcrypto-core'
import type {
  CryptoKeyPair,
  EcKeyGenParams,
  EcKeyImportParams,
  EcdsaParams,
  JsonWebKey,
  KeyFormat,
  KeyUsage,
} from './types'
import { AskarCryptoKey, assertIsAskarCryptoKey } from './CryptoKey'

export class EcdsaProvider extends core.EcdsaProvider {
  public async onSign(algorithm: EcdsaParams, key: AskarCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    assertIsAskarCryptoKey(key)
    return key.sign(algorithm, data)
  }

  public async onVerify(
    algorithm: EcdsaParams,
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
    const publicKey = new AskarCryptoKey({
      askarKey: privateKey.askarKey,
      type: 'public',
      usages: keyUsages,
      algorithm,
      extractable,
    })

    return {
      publicKey,
      privateKey,
    }
  }

  public async onExportKey(format: KeyFormat, key: AskarCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    assertIsAskarCryptoKey(key)
    return key.exportKey(format)
  }

  public async onImportKey(
    format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer,
    algorithm: EcKeyImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<AskarCryptoKey> {
    return AskarCryptoKey.importKey(format, keyData, algorithm, extractable, keyUsages)
  }
}
