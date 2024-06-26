import * as core from 'webcrypto-core'
import { CallbackCryptoKey } from './CallbackKey'
import type { CryptoCallback } from './CryptoCallback'
import type {
  CallbackCryptoKeyPair,
  EcKeyGenParams,
  EcKeyImportParams,
  EcdsaParams,
  JsonWebKey,
  KeyFormat,
  KeyUsage,
} from './types'

export class EcdsaCallbackProvider<T> extends core.EcdsaProvider {
  public constructor(private callbacks: CryptoCallback<T>) {
    super()
  }

  public async onSign(algorithm: EcdsaParams, key: CallbackCryptoKey<T>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.callbacks.sign(key, new Uint8Array(data), algorithm)
  }

  public async onVerify(
    algorithm: EcdsaParams,
    key: CallbackCryptoKey<T>,
    signature: ArrayBuffer,
    data: ArrayBuffer
  ): Promise<boolean> {
    return this.callbacks.verify(key, algorithm, new Uint8Array(data), new Uint8Array(signature))
  }

  public async onGenerateKey(
    algorithm: EcKeyGenParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CallbackCryptoKeyPair<T>> {
    const key: T = await this.callbacks.generate(algorithm)

    return {
      publicKey: new CallbackCryptoKey(key, algorithm, extractable, 'public', keyUsages),
      privateKey: new CallbackCryptoKey(key, algorithm, extractable, 'private', keyUsages),
    }
  }

  public async onExportKey(format: KeyFormat, key: CallbackCryptoKey<T>): Promise<JsonWebKey | ArrayBuffer> {
    return this.callbacks.exportKey(format, key)
  }

  public async onImportKey(
    format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer,
    algorithm: EcKeyImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CallbackCryptoKey<T>> {
    return this.callbacks.importKey(
      format,
      ArrayBuffer.isView(keyData) ? new Uint8Array(keyData as ArrayBuffer) : (keyData as JsonWebKey),
      algorithm,
      extractable,
      keyUsages
    )
  }
}
