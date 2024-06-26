import type { CallbackCryptoKey } from './CallbackKey'
import type { JsonWebKey, KeyAlgorithm, KeyFormat, KeyImportParams, KeySignParams, KeyUsage } from './types'

export interface CryptoCallback<T> {
  sign: (key: CallbackCryptoKey<T>, message: Uint8Array, algorithm: KeySignParams) => Promise<Uint8Array>
  generate: (algorithm: KeyAlgorithm) => Promise<T>
  importKey: (
    format: KeyFormat,
    keyData: Uint8Array | JsonWebKey,
    algorithm: KeyImportParams,
    extractable: boolean,
    keyUsages: Array<KeyUsage>
  ) => Promise<CallbackCryptoKey<T>>
  exportKey: (format: KeyFormat, key: CallbackCryptoKey<T>) => Promise<JsonWebKey | Uint8Array>
  verify: (
    key: CallbackCryptoKey<T>,
    algorithm: KeySignParams,
    message: Uint8Array,
    signature: Uint8Array
  ) => Promise<boolean>
}
