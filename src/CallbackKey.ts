import * as core from 'webcrypto-core'
import type { KeyAlgorithm, KeyType, KeyUsage } from './types'

export class CallbackCryptoKey<T> extends core.CryptoKey {
  public constructor(
    public key: T,
    public override algorithm: KeyAlgorithm,
    public override extractable: boolean,
    public override type: KeyType,
    public override usages: Array<KeyUsage>
  ) {
    super()
  }
}
