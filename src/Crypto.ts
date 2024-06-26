import * as core from 'webcrypto-core'
import { askarGetRandomValues } from './askar'
import { EcdsaCallbackProvider } from './EcdsaCallbackProvider'
import type { CryptoCallback } from './CryptoCallback'

class Subtle<T> extends core.SubtleCrypto {
  public constructor(callbacks: CryptoCallback<T>) {
    super()

    this.providers.set(new EcdsaCallbackProvider(callbacks))
  }
}

export class Crypto<T> extends core.Crypto {
  public subtle: Subtle<T>

  public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    if (!ArrayBuffer.isView(array)) {
      throw new TypeError('Input is not an array buffer view')
    }
    const buffer = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
    askarGetRandomValues(buffer)
    return array
  }

  public constructor(callbacks: CryptoCallback<T>) {
    super()

    this.subtle = new Subtle(callbacks)
  }
}
