import * as core from 'webcrypto-core'
import { Ed25519Provider } from './Ed25519Provider'
import { EcdsaProvider } from './EcdsaProvider'
import { askarGetRandomValues } from './askar'
import { Sha1Provider } from './Sha1Provider'

class Subtle extends core.SubtleCrypto {
  public constructor() {
    super()

    this.providers.set(new EcdsaProvider())

    this.providers.set(new Ed25519Provider())

    this.providers.set(new Sha1Provider())
  }
}

export class Crypto extends core.Crypto {
  public subtle = new Subtle()

  public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    if (!ArrayBuffer.isView(array)) {
      throw new TypeError('Input is not an array buffer view')
    }
    const buffer = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
    askarGetRandomValues(buffer)
    return array
  }
}

export * from './types'
