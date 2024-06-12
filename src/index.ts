import * as core from 'webcrypto-core'
import { Ed25519Provider } from './Ed25519Provider'
import { EcdsaProvider } from './EcdsaProvider'

class Subtle extends core.SubtleCrypto {
  public constructor() {
    super()

    this.providers.set(new EcdsaProvider())

    this.providers.set(new Ed25519Provider())
  }
}

export class Crypto extends core.Crypto {
  public subtle = new Subtle()

  public getRandomValues<T extends ArrayBufferView | null>(_array: T): T {
    throw new Error('getRandomValues is not implemented')
  }
}

export * from './types'
