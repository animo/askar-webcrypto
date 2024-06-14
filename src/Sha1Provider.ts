import * as core from 'webcrypto-core'
import { sha1 } from '@noble/hashes/sha1'
import type { HashAlgorithm } from './types'

export class Sha1Provider extends core.ProviderCrypto {
  public name = 'SHA-1'
  public usages = []

  public override async onDigest(algorithm: HashAlgorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case 'SHA-1': {
        const hash = sha1(new Uint8Array(data))
        return hash.buffer
      }
      default:
        throw new Error(`Hashing algorithm: ${JSON.stringify(algorithm)} is not supported`)
    }
  }
}
