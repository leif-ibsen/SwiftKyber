# Key Representation

SwiftKyber keys can be stored as raw bytes and later recreated from the stored bytes

## 

### Example

```swift
import SwiftKyber

let (encapKey, decapKey) = Kyber.K768.GenerateKeyPair()

let encapKeyBytes = encapKey.keyBytes
let decapKeyBytes = decapKey.keyBytes

let newEncapKey = try EncapsulationKey(keyBytes: encapKeyBytes)
let newDecapKey = try DecapsulationKey(keyBytes: decapKeyBytes)

// newEncapKey is now equal to encapKey and newDecapKey is equal to decapKey

assert(newEncapKey == encapKey)
assert(newDecapKey == decapKey)
```
