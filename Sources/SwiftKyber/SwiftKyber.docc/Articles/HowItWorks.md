# How it Works

## 

Suppose Alice and Bob wish to share a secret key they can use as a symmetric encryption key:

* Alice generates a Kyber key pair, `encapKey` and `decapKey`. She sends `encapKey` to Bob
* Bob runs `encapKey.Encapsulate()` to generate a shared secret `K` and a cipher text `cipher`
* Bob sends `cipher` to Alice
* Alice runs `decapKey.Decapsulate(ct: cipher)` to generate the same shared secret `K`

### Example

```swift
import SwiftKyber

// Alice:
let (encapKey, decapKey) = Kyber.K512.GenerateKeyPair()

// Bob:
let (K1, cipher) = encapKey.Encapsulate()
print("Bob's K:  ", K1)
    
// Alice:
let K2 = try decapKey.Decapsulate(ct: cipher)
print("Alice's K:", K2)
```
giving (for example):
```swift
Bob's K:   [106, 169, 16, 187, 123, 157, 206, 223, 236, 143, 173, 180, 243, 130, 157, 122, 150, 68, 167, 31, 33, 246, 28, 150, 215, 182, 71, 72, 128, 37, 202, 17]
Alice's K: [106, 169, 16, 187, 123, 157, 206, 223, 236, 143, 173, 180, 243, 130, 157, 122, 150, 68, 167, 31, 33, 246, 28, 150, 215, 182, 71, 72, 128, 37, 202, 17]
```
