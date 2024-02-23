# ``SwiftKyber``

Module-Lattice-based Key-Encapsulation Mechanism Standard

## Overview

SwiftKyber is a Swift implementation of NIST FIPS 203 (Draft): *Module-Lattice-based Key-Encapsulation Mechanism Standard, August 2023*.

SwiftKyber contains three Kyber instances: `Kyber.K512`, `Kyber.K768` and `Kyber.K1024` corresponding to the three instances defined in [FIPS 203].

Its functionality encompasses:

* Generation of key pairs
* A key encapsulation function
* A key decapsulation function

### How it Works

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

### Usage

To use SwiftKyber, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftKyber", from: "2.3.0"),
]
```

SwiftKyber itself depends on the Digest package

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.3.0"),
],
```

> Important:
SwiftKyber requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Structures

- ``SwiftKyber/Kyber``
- ``SwiftKyber/EncapsulationKey``
- ``SwiftKyber/DecapsulationKey``

### Type Aliases

- ``SwiftKyber/Byte``
- ``SwiftKyber/Bytes``

### Enumerations

- ``SwiftKyber/KyberException``

### Additional Information

- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:References>
