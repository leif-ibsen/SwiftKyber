# ``SwiftKyber``

Module-Lattice-Based Key-Encapsulation Mechanism Standard

## Overview

SwiftKyber is a Swift implementation of NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard, August 13, 2024*.

SwiftKyber functionality:

* Support for the three Kyber kinds defined in [FIPS 203]
* Generation of key pairs
* A key encapsulation function
* A key decapsulation function

### Usage

To use SwiftKyber, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftKyber", from: "3.0.0"),
]
```

SwiftKyber itself depends on the [ASN1](https://leif-ibsen.github.io/ASN1/documentation/asn1), [BigInt](https://leif-ibsen.github.io/BigInt/documentation/bigint) and [Digest](https://leif-ibsen.github.io/Digest/documentation/digest) packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.6.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.19.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.8.0"),
],
```

SwiftKyber doesn't do big integer arithmetic, but the ASN1 package depends on the BigInt package.

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

- ``SwiftKyber/Kind``
- ``SwiftKyber/Exception``

### Additional Information

- <doc:HowItWorks>
- <doc:KeyManagement>
- <doc:OIDs>
- <doc:Performance>
- <doc:References>
