# ``SwiftKyber``

## Overview

SwiftKyber is a Swift implementation of NIST FIPS 203 (Draft): Module-Lattice-based Key-Encapsulation Mechanism Standard, August 2023.

Its functionality encompasses:

* Generation of key pairs
* A key encapsulation function
* A key decapsulation function

SwiftKyber contains three Kyber instances: `Kyber.K512`, `Kyber.K768` and `Kyber.K1024` corresponding to the three instances defined in [FIPS 203].
> Important:
SwiftKyber requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

- <doc:Usage>
- <doc:HowItWorks>
- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:Dependencies>
- <doc:References>

