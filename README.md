## SwiftKyber

SwiftKyber is a Swift implementation of NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard, August 13, 2024*.

Its functionality encompasses:

* Generation of key pairs
* A key encapsulation function
* A key decapsulation function

SwiftKyber contains three Kyber instances: Kyber.K512, Kyber.K768 and Kyber.K1024 corresponding to the three instances defined in FIPS 203.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftKyber/documentation/swiftkyber

The documentation is also available in the *SwiftKyber.doccarchive* file.

The KAT test vectors have been updated from the GitHub Rust Crypto site
to comply with the final specification.
