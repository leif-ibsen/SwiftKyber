## SwiftKyber

SwiftKyber is a Swift implementation of NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard, August 13, 2024*.

Its functionality encompasses:

* Support for the three Kyber kinds defined in the standard
* Create encapsulation keys and decapsulation keys
* A key encapsulation function
* A key decapsulation function
* Store keys in their PEM encoded ASN1 representation
* Recreate keys from their PEM encoded ASN1 representation

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftKyber/documentation/swiftkyber

The documentation is also available in the *SwiftKyber.doccarchive* file.

The KAT test vectors come from NIST ACVP-server version 1.1.0.38 to comply with the final specification.
