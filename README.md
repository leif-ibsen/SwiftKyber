<h2><b>SwiftKyber</b></h2>
<h3><b>Contents:</b></h3>
<ul>
<li><a href="#use">Usage</a></li>
<li><a href="#basic">How it Works</a></li>
<li><a href="#key">Key Representation</a></li>
<li><a href="#perf">Performance</a></li>
<li><a href="#dep">Dependencies</a></li>
<li><a href="#ref">References</a></li>
</ul>
SwiftKyber is a Swift implementation of the proposed PQC (Post Quantum Cryptography)
key encapsulation mechanism: CRYSTALS-Kyber.

SwiftKyber makes it possible to explore CRYSTALS-Kyber in a Swift context.
<h2 id="use"><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftKyber", from: "1.1.0"),
	  ]
<h2 id="basic"><b>How it Works</b></h2>
Suppose Alice and Bob wish to share a secret key they can use as a symmetric encryption key:<br/>
<ul>
<li>Alice generates a Kyber key pair, <i>publicKey</i> and <i>secretKey</i>. She sends <i>publicKey</i> to Bob</li>
<li>Bob runs <i>publicKey.Encapsulate()</i> to generate a shared secret <i>K</i> and a cipher text <i>cipher</i></li>
<li>Bob sends <i>cipher</i> to Alice</li>
<li>Alice runs <i>secretKey.Decapsulate(ct: cipher)</i> to generate the same shared secret <i>K</i></li>
</ul>
SwiftKyber contains three static Kyber instances: *Kyber.K512*, *Kyber.K768* and *Kyber.K1024*
corresponding to the three instances defined in the Kyber specification.<br/>

Here is a *Kyber.K512* example:

    import SwiftKyber

    // Alice:
    let (publicKey, secretKey) = Kyber.K512.GenerateKeyPair()
    
    // Bob:
    let (cipher, K1) = publicKey.Encapsulate()
    print("Bob's K:  ", K1)
    
    // Alice:
    let K2 = try secretKey.Decapsulate(ct: cipher)
    print("Alice's K:", K2)

giving (for example):

    Bob's K:   [106, 169, 16, 187, 123, 157, 206, 223, 236, 143, 173, 180, 243, 130, 157, 122, 150, 68, 167, 31, 33, 246, 28, 150, 215, 182, 71, 72, 128, 37, 202, 17]
    Alice's K: [106, 169, 16, 187, 123, 157, 206, 223, 236, 143, 173, 180, 243, 130, 157, 122, 150, 68, 167, 31, 33, 246, 28, 150, 215, 182, 71, 72, 128, 37, 202, 17]

<h2 id="key"><b>Key Representation</b></h2>
SwiftKyber public and secret keys can be stored in three formats:
<ul>
<li>DER encoded - a byte array</li>
<li>PEM encoded - a string</li>
<li>As raw bytes</li>
</ul>
The three main key management operations are:
<ul>
<li>Generate new keys</li>
<li>Store existing keys in DER or PEM format or as raw bytes</li>
<li>Load keys from their DER or PEM encoding or from their raw bytes</li>
</ul>
Generating new keys is easy:

    import SwiftKyber
    
    let (pk, sk) = Kyber.K768.GenerateKeyPair()

generates a new public key *pk* and a new secret key *sk* for the K768 instance.<br/>
Keys can be stored in DER format, in PEM format or as raw bytes.

    import SwiftKyber
    
    let (pk, _) = Kyber.K512.GenerateKeyPair()
    
    let pkDer = pk.der // The DER encoding - a byte array
    let pkPem = pk.pem // The PEM encoding - a String
    let pkBytes = pk.bytes // The raw bytes
    
    let newPkFromDER = try PublicKey(der: pkDer)
    let newPkFromPEM = try PublicKey(pem: pkPem)
    let newPkFromRaw = try PublicKey(bytes: pkBytes)
    
    assert(pk == newPkFromDER)
    assert(pk == newPkFromPEM)
    assert(pk == newPkFromRaw)

and for secret keys:

    import SwiftKyber
    
    let (_, sk) = Kyber.K512.GenerateKeyPair()
    
    let skDer = sk.der // The DER encoding - a byte array
    let skPem = sk.pem // The PEM encoding - a String
    let skBytes = sk.bytes // The raw bytes
    
    let newSkFromDER = try SecretKey(der: skDer)
    let newSkFromPEM = try SecretKey(pem: skPem)
    let newSkFromRaw = try SecretKey(bytes: skBytes)
    
    assert(sk == newSkFromDER)
    assert(sk == newSkFromPEM)
    assert(sk == newSkFromRaw)

<h3><b>ASN1 reservations</b></h3>
The DER and PEM formats are based on the ASN1 structure of the keys.
These structures are defined in [KEYS], but it is my understanding that the ASN1 representation is not settled yet:
It may change, there may be no ASN1 structure at all or I may have misread [KEYS].

<h2 id="perf"><b>Performance</b></h2>
SwiftKyber's key generation, encapsulation and decapsulation performance was measured on an iMac 2021, Apple M1 chip.
The table below shows the figures in milli seconds for the three Kyber instances.
<table width="75%">
<tr><th align="left" width="25%">Kyber Instance</th><th align="right" width="25%">GenerateKeyPair</th><th align="right" width="20%">Encapsulate</th><th align="right" width="20%">Decapsulate</th></tr>
<tr><td>Kyber.K512</td><td align="right">0.21 mSec</td><td align="right">0.22 mSec</td><td align="right">0.25 mSec</td></tr>
<tr><td>Kyber.K768</td><td align="right">0.36 mSec</td><td align="right">0.38 mSec</td><td align="right">0.42 mSec</td></tr>
<tr><td>Kyber.K1024</td><td align="right">0.57 mSec</td><td align="right">0.58 mSec</td><td align="right">0.64 mSec</td></tr>
</table>

<h2 id="dep"><b>Dependencies</b></h2>
The SwiftKyber package depends on the ASN1 and BigInt packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.2.0"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.14.0"),
    ],
    
SwiftKyber does not do Big Integer arithmetic, but BigInt is a dependency because ASN1 depends on it.

<h2 id="ref"><b>References</b></h2>

Algorithms from the following papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[KYBER] - CRYSTALS-Kyber, Algorithm Specifications And Supporting Documentation, January 2021</li>
<li>[DRAFT] - Kyber Post-Quantum KEM, draft-cfrg-schwabe-kyber-03, September 2023</li>
<li>[KEYS] - Quantum Safe Cryptography Key Information for CRYSTALS-Kyber, October 2022</li>
</ul>
