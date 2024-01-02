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
SwiftKyber is a Swift implementation of NIST FIPS 203 (Draft): *Module-Lattice-based Key-Encapsulation Mechanism Standard, August 2023*.
<h2 id="use"><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftKyber", from: "2.0.0"),
	  ]
<h2 id="basic"><b>How it Works</b></h2>
Suppose Alice and Bob wish to share a secret key they can use as a symmetric encryption key:<br/>
<ul>
<li>Alice generates a Kyber key pair, <i>encapKey</i> and <i>decapKey</i>. She sends <i>encapKey</i> to Bob</li>
<li>Bob runs <i>encapKey.Encapsulate()</i> to generate a shared secret <i>K</i> and a cipher text <i>cipher</i></li>
<li>Bob sends <i>cipher</i> to Alice</li>
<li>Alice runs <i>decapKey.Decapsulate(ct: cipher)</i> to generate the same shared secret <i>K</i></li>
</ul>
SwiftKyber contains three static Kyber instances: *Kyber.K512*, *Kyber.K768* and *Kyber.K1024*
corresponding to the three instances defined in FIPS 203.<br/>

Here is a *Kyber.K512* example:

    import SwiftKyber

    // Alice:
    let (encapKey, decapKey) = Kyber.K512.GenerateKeyPair()
    
    // Bob:
    let (K1, cipher) = encapKey.Encapsulate()
    print("Bob's K:  ", K1)
    
    // Alice:
    let K2 = try decapKey.Decapsulate(ct: cipher)
    print("Alice's K:", K2)

giving (for example):

    Bob's K:   [106, 169, 16, 187, 123, 157, 206, 223, 236, 143, 173, 180, 243, 130, 157, 122, 150, 68, 167, 31, 33, 246, 28, 150, 215, 182, 71, 72, 128, 37, 202, 17]
    Alice's K: [106, 169, 16, 187, 123, 157, 206, 223, 236, 143, 173, 180, 243, 130, 157, 122, 150, 68, 167, 31, 33, 246, 28, 150, 215, 182, 71, 72, 128, 37, 202, 17]

<h2 id="key"><b>Key Representation</b></h2>
SwiftKyber keys can be stored as raw bytes and later recreated from the stored bytes.

Example:

    import SwiftKyber
    
    let (encapKey, decapKey) = Kyber.K768.GenerateKeyPair()

	let encapKeyBytes = encapKey.keyBytes
	let decapKeyBytes = decapKey.keyBytes
	
	let newEncapKey = try EncapsulationKey(keyBytes: encapKeyBytes)
	let newDecapKey = try DecapsulationKey(keyBytes: decapKeyBytes)
	
	// newEncapKey is now equal to encapKey and newDecapKey is equal to decapKey
	
	assert(newEncapKey == encapKey)
	assert(newDecapKey == decapKey)

<h2 id="perf"><b>Performance</b></h2>
SwiftKyber's key generation, encapsulation and decapsulation performance was measured on an iMac 2021, Apple M1 chip.
The table below shows the times in milli seconds for the three Kyber instances.
<table width="75%">
<tr><th align="left" width="25%">Instance</th><th align="right" width="25%">GenerateKeyPair</th><th align="right" width="20%">Encapsulate</th><th align="right" width="20%">Decapsulate</th></tr>
<tr><td>Kyber.K512</td><td align="right">0.15 mSec</td><td align="right">0.13 mSec</td><td align="right">0.18 mSec</td></tr>
<tr><td>Kyber.K768</td><td align="right">0.24 mSec</td><td align="right">0.21 mSec</td><td align="right">0.27 mSec</td></tr>
<tr><td>Kyber.K1024</td><td align="right">0.36 mSec</td><td align="right">0.32 mSec</td><td align="right">0.39 mSec</td></tr>
</table>

<h2 id="dep"><b>Dependencies</b></h2>
The SwiftKyber package depends on the Digest package

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.1.0"),
    ],
<h2 id="ref"><b>References</b></h2>

Algorithms from the below paper have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[FIPS203] - Module-Lattice-based Key-Encapsulation Mechanism Standard, August 2023</li>
</ul>
