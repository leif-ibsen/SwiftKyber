//
//  KeysTest.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import XCTest
@testable import SwiftKyber

final class KeysTest: XCTestCase {

    func doTest(_ kyber: Kyber) throws {
        let (pk, sk) = kyber.GenerateKeyPair()
        XCTAssertEqual(pk, sk.publicKey)
        XCTAssertEqual(pk.bytes, pk.t + pk.rho)
        XCTAssertEqual(sk.bytes, sk.s + sk.t + sk.rho + sk.h + sk.z)
        let pkPem = pk.pem
        let pkDer = pk.der
        let pk1 = try PublicKey(der: pkDer)
        let pk2 = try PublicKey(pem: pkPem)
        XCTAssertEqual(pk, pk1)
        XCTAssertEqual(pk, pk2)
        let skPem = sk.pem
        let skDer = sk.der
        let sk1 = try SecretKey(der: skDer)
        let sk2 = try SecretKey(pem: skPem)
        XCTAssertEqual(sk, sk1)
        XCTAssertEqual(sk, sk2)
    }

    func test() throws {
        try doTest(Kyber.K512)
        try doTest(Kyber.K768)
        try doTest(Kyber.K1024)
    }

}
