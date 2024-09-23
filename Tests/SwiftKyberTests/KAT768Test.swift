//
//  KAT768Test.swift
//  
//
//  Created by Leif Ibsen on 21/12/2023.
//

import XCTest
@testable import SwiftKyber

final class KAT768Test: XCTestCase {

    // Test vectors from the GitHub Rust Crypto site

    override func setUpWithError() throws {
        let url1 = Bundle.module.url(forResource: "kat768KeyGen", withExtension: "rsp")!
        Util.makeKeyGenTests(&keyGenTests, try Data(contentsOf: url1))
        let url2 = Bundle.module.url(forResource: "kat768EncapDecap", withExtension: "rsp")!
        Util.makeEncapDecapTests(&encapDecapTests, try Data(contentsOf: url2))
    }

    var keyGenTests: [Util.keyGenTest] = []
    var encapDecapTests: [Util.encapDecapTest] = []

    func testKeyGen() throws {
        let kyber = Kyber(Kind.K768)
        for t in keyGenTests {
            let (ek, dk) = kyber.ML_KEMKeyGen_internal(t.d, t.z)
            XCTAssertEqual(ek, t.ek)
            XCTAssertEqual(dk, t.dk)
        }
    }
    
    func testEncapDecap() throws {
        let kyber = Kyber(Kind.K768)
        for t in encapDecapTests {
            let (k1, c) = kyber.ML_KEMEncaps_internal(t.ek, t.m)
            XCTAssertEqual(k1, t.k)
            XCTAssertEqual(c, t.c)
            let k2 = kyber.ML_KEMDecaps_internal(t.dk, t.c)
            XCTAssertEqual(k2, t.k)
        }
    }

}
