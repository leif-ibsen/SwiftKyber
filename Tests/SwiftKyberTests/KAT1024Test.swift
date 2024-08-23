//
//  KAT1024Test.swift
//  
//
//  Created by Leif Ibsen on 21/12/2023.
//

import XCTest
@testable import SwiftKyber

final class KAT1024Test: XCTestCase {

    // Test vectors from the GitHub Rust Crypto site

    override func setUpWithError() throws {
        let url1 = Bundle.module.url(forResource: "kat1024KeyGen", withExtension: "rsp")!
        Util.makeKeyGenTests(&keyGenTests, try Data(contentsOf: url1))
        let url2 = Bundle.module.url(forResource: "kat1024EncapDecap", withExtension: "rsp")!
        Util.makeEncapDecapTests(&encapDecapTests, try Data(contentsOf: url2))
    }

    var keyGenTests: [Util.keyGenTest] = []
    var encapDecapTests: [Util.encapDecapTest] = []

    func testKeyGen() throws {
        for t in keyGenTests {
            let (ek, dk) = Kyber.K1024.ML_KEMKeyGen_internal(t.d, t.z)
            XCTAssertEqual(ek, t.ek)
            XCTAssertEqual(dk, t.dk)
        }
    }

    func testEncapDecap() throws {
        for t in encapDecapTests {
            let (k1, c) = Kyber.K1024.ML_KEMEncaps_internal(t.ek, t.m)
            XCTAssertEqual(k1, t.k)
            XCTAssertEqual(c, t.c)
            let k2 = Kyber.K1024.ML_KEMDecaps_internal(t.dk, t.c)
            XCTAssertEqual(k2, t.k)
        }
    }

}
