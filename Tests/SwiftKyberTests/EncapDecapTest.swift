//
//  EncapDecapTest.swift
//  
//
//  Created by Leif Ibsen on 01/11/2023.
//

import XCTest
@testable import SwiftKyber

final class EncapDecapTest: XCTestCase {

    func doTest(_ kyber: Kyber) throws {
        for _ in 0 ..< 10 {
            let (encapKey, decapKey) = kyber.GenerateKeyPair()
            let (K, cipherText) = encapKey.Encapsulate()
            let K1 = try decapKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

    func test512() throws {
        try doTest(Kyber.K512)
    }

    func test768() throws {
        try doTest(Kyber.K768)
    }

    func test1024() throws {
        try doTest(Kyber.K1024)
    }

}
