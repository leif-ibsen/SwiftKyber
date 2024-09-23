//
//  EncapDecapTest.swift
//  
//
//  Created by Leif Ibsen on 01/11/2023.
//

import XCTest
@testable import SwiftKyber

final class EncapDecapTest: XCTestCase {

    func doTest(_ kind: Kind) throws {
        for _ in 0 ..< 10 {
            let (encapKey, decapKey) = Kyber.GenerateKeyPair(kind: kind)
            let (K, cipherText) = encapKey.Encapsulate()
            let K1 = try decapKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

    func test512() throws {
        try doTest(.K512)
    }

    func test768() throws {
        try doTest(.K768)
    }

    func test1024() throws {
        try doTest(.K1024)
    }

}
