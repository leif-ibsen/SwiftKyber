//
//  EncapDecapTest.swift
//  
//
//  Created by Leif Ibsen on 01/11/2023.
//

import XCTest
@testable import SwiftKyber

final class EncapDecapTest: XCTestCase {

    func test512() throws {
        for _ in 0 ..< 10 {
            let (encapKey, decapKey) = Kyber.K512.GenerateKeyPair()
            let (K, cipherText) = encapKey.Encapsulate()
            let K1 = try decapKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

    func test768() throws {
        for _ in 0 ..< 10 {
            let (encapKey, decapKey) = Kyber.K768.GenerateKeyPair()
            let (K, cipherText) = encapKey.Encapsulate()
            let K1 = try decapKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

    func test1024() throws {
        for _ in 0 ..< 10 {
            let (encapKey, decapKey) = Kyber.K1024.GenerateKeyPair()
            let (K, cipherText) = encapKey.Encapsulate()
            let K1 = try decapKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

}
