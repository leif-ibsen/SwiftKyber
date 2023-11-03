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
        let kyber = Kyber.K512
        for _ in 0 ..< 10 {
            let (publicKey, secretKey) = kyber.GenerateKeyPair()
            let (cipherText, K) = publicKey.Encapsulate()
            let K1 = try secretKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

    func test768() throws {
        let kyber = Kyber.K768
        for _ in 0 ..< 10 {
            let (publicKey, secretKey) = kyber.GenerateKeyPair()
            let (cipherText, K) = publicKey.Encapsulate()
            let K1 = try secretKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

    func test1024() throws {
        let kyber = Kyber.K1024
        for _ in 0 ..< 10 {
            let (publicKey, secretKey) = kyber.GenerateKeyPair()
            let (cipherText, K) = publicKey.Encapsulate()
            let K1 = try secretKey.Decapsulate(ct: cipherText)
            XCTAssertEqual(K, K1)
        }
    }

}
