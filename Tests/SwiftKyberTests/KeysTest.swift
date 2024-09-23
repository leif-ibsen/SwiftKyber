//
//  KeysTest.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import XCTest
@testable import SwiftKyber

final class KeysTest: XCTestCase {

    func doTest(_ kind: Kind) throws {
        let (ek, dk) = Kyber.GenerateKeyPair(kind: kind)
        XCTAssertEqual(ek.keyBytes, dk.encapsulationKey.keyBytes)
        let newEk = try EncapsulationKey(keyBytes: ek.keyBytes)
        let newDk = try DecapsulationKey(keyBytes: dk.keyBytes)
        XCTAssertEqual(ek, newEk)
        XCTAssertEqual(dk, newDk)
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
