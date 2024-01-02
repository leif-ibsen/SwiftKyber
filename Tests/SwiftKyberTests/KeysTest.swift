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
        let (ek, dk) = kyber.GenerateKeyPair()
        XCTAssertEqual(ek.keyBytes, dk.encapsulationKey.keyBytes)
        let newEk = try EncapsulationKey(keyBytes: ek.keyBytes)
        let newDk = try DecapsulationKey(keyBytes: dk.keyBytes)
        XCTAssertEqual(ek, newEk)
        XCTAssertEqual(dk, newDk)
    }

    func test() throws {
        try doTest(Kyber.K512)
        try doTest(Kyber.K768)
        try doTest(Kyber.K1024)
    }

}
