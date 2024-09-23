//
//  PEMTest.swift
//  
//
//  Created by Leif Ibsen on 18/09/2024.
//

import XCTest
@testable import SwiftKyber

final class PEMTest: XCTestCase {

    func doTest(_ kind: Kind) throws {
        let (encap, decap) = Kyber.GenerateKeyPair(kind: kind)
        let encap1 = try EncapsulationKey(pem: encap.pem)
        let decap1 = try DecapsulationKey(pem: decap.pem)
        XCTAssertEqual(encap, encap1)
        XCTAssertEqual(decap, decap1)
    }

    func testK512() throws {
        try doTest(.K512)
    }

    func testK768() throws {
        try doTest(.K768)
    }

    func testK1024() throws {
        try doTest(.K1024)
    }

}
