//
//  ML_KEMInternalTest.swift
//  
//
//  Created by Leif Ibsen on 18/08/2024.
//

import XCTest
@testable import SwiftKyber

final class ML_KEMInternalTest: XCTestCase {

    func doTest(_ kyber: Kyber) {
        var d = Bytes(repeating: 0, count: 32)
        var z = Bytes(repeating: 0, count: 32)
        Util.randomBytes(&d)
        Util.randomBytes(&z)
        let (ek, dk) = kyber.ML_KEMKeyGen_internal(d, z)
        var m = Bytes(repeating: 0, count: 32)
        Util.randomBytes(&m)
        let (K, c) = kyber.ML_KEMEncaps_internal(ek, m)
        let K1 = kyber.ML_KEMDecaps_internal(dk, c)
        XCTAssertEqual(K, K1)
    }

    func test512() throws {
        doTest(Kyber.K512)
    }

    func test768() throws {
        doTest(Kyber.K768)
    }

    func test1024() throws {
        doTest(Kyber.K1024)
    }

}
