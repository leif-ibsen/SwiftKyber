//
//  K_PKETest.swift
//  
//
//  Created by Leif Ibsen on 18/08/2024.
//

import XCTest
@testable import SwiftKyber

final class K_PKETest: XCTestCase {

    func doTest(_ kind: Kind) {
        let kyber = Kyber(kind)
        for _ in 0 ..< 10 {
            var d = Bytes(repeating: 0, count: 32)
            Util.randomBytes(&d)
            let (ek, dk) = kyber.K_PKEKeyGen(d)
            var m = Bytes(repeating: 1, count: 32)
            Util.randomBytes(&m)
            var r = Bytes(repeating: 0, count: 32)
            Util.randomBytes(&r)
            let c = kyber.K_PKEEncrypt(ek, m, r)
            let m1 = kyber.K_PKEDecrypt(dk, c)
            XCTAssertEqual(m, m1)
        }
    }

    func test512() throws {
        doTest(.K512)
    }

    func test768() throws {
        doTest(.K768)
    }

    func test1024() throws {
        doTest(.K1024)
    }

}
