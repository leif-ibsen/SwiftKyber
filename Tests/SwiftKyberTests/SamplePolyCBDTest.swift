//
//  SamplePolyCBDTest.swift
//  
//
//  Created by Leif Ibsen on 18/08/2024.
//

import XCTest
@testable import SwiftKyber

final class SamplePolyCBDTest: XCTestCase {

    func doTest(_ eta: Int) {
        var B = Bytes(repeating: 0, count: eta * 64)
        Util.randomBytes(&B)
        let f = Kyber.SamplePolyCBD(B, eta)
        XCTAssertTrue(f.coefficients.count == 256)
        for i in 0 ..< 256 {
            let x = f.coefficients[i]
            XCTAssertTrue((0 <= x && x <= eta) || (Kyber.Q - eta <= x && x < Kyber.Q))
        }
    }

    func test() throws {
        doTest(2)
        doTest(3)
    }

}
