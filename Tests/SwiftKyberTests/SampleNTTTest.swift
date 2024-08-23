//
//  SampleNTTTest.swift
//  
//
//  Created by Leif Ibsen on 18/08/2024.
//

import XCTest
@testable import SwiftKyber

final class SampleNTTTest: XCTestCase {

    func test() throws {
        var B = Bytes(repeating: 0, count: 34)
        Util.randomBytes(&B)
        let a = Kyber.SampleNTT(B)
        XCTAssertTrue(a.coefficients.count == 256)
        for i in 0 ..< 256 {
            XCTAssertTrue(0 <= a.coefficients[i] && a.coefficients[i] < Kyber.Q)
        }
    }

}
