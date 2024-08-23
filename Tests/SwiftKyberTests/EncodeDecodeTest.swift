//
//  EncodeDecodeTest.swift
//  
//
//  Created by Leif Ibsen on 18/08/2024.
//

import XCTest
@testable import SwiftKyber

final class EncodeDecodeTest: XCTestCase {

    func test() throws {
        var F = [Int](repeating: 0, count: 256)
        for d in 1 ... 12 {
            Util.randomInts(&F)
            for i in 0 ..< 256 {
                F[i] = (F[i] & (1 << d - 1)) % Kyber.Q
            }
            let B = Kyber.ByteEncode(F, d)
            XCTAssertTrue(B.count == d * 32)
            let F1 = Kyber.ByteDecode(B, d)
            XCTAssertEqual(F, F1)
        }
    }

}
