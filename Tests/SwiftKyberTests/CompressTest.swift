//
//  CompressTest.swift
//  
//
//  Created by Leif Ibsen on 09/11/2023.
//

import XCTest
@testable import SwiftKyber

final class CompressTest: XCTestCase {

    func RoundQ(_ x: Int) -> Int {
        let (q, r) = Kyber.Q.quotientAndRemainder(dividingBy: x)
        return r * 2 >= x ? q + 1 : q
    }

    func modPM(_ r: Int) -> Int {
        var x = r % Kyber.Q
        if r < 0 {
            x += Kyber.Q
        }
        return x > (Kyber.Q - 1) / 2 ? x - Kyber.Q : x
    }

    func test() throws {
        for _ in 0 ..< 1000 {
            let x = Int.random(in: 0 ..< Kyber.Q)
            for d in 0 ..< 12 {
                let c = Kyber.K512.Compress(x, d)
                XCTAssertTrue(0 <= c && c < 1 << d)
                let x1 = Kyber.K512.Decompress(c, d)
                XCTAssertTrue(Swift.abs(modPM(x1 - x)) <= RoundQ(1 << (d + 1)))
            }
        }
    }

}
