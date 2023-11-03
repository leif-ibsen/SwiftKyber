//
//  NTTTest.swift
//  
//
//  Created by Leif Ibsen on 17/10/2023.
//

import XCTest
@testable import SwiftKyber

final class NTTTest: XCTestCase {

    func randomInts(_ ints: inout [Int]) {
        guard SecRandomCopyBytes(kSecRandomDefault, 8 * ints.count, &ints) == errSecSuccess else {
            fatalError("randomInts failed")
        }
    }

    func test1() throws {
        var x = [Int](repeating: 0, count: 256)
        for _ in 0 ..< 100 {
            randomInts(&x)
            for i in 0 ..< 256 {
                x[i] = abs(x[i]) % Kyber.Q
            }
            var p = Polynomial(x)
            let p1 = p
            p = p.NTT()
            p = p.INTT()
            XCTAssertEqual(p, p1)
        }
    }

    func test2() throws {
        var x = [Int](repeating: 0, count: 256)
        for _ in 0 ..< 100 {
            randomInts(&x)
            for i in 0 ..< 256 {
                x[i] = abs(x[i]) % Kyber.Q
            }
            var p = Polynomial(x)
            let p1 = p
            p = p.INTT()
            p = p.NTT()
            XCTAssertEqual(p, p1)
        }
    }

}
