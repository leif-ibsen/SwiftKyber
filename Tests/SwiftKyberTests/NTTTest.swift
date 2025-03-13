//
//  NTTTest.swift
//  
//
//  Created by Leif Ibsen on 17/10/2023.
//

import XCTest
@testable import SwiftKyber

final class NTTTest: XCTestCase {

    // Schoolbook polynomial multiplication in Z[X]/(X^256 + 1)
    // KNUTH - section 4.6.1
    func mulP(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var u = [Int](repeating: 0, count: 512)
        var q = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            for j in 0 ..< 256 {
                u[i + j] += p1.coefficients[i] * p2.coefficients[j]
            }
        }
        for i in 0 ..< 512 {
            u[i] = u[i] % Kyber.Q
        }
        for k in (0 ..< 256).reversed() {
            q[k] = u[256 + k]
            u[k + 256] -= q[k]
            u[k] -= q[k]
        }
        // u = remainder dividing u by X^256 + 1
        return Polynomial([Int](u[0 ..< 256]))
    }

    func test1() throws {
        var x = [Int](repeating: 0, count: 256)
        for _ in 0 ..< 100 {
            Util.randomInts(&x)
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
            Util.randomInts(&x)
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

    func test3() throws {
        var x1 = [Int](repeating: 0, count: 256)
        var x2 = [Int](repeating: 0, count: 256)
        for _ in 0 ..< 100 {
            Util.randomInts(&x1)
            Util.randomInts(&x2)
            for i in 0 ..< 256 {
                x1[i] = abs(x1[i]) % Kyber.Q
                x2[i] = abs(x2[i]) % Kyber.Q
            }
            let p1 = Polynomial(x1)
            let p2 = Polynomial(x2)

            // Schoolbook multiplication in Z[X]/(X^256 + 1)
            let px = mulP(p1, p2)

            // NTT multiplication
            let py = (p1.NTT() * p2.NTT()).INTT()
        
            // Results must be equal modulo Kyber.Q
            for i in 0 ..< 256 {
                XCTAssertTrue((px.coefficients[i] - py.coefficients[i]) % Kyber.Q == 0)
            }
        }
    }

}
