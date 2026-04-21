//
//  WycheproofTest.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 01/09/2025.
//

import XCTest
@testable import SwiftKyber
import Digest

// Test various edge cases
// Test vectors from Wycheproof mlkem_512_test.json, mlkem_768_test.json and mlkem_1024_test.json

final class WycheproofEdgeCaseTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "wycheproofEdgeCase", withExtension: "rsp")!
        makeEdgeCaseTests(try Data(contentsOf: url))
    }
    
    struct edgeCaseTest {
        let tcId: String
        let kind: Kind
        let seed: Bytes
        let ek: Bytes
        let c: Bytes
        let K: Bytes
    }

    var edgeCaseTests: [edgeCaseTest] = []
    
    func makeEdgeCaseTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(7)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let tcId = lines[j]
            let kind = Util.kyberKind(lines[j + 1])
            let seed = Base64.hex2bytes(lines[j + 2])!
            let ek = Base64.hex2bytes(lines[j + 3])!
            let c = Base64.hex2bytes(lines[j + 4])!
            let K = Base64.hex2bytes(lines[j + 5])!
            edgeCaseTests.append(edgeCaseTest(tcId: tcId, kind: kind, seed: seed, ek: ek, c: c, K: K))
        }
    }

    func testEdgeCase() throws {
        for t in edgeCaseTests {
            let (ek, dk) = try Kyber.DeriveKeyPair(kind: t.kind, ikm: t.seed)
            XCTAssertEqual(ek.keyBytes, t.ek)
            XCTAssertEqual(try dk.Decapsulate(ct: t.c), t.K)
        }
    }

}
