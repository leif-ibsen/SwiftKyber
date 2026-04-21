//
//  WycheproofTest.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 01/09/2025.
//

import XCTest
@testable import SwiftKyber
import Digest

// Test encapsulation edge cases
// Test vectors from Wycheproof mlkem_512_encaps_test.json, mlkem_768_encaps_test.json and mlkem_1024_encaps_test.json

final class WycheproofEncapTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "wycheproofEncap", withExtension: "rsp")!
        makeEncapTests(try Data(contentsOf: url))
    }
    
    struct encapTest {
        let tcId: String
        let kind: Kind
        let ek: Bytes
        let m: Bytes
        let c: Bytes
        let K: Bytes
    }

    var encapTests: [encapTest] = []
    
    func makeEncapTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(4)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let tcId = lines[j]
            let kind = Util.kyberKind(lines[j + 1])
            let ek = Base64.hex2bytes(lines[j + 2])!
            let m = Base64.hex2bytes(lines[j + 3])!
            let c = Base64.hex2bytes(lines[j + 4])!
            let K = Base64.hex2bytes(lines[j + 5])!
            encapTests.append(encapTest(tcId: tcId, kind: kind, ek: ek, m: m, c: c, K: K))
        }
    }

    func testEncap() throws {
        for t in encapTests {
            let kyber = Kyber(t.kind)
            let (k, c) = kyber.ML_KEMEncaps_internal(t.ek, t.m)
            XCTAssertEqual(k, t.K)
            XCTAssertEqual(c, t.c)
        }
    }

}
