//
//  KAT512Test.swift
//  
//
//  Created by Leif Ibsen on 22/10/2023.
//

import XCTest
@testable import SwiftKyber
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestEncap: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestEncap", withExtension: "rsp")!
        makeEncapTests(&encapTests, try Data(contentsOf: url))
    }

    struct encapTest {
        let tcId: String
        let kind: Kind
        let ek: Bytes
        let dk: Bytes
        let c: Bytes
        let k: Bytes
        let m: Bytes
    }

    var encapTests: [encapTest] = []
    
    func makeEncapTests(_ tests: inout [encapTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(4)
            lines[j + 6].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let tcId = lines[j]
            let kind = Util.kyberKind(lines[j + 1])
            let ek = Base64.hex2bytes(lines[j + 2])!
            let dk = Base64.hex2bytes(lines[j + 3])!
            let c = Base64.hex2bytes(lines[j + 4])!
            let k = Base64.hex2bytes(lines[j + 5])!
            let m = Base64.hex2bytes(lines[j + 6])!
            tests.append(encapTest(tcId: tcId, kind: kind, ek: ek, dk: dk, c: c, k: k, m: m))
        }
    }

    func testEncap() {
        for t in encapTests {
            let kyber = Kyber(t.kind)
            let (k1, c) = kyber.ML_KEMEncaps_internal(t.ek, t.m)
            XCTAssertEqual(k1, t.k)
            XCTAssertEqual(c, t.c)
            let k2 = kyber.ML_KEMDecaps_internal(t.dk, t.c)
            XCTAssertEqual(k2, t.k)
        }
    }

}
