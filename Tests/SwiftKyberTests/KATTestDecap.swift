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

final class KATTestDecap: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestDecap", withExtension: "rsp")!
        makeDecapTests(try Data(contentsOf: url))
    }

    struct decapTest {
        let tcId: String
        let kind: Kind
        let ek: Bytes
        let dk: Bytes
        let c: Bytes
        let k: Bytes
    }

    var decapTests: [decapTest] = []
    
    func makeDecapTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let tcId = lines[j]
            let kind = Util.kyberKind(lines[j + 1])
            let ek = Base64.hex2bytes(lines[j + 2])!
            let dk = Base64.hex2bytes(lines[j + 3])!
            let c = Base64.hex2bytes(lines[j + 4])!
            let k = Base64.hex2bytes(lines[j + 5])!
            decapTests.append(decapTest(tcId: tcId, kind: kind, ek: ek, dk: dk, c: c, k: k))
        }
    }

    func testDecap() {
        for t in decapTests {
            let kyber = Kyber(t.kind)
            let k = kyber.ML_KEMDecaps_internal(t.dk, t.c)
            XCTAssertEqual(k, t.k)
            let (k1, ct) = kyber.ML_KEMEncaps(t.ek)
            XCTAssertEqual(k1, kyber.ML_KEMDecaps_internal(t.dk, ct))
        }
    }

}
