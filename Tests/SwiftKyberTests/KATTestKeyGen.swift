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

final class KATTestKeyGen: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestKeyGen", withExtension: "rsp")!
        makeKeyGenTests(try Data(contentsOf: url))
    }

    struct keyGenTest {
        let tcId: String
        let kind: Kind
        let z: Bytes
        let d: Bytes
        let ek: Bytes
        let dk: Bytes
    }

    var keyGenTests: [keyGenTest] = []
    
    func makeKeyGenTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(4)
            lines[j + 3].removeFirst(4)
            lines[j + 4].removeFirst(5)
            lines[j + 5].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let tcId = lines[j]
            let kind = Util.kyberKind(lines[j + 1])
            let z = Base64.hex2bytes(lines[j + 2])!
            let d = Base64.hex2bytes(lines[j + 3])!
            let ek = Base64.hex2bytes(lines[j + 4])!
            let dk = Base64.hex2bytes(lines[j + 5])!
            keyGenTests.append(keyGenTest(tcId: tcId, kind: kind, z: z, d: d, ek: ek, dk: dk))
        }
    }

    func testKeyGen() throws {
        for t in keyGenTests {
            let kyber = Kyber(t.kind)
            let (ek1, dk1) = kyber.ML_KEMKeyGen_internal(t.d, t.z)
            XCTAssertEqual(ek1, t.ek)
            XCTAssertEqual(dk1, t.dk)
            let (ek2, dk2) = try Kyber.DeriveKeyPair(kind: t.kind, ikm: t.d + t.z)
            XCTAssertEqual(ek2.keyBytes, t.ek)
            XCTAssertEqual(dk2.keyBytes, t.dk)
        }
    }

}
