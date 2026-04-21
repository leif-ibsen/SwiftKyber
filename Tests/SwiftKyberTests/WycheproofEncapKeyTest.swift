//
//  WycheproofTest.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 01/09/2025.
//

import XCTest
@testable import SwiftKyber
import Digest

// Test inconsistent encapsulationKey data
// Test vectors from Wycheproof mlkem_512_encaps_test.json, mlkem_768_encaps_test.json and mlkem_1024_encaps_test.json

final class WycheproofEncapKeyTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "wycheproofEncapKey", withExtension: "rsp")!
        makeEncapKeyTests(try Data(contentsOf: url))
    }
    
    struct encapKeyTest {
        let tcId: String
        let kind: Kind
        let ek: Bytes
    }

    var encapKeyTests: [encapKeyTest] = []
    
    func makeEncapKeyTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 4
        for i in 0 ..< groups {
            let j = i * 4
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 4
            let tcId = lines[j]
            let kind = Util.kyberKind(lines[j + 1])
            let ek = Base64.hex2bytes(lines[j + 2])!
            encapKeyTests.append(encapKeyTest(tcId: tcId, kind: kind, ek: ek))
        }
    }

    func testEncapKey() throws {
        for t in encapKeyTests {
            do {
                let _ = try EncapsulationKey(keyBytes: t.ek)
                XCTFail("Expected encapsulationKeyInconsistent exception")
            } catch Exception.encapsulationKeyInconsistent {
            } catch {
                XCTFail("Expected encapsulationKeyInconsistent exception")
            }
        }
    }

}
