//
//  KAT1024Test.swift
//  
//
//  Created by Leif Ibsen on 23/10/2023.
//

import XCTest
@testable import SwiftKyber

// Test vectors from GitHub - itzmeanjan
final class KAT1024Test: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "kyber1024", withExtension: "kat")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        for t in katTests {
            let (pk, sk) = Kyber.K1024.CCAKEM_KeyGen(t.d + t.z)
            XCTAssertEqual(pk, t.pk)
            XCTAssertEqual(sk, t.sk)
            let PK = try PublicKey(bytes: pk)
            let SK = try SecretKey(bytes: sk)
            let (ct, ss) = PK.Encapsulate(t.m)
            XCTAssertEqual(ct, t.ct)
            XCTAssertEqual(ss, t.ss)
            XCTAssertEqual(try SK.Decapsulate(ct: ct), ss)
        }
    }

}
