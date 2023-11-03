//
//  KAT512Test.swift
//  
//
//  Created by Leif Ibsen on 22/10/2023.
//

import XCTest
@testable import SwiftKyber

// Test vectors from GitHub - itzmeanjan
final class KAT512Test: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "kyber512", withExtension: "kat")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        let kyber = Kyber.K512
        for t in katTests {
            let (pk, sk) = kyber.CCAKEM_KeyGen(t.d + t.z)
            XCTAssertEqual(pk, t.pk)
            XCTAssertEqual(sk, t.sk)
            let (ct, ss) = kyber.CCAKEM_Enc(try PublicKey(bytes: pk), t.m)
            XCTAssertEqual(ct, t.ct)
            XCTAssertEqual(ss, t.ss)
            XCTAssertEqual(kyber.CCAKEM_Dec(ct, try SecretKey(bytes: sk)), t.ss)
        }
    }

}
