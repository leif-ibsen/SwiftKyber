//
//  KAT1024Test.swift
//  
//
//  Created by Leif Ibsen on 21/12/2023.
//

import XCTest
@testable import SwiftKyber

final class KAT1024Test: XCTestCase {

    // Test vectors from GitHub: Krzystof Kwiatkowski

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "kat1024", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        for t in katTests {
            let (ek, dk) = Kyber.K1024.KEMKeyGen(t.d + t.z)
            XCTAssertEqual(ek, t.pk)
            XCTAssertEqual(dk, t.sk)
            let EK = try EncapsulationKey(keyBytes: ek)
            let DK = try DecapsulationKey(keyBytes: dk)
            let (ss, ct) = EK.Encapsulate(t.m)
            XCTAssertEqual(ss, t.ss)
            XCTAssertEqual(ct, t.ct)
            XCTAssertEqual(try DK.Decapsulate(ct: ct), ss)
        }
    }

}
