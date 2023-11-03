//
//  SHAKETest.swift
//  
//
//  Created by Leif Ibsen on 05/10/2023.
//

import XCTest
@testable import SwiftKyber

final class SHAKETest: XCTestCase {

    func testSHAKE() throws {
        let shake = SHAKE256()
        shake.update(Bytes("".utf8))
        XCTAssertEqual(Util.bytes2hex(shake.digest(16)), "46b9dd2b0ba88d13233b3feb743eeb24")
        shake.update(Bytes("abc".utf8))
        XCTAssertEqual(Util.bytes2hex(shake.digest(16)), "483366601360a8771c6863080cc4114d")
        shake.update(Bytes("hello123".utf8))
        XCTAssertEqual(Util.bytes2hex(shake.digest(8)), "ade612ba265f92de")
        shake.update(Bytes("hello".utf8))
        shake.update(Bytes("123".utf8))
        XCTAssertEqual(Util.bytes2hex(shake.digest(8)), "ade612ba265f92de")
        shake.update(Bytes("123".utf8))
        XCTAssertEqual(Util.bytes2hex(shake.digest(0)), "")
    }

    func testXOF() throws {
        var xof = XOF(Bytes("".utf8))
        XCTAssertEqual(Util.bytes2hex(xof.read(16)), "7f9c2ba4e88f827d616045507605853e")
        xof = XOF(Bytes("abc".utf8))
        XCTAssertEqual(Util.bytes2hex(xof.read(16)), "5881092dd818bf5cf8a3ddb793fbcba7")
        xof = XOF(Bytes("hello123".utf8))
        XCTAssertEqual(Util.bytes2hex(xof.read(8)), "1b85861510bc4d8e")
        xof = XOF(Bytes("123".utf8))
        XCTAssertEqual(Util.bytes2hex(xof.read(0)), "")
    }

}
