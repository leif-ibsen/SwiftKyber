//
//  ExceptionTest.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import XCTest
@testable import SwiftKyber
import ASN1

final class ExceptionTest: XCTestCase {

    func test1() throws {
        do {
            let _ = try PublicKey(bytes: Bytes(repeating: 0, count: 600))
            XCTFail("Expected pkSize exception")
        } catch KyberException.pkSize {
        } catch {
            XCTFail("Expected pkSize exception")
        }
    }

    func test2() throws {
        do {
            let _ = try SecretKey(bytes: Bytes(repeating: 0, count: 600))
            XCTFail("Expected skSize exception")
        } catch KyberException.skSize {
        } catch {
            XCTFail("Expected skSize exception")
        }
    }

    func test3() throws {
        do {
            let (_, sk) = Kyber.K512.GenerateKeyPair()
            let _ = try sk.Decapsulate(ct: Bytes(repeating: 0, count: 600))
            XCTFail("Expected ctSize exception")
        } catch KyberException.ctSize {
        } catch {
            XCTFail("Expected ctSize exception")
        }
    }

}
