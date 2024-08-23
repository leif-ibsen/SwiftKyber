 //
//  ExceptionTest.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import XCTest
@testable import SwiftKyber

final class ExceptionTest: XCTestCase {

    func test1() throws {
        do {
            let _ = try EncapsulationKey(keyBytes: Bytes(repeating: 0, count: 600))
            XCTFail("Expected encapsulationKeySize exception")
        } catch KyberException.encapsulationKeySize {
        } catch {
            XCTFail("Expected encapsulationKeySize exception")
        }
    }

    func test2() throws {
        do {
            let _ = try DecapsulationKey(keyBytes: Bytes(repeating: 0, count: 600))
            XCTFail("Expected decapsulationKeySize exception")
        } catch KyberException.decapsulationKeySize {
        } catch {
            XCTFail("Expected decapsulationKeySize exception")
        }
    }

    func test3() throws {
        do {
            let (_, dk) = Kyber.K512.GenerateKeyPair()
            let _ = try dk.Decapsulate(ct: Bytes(repeating: 0, count: 600))
            XCTFail("Expected cipherTextSize exception")
        } catch KyberException.cipherTextSize {
        } catch {
            XCTFail("Expected cipherTextSize exception")
        }
    }

    func test4() throws {
        do {
            let _ = try EncapsulationKey(keyBytes: Bytes(repeating: 255, count: Kyber.K512.ekSize))
            XCTFail("Expected encapsulationKeyInconsistent exception")
        } catch KyberException.encapsulationKeyInconsistent {
        } catch {
            XCTFail("Expected encapsulationKeyInconsistent exception")
        }
    }

    func test5() throws {
        do {
            let (_, dk) = Kyber.K512.GenerateKeyPair()
            var kb = dk.keyBytes
            kb[Kyber.K512.k768 + 32] &+= 1
            let _ = try DecapsulationKey(keyBytes: kb)
            XCTFail("Expected decapsulationKeyInconsistent exception")
        } catch KyberException.decapsulationKeyInconsistent {
        } catch {
            XCTFail("Expected decapsulationKeyInconsistent exception")
        }
    }

}
