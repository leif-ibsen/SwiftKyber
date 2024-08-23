//
//  File.swift
//  
//
//  Created by Leif Ibsen on 21/12/2023.
//

import Foundation
@testable import SwiftKyber

struct Util {
    
    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomInts failed")
        }
    }

    static func randomInts(_ ints: inout [Int]) {
        guard SecRandomCopyBytes(kSecRandomDefault, 8 * ints.count, &ints) == errSecSuccess else {
            fatalError("randomInts failed")
        }
    }

    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }
    
    static func bytes2hex(_ x: Bytes) -> String {
        let hexDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }
    
    struct keyGenTest {
        let z: Bytes
        let d: Bytes
        let ek: Bytes
        let dk: Bytes
    }

    struct encapDecapTest {
        let ek: Bytes
        let dk: Bytes
        let c: Bytes
        let k: Bytes
        let m: Bytes
    }

    static func makeKeyGenTests(_ tests: inout [keyGenTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 6
        for i in 0 ..< groups {
            let j = i * 6
            lines[j + 1].removeFirst(4)
            lines[j + 2].removeFirst(4)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 6
            let z = hex2bytes(lines[j + 1])
            let d = hex2bytes(lines[j + 2])
            let ek = hex2bytes(lines[j + 3])
            let dk = hex2bytes(lines[j + 4])
            tests.append(keyGenTest(z: z, d: d, ek: ek, dk: dk))
        }
    }

    static func makeEncapDecapTests(_ tests: inout [encapDecapTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(4)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let ek = hex2bytes(lines[j + 1])
            let dk = hex2bytes(lines[j + 2])
            let c = hex2bytes(lines[j + 3])
            let k = hex2bytes(lines[j + 4])
            let m = hex2bytes(lines[j + 5])
            tests.append(encapDecapTest(ek: ek, dk: dk, c: c, k: k, m: m))
        }
    }

}
