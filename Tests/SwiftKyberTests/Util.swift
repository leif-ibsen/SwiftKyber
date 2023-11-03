//
//  Util.swift
//  
//
//  Created by Leif Ibsen on 20/10/2023.
//

import XCTest
@testable import SwiftKyber

final class Util: XCTestCase {
    
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
    
    struct katTest {
        let d: Bytes
        let z: Bytes
        let pk: Bytes
        let sk: Bytes
        let m: Bytes
        let ct: Bytes
        let ss: Bytes
    }
    
    static func makeKatTests(_ katTests: inout [katTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j].removeFirst(4)
            lines[j + 1].removeFirst(4)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(5)
            lines[j + 6].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let d = hex2bytes(lines[j])
            let z = hex2bytes(lines[j + 1])
            let pk = hex2bytes(lines[j + 2])
            let sk = hex2bytes(lines[j + 3])
            let m = hex2bytes(lines[j + 4])
            let ct = hex2bytes(lines[j + 5])
            let ss = hex2bytes(lines[j + 6])
            katTests.append(katTest(d: d, z: z, pk: pk, sk: sk, m: m, ct: ct, ss: ss))
        }
    }

}
