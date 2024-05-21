//
//  File.swift
//  
//
//  Created by Leif Ibsen on 21/12/2023.
//

import Foundation
@testable import SwiftKyber

struct Util {
    
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
        let z: Bytes
        let d: Bytes
        let msg: Bytes
        let seed: Bytes
        let pk: Bytes
        let sk: Bytes
        let ct_n: Bytes
        let ss_n: Bytes
        let ct: Bytes
        let ss: Bytes
    }
    
    static func makeKatTests(_ katTests: inout [katTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 12
        for i in 0 ..< groups {
            let j = i * 12
            lines[j + 1].removeFirst(4)
            lines[j + 2].removeFirst(4)
            lines[j + 3].removeFirst(6)
            lines[j + 4].removeFirst(7)
            lines[j + 5].removeFirst(5)
            lines[j + 6].removeFirst(5)
            lines[j + 7].removeFirst(7)
            lines[j + 8].removeFirst(7)
            lines[j + 9].removeFirst(5)
            lines[j + 10].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 12
            let z = hex2bytes(lines[j + 1])
            let d = hex2bytes(lines[j + 2])
            let msg = hex2bytes(lines[j + 3])
            let seed = hex2bytes(lines[j + 4])
            let pk = hex2bytes(lines[j + 5])
            let sk = hex2bytes(lines[j + 6])
            let ct_n = hex2bytes(lines[j + 7])
            let ss_n = hex2bytes(lines[j + 8])
            let ct = hex2bytes(lines[j + 9])
            let ss = hex2bytes(lines[j + 10])
            katTests.append(katTest(z: z, d: d, msg: msg, seed: seed, pk: pk, sk: sk, ct_n: ct_n, ss_n: ss_n, ct: ct, ss: ss))
        }
    }

}
