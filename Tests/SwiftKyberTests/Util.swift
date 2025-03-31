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

    static func kyberKind(_ kind: String) -> Kind {
        switch kind {
        case "ML-KEM-512":
            return Kind.K512
        case "ML-KEM-768":
            return Kind.K768
        case "ML-KEM-1024":
            return Kind.K1024
        default:
            fatalError("Wrong Kyber kind: \(kind)")
        }
    }

}
