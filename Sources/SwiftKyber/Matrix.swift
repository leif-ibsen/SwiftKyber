//
//  Matrix.swift
//  SwiftKyberTest
//
//  Created by Leif Ibsen on 11/10/2023.
//

// Vector of vector of polynomials
struct Matrix: Equatable {
    
    var vector: [Vector]
    let n: Int
    
    init(_ n: Int) {
        self.vector = [Vector](repeating: Vector(n), count: n)
        self.n = n
    }
    
    // m o v
    static func *(_ m: Matrix, _ v: Vector) -> Vector {
        assert(m.n == v.n)
        var x = Vector(m.n)
        for i in 0 ..< m.n {
            for j in 0 ..< m.n {
                x.polynomial[i] += m.vector[i].polynomial[j] * v.polynomial[j]
            }
        }
        return x
    }
    
}
