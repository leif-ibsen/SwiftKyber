//
//  Matrix.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 11/10/2023.
//

// Vector of vector of polynomials
struct Matrix: Equatable {
    
    var vectors: [Vector]
    let n: Int
    
    init(_ n: Int) {
        self.vectors = [Vector](repeating: Vector(n), count: n)
        self.n = n
    }

    // m o v
    static func *(_ m: Matrix, _ v: Vector) -> Vector {
        assert(m.n == v.n)
        var x = Vector(m.n)
        for i in 0 ..< m.n {
            for j in 0 ..< m.n {
                x.polynomials[i] += m.vectors[i].polynomials[j] * v.polynomials[j]
            }
        }
        return x
    }
    
}
