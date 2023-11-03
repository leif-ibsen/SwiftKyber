//
//  Matrix.swift
//  SwiftKyberTest
//
//  Created by Leif Ibsen on 11/10/2023.
//

struct Matrix: Equatable {
    
    var vector: [Vector]
    
    init(_ n: Int) {
        self.vector = [Vector](repeating: Vector(n), count: n)
    }
    
    // m dot v
    static func *(_ m: Matrix, _ v: Vector) -> Vector {
        var x = Vector(v.n)
        for row in 0 ..< x.n {
            for col in 0 ..< x.n {
                x.polynomial[row] += m.vector[row].polynomial[col] * v.polynomial[col]
            }
        }
        return x
    }
    
}
