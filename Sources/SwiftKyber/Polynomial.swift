//
//  Polynomial.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 09/10/2023.
//

// Polynomials of degree 255
struct Polynomial: Equatable {
    
    // 17 ^ bitreversal(i) mod Kyber.Q, for i in 0 ..< 128
    static let zetas1 = [
           1, 1729, 2580, 3289, 2642,  630, 1897,  848, 1062, 1919,  193,  797, 2786, 3260,  569, 1746,
         296, 2447, 1339, 1476, 3046,   56, 2240, 1333, 1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
         289,  331, 3253, 1756, 1197, 2304, 2277, 2055,  650, 1977, 2513,  632, 2865,   33, 1320, 1915,
        2319, 1435,  807,  452, 1438, 2868, 1534, 2402, 2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
          17, 2761,  583, 2649, 1637,  723, 2288, 1100, 1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,  939, 2308, 2437, 2388,  733, 2337,  268,  641,
        1584, 2298, 2037, 3220,  375, 2549, 2090, 1645, 1063,  319, 2773,  757, 2099,  561, 2466, 2594,
        2804, 1092,  403, 1026, 1143, 2150, 2775,  886, 1722, 1212, 1874, 1029, 2110, 2935,  885, 2154
    ]
    
    // 17 ^ (2 * bitreversal(i) + 1) mod Kyber.Q, for i in 0 ..< 128
    static let zetas2 = [
          17, 3312, 2761,  568,  583, 2746, 2649,  680, 1637, 1692,  723, 2606, 2288, 1041, 1100, 2229,
        1409, 1920, 2662,  667, 3281,   48,  233, 3096,  756, 2573, 2156, 1173, 3015,  314, 3050,  279,
        1703, 1626, 1651, 1678, 2789,  540, 1789, 1540, 1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
         939, 2390, 2308, 1021, 2437,  892, 2388,  941,  733, 2596, 2337,  992,  268, 3061,  641, 2688,
        1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,  375, 2954, 2549,  780, 2090, 1239, 1645, 1684,
        1063, 2266,  319, 3010, 2773,  556,  757, 2572, 2099, 1230,  561, 2768, 2466,  863, 2594,  735,
        2804,  525, 1092, 2237,  403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775,  554,  886, 2443,
        1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935,  394,  885, 2444, 2154, 1175
    ]
    
    var coefficient: [Int]
    
    init() {
        self.coefficient = [Int](repeating: 0, count: 256)
    }
    
    init(_ coefficient: [Int]) {
        assert(coefficient.count == 256)
        self.coefficient = coefficient
    }
    
    func Compress(_ d: Int) -> Polynomial {
        var x = Polynomial()
        for i in 0 ..< 256 {
            x.coefficient[i] = Kyber.Compress(self.coefficient[i], d)
        }
        return x
    }

    func Decompress(_ d: Int) -> Polynomial {
        var x = Polynomial()
        for i in 0 ..< 256 {
            x.coefficient[i] = Kyber.Decompress(self.coefficient[i], d)
        }
        return x
    }
    
    func ByteEncode(_ d: Int) -> Bytes {
        assert(0 < d && d <= 12)
        return Kyber.ByteEncode(self.coefficient, d)
    }

    static func ByteDecode(_ bytes: Bytes, _ d: Int) -> Polynomial {
        assert(bytes.count == d << 5)
        return Polynomial(Kyber.ByteDecode(bytes, d))
    }

    // Number Theoretic Transform
    // [FIPS203] - Algorithm 8
    func NTT() -> Polynomial {
        var f = self.coefficient
        var k = 1
        var len = 128
        while len >= 2 {
            var start = 0
            while start < 256 {
                let zeta = Polynomial.zetas1[k]
                k += 1
                for j in start ..< start + len {
                    let t = Kyber.reduceModQ(zeta * f[j + len])
                    f[j + len] = Kyber.subModQ(f[j], t)
                    f[j] = Kyber.addModQ(f[j], t)
                }
                start += len << 1
            }
            len >>= 1
        }
        return Polynomial(f)
    }

    // Inverse Number Theoretic Transform
    // [FIPS203] - Algorithm 9
    func INTT() -> Polynomial {
        var f = self.coefficient
        var k = 127
        var len = 2
        while len <= 128 {
            var start = 0
            while start < 256 {
                let zeta = Polynomial.zetas1[k]
                k -= 1
                for j in start ..< start + len {
                    let t = f[j]
                    f[j] = Kyber.addModQ(t, f[j + len])
                    f[j + len] = Kyber.reduceModQ(zeta * Kyber.subModQ(f[j + len], t))
                }
                start += len << 1
            }
            len <<= 1
        }
        for i in 0 ..< f.count {
            f[i] = Kyber.reduceModQ(f[i] * 3303)  // 3303 = 128^-1 mod 3329
        }
        return Polynomial(f)
    }

    // f * g
    // [FIPS203] - Algorithm 10
    static func *(_ f: Polynomial, _ g: Polynomial) -> Polynomial {
        var h = [Int](repeating: 0, count: 256)
        for i in stride(from: 0, to: 256, by: 2) {
            let x1 = f.coefficient[i]
            let x2 = f.coefficient[i + 1]
            let y1 = g.coefficient[i]
            let y2 = g.coefficient[i + 1]
            let z = zetas2[i >> 1]
            h[i] = Kyber.addModQ(Kyber.reduceModQ(x1 * y1), Kyber.reduceModQ(z * Kyber.reduceModQ(x2 * y2)))
            h[i + 1] = Kyber.addModQ(Kyber.reduceModQ(x2 * y1), Kyber.reduceModQ(x1 * y2))
        }
        return Polynomial(h)
    }
    
    // p1 + p2
    static func +(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var sum = p1
        sum += p2
        return sum
    }
    
    // p1 += p2
    static func +=(_ p1: inout Polynomial, _ p2: Polynomial) {
        for i in 0 ..< 256 {
            p1.coefficient[i] = Kyber.addModQ(p1.coefficient[i], p2.coefficient[i])
        }
    }
    
    // p1 - p2
    static func -(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var diff = p1
        diff -= p2
        return diff
    }
    
    // p1 -= p2
    static func -=(_ p1: inout Polynomial, _ p2: Polynomial) {
        for i in 0 ..< 256 {
            p1.coefficient[i] = Kyber.subModQ(p1.coefficient[i], p2.coefficient[i])
        }
    }
    
}
