//
//  Kyber.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 09/10/2023.
//

import Foundation
import Digest

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

public struct Kyber {
    
    
    // MARK: Kyber Instances
    
    /// The K512 instance
    public static let K512 = Kyber(KyberParameters.k512)

    /// The K768 instance
    public static let K768 = Kyber(KyberParameters.k768)

    /// The K1024 instance
    public static let K1024 = Kyber(KyberParameters.k1024)


    // MARK: Instance Methods
    
    /// Generates an encapsulation key and a decapsulation key
    ///
    /// - Returns: The encapsulation key `encap` and the decapsulation key `decap`
    public func GenerateKeyPair() -> (encap: EncapsulationKey, decap: DecapsulationKey) {
        let (encap, decap) = KEMKeyGen([])
        do {
            return (try EncapsulationKey(encap, false), try DecapsulationKey(decap, false))
        } catch {
            // Shouldn't happen
            fatalError("GenerateKeyPair inconsistency")
        }
    }

    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }

    static let Q = 3329
    static let rhoSize = 32
    static let hSize = 32
    static let zSize = 32
    static let sha256 = MessageDigest(.SHA3_256)
    static let sha512 = MessageDigest(.SHA3_512)
    static let shake256 = SHAKE(.SHAKE256)

    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let ekSize: Int
    let dkSize: Int
    let ctSize: Int
    let k384: Int
    let k768: Int

    init(_ kp: KyberParameters) {
        self.k = kp.k
        self.eta1 = kp.eta1
        self.eta2 = kp.eta2
        self.du = kp.du
        self.dv = kp.dv
        self.ekSize = kp.ekSize
        self.dkSize = kp.dkSize
        self.ctSize = kp.ctSize
        self.k384 = self.k * 384
        self.k768 = self.k * 768
    }
    
    
    // Message digest helper functions

    static func H(_ seed: Bytes) -> Bytes {
        Kyber.sha256.update(seed)
        return Kyber.sha256.digest()
    }
    
    static func G(_ seed: Bytes) -> (Bytes, Bytes) {
        Kyber.sha512.update(seed)
        let x = Kyber.sha512.digest()
        return (Bytes(x[0 ..< 32]), Bytes(x[32 ..< 64]))
    }
    
    static func J(_ seed: Bytes) -> Bytes {
        Kyber.shake256.update(seed)
        return Kyber.shake256.digest(32)
    }

    static func PRF(_ seed: Bytes, _ N: Byte, _ eta: Int) -> Bytes {
        assert(seed.count == 32)
        Kyber.shake256.update(seed + [N])
        return Kyber.shake256.digest(eta << 6)
    }

    
    // Compression and decompression
    
    static func Compress(_ x: Int, _ d: Int) -> Int {
        assert(0 <= x && x < Kyber.Q)
        assert(0 < d && d < 12)
        let (q, r) = (x << d).quotientAndRemainder(dividingBy: Kyber.Q)
        return (r >= 1665 ? q + 1 : q) & (1 << d - 1)
    }
    
    static func Decompress(_ y: Int, _ d: Int) -> Int {
        assert(0 <= y && y < 1 << d)
        assert(0 < d && d < 12)
        let yQ = (y * Kyber.Q) >> (d - 1)
        return yQ & 1 == 1 ? (yQ >> 1) + 1 : yQ >> 1
    }

    // [FIPS203] - Algorithm 4
    static func ByteEncode(_ F: [Int], _ d: Int) -> Bytes {
        assert(0 < d && d <= 12)
        assert(F.count == 256)
        var x = Bytes(repeating: 0, count: d << 5)
        var id = 0
        for i in 0 ..< 256 {
            for j in 0 ..< d {
                let bit = F[i] & (1 << j) != 0 ? Byte(1) : Byte(0)
                x[(id + j) >> 3] |= bit << ((id + j) & 0x7)
            }
            id += d
        }
        return x
    }

    // [FIPS203] - Algorithm 5
    static func ByteDecode(_ B: Bytes, _ d: Int) -> [Int] {
        assert(0 < d && d <= 12)
        assert(B.count == d * 32)
        var F = [Int](repeating: 0, count: 256)
        var id = 0
        for i in 0 ..< F.count {
            for j in 0 ..< d {
                F[i] |= (Int(B[(id + j) >> 3] >> ((id + j) & 0x7)) & 1) << j
            }
            id += d
        }
        if d == 12 {
            for i in 0 ..< F.count {
                F[i] = Kyber.reduceModQ(F[i])
            }
        }
        return F
    }

    // [FIPS203] - Algorithm 6
    func SampleNTT(_ xof: XOF) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        var j = 0
        let bufferSize = 504 // 3 * SHAKE128 buffer size
        var xofBuffer = Bytes(repeating: 0, count: bufferSize)
        var xofIndex = bufferSize
        while j < 256 {
            if xofIndex == bufferSize {
                xof.read(&xofBuffer)
                xofIndex = 0
            }
            let b0 = Int(xofBuffer[xofIndex])
            let b1 = Int(xofBuffer[xofIndex + 1])
            let b2 = Int(xofBuffer[xofIndex + 2])
            xofIndex += 3
            let d1 = b0 + (b1 & 0xf) << 8
            let d2 = b1 >> 4 + b2 << 4
            if d1 < Kyber.Q {
                x[j] = d1
                j += 1
            }
            if d2 < Kyber.Q && j < 256 {
                x[j] = d2
                j += 1
            }
        }
        return Polynomial(x)
    }

    // [FIPS203] - Algorithm 7
    func SamplePolyCBD(_ B: Bytes, _ eta: Int) -> Polynomial {
        assert(B.count == eta << 6)
        let onebits: [Int] = [0, 1, 1, 2, 1, 2, 2, 3]
        var f = [Int](repeating: 0, count: 256)
        var x: Byte
        var y: Byte
        var bitNo = 0
        if eta == 2 {
            for i in 0 ..< 256 {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    x = B[byteNo] & 0x3
                    y = (B[byteNo] >> 2) & 0x3
                case 4:
                    x = (B[byteNo] >> 4) & 0x3
                    y = (B[byteNo] >> 6) & 0x3
                default:
                    fatalError("SamplePolyCBD inconsistency")
                }
                bitNo += 4
                f[i] = Kyber.subModQ(onebits[Int(x)], onebits[Int(y)])
            }
        } else {
            assert(eta == 3)
            for i in 0 ..< 256 {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    x = B[byteNo] & 0x7
                    y = (B[byteNo] >> 3) & 0x7
                case 2:
                    x = (B[byteNo] >> 2) & 0x7
                    y = (B[byteNo] >> 5) & 0x7
                case 4:
                    x = (B[byteNo] >> 4) & 0x7
                    y = (B[byteNo] >> 7) & 0x1 | ((B[byteNo + 1] & 0x3) << 1)
                case 6:
                    x = (B[byteNo] >> 6) & 0x3 | ((B[byteNo + 1] & 0x1) << 2)
                    y = (B[byteNo + 1] >> 1) & 0x7
                default:
                    fatalError("SamplePolyCBD inconsistency")
                }
                bitNo += 6
                f[i] = Kyber.subModQ(onebits[Int(x)], onebits[Int(y)])
            }
        }
        return Polynomial(f)
    }

    // [FIPS203] - Algorithm 12
    func PKEKeyGen(_ seed: Bytes = []) -> (ek: Bytes, dk: Bytes) {
        assert(seed.count == 0 || seed.count == 32)
        var d = Bytes(repeating: 0, count: 32)
        if seed.count == 0 {
            Kyber.randomBytes(&d)
        } else {
            d = seed
        }
        let (rho, sigma) = Kyber.G(d)
        var N = Byte(0)
        var Ahat = Matrix(self.k)
        for i in 0 ..< self.k {
            for j in 0 ..< self.k {
                Ahat.vector[i].polynomial[j] = SampleNTT(XOF(.XOF128, rho + [Byte(j), Byte(i)]))
            }
        }
        var s = Vector(self.k)
        for i in 0 ..< self.k {
            s.polynomial[i] = SamplePolyCBD(Kyber.PRF(sigma, N, self.eta1), self.eta1)
            N += 1
        }
        var e = Vector(self.k)
        for i in 0 ..< self.k {
            e.polynomial[i] = SamplePolyCBD(Kyber.PRF(sigma, N, self.eta1), self.eta1)
            N += 1
        }
        let sHat = s.NTT()
        let eHat = e.NTT()
        let tHat = Ahat * sHat + eHat
        let ek = tHat.ByteEncode(12) + rho
        let dk = sHat.ByteEncode(12)
        return (ek, dk)
    }
    
    //  [FIPS203] - Algorithm 13
    func PKEEncrypt(_ ek: Bytes, _ m: Bytes, _ rnd: Bytes) -> Bytes {
        assert(ek.count == self.k384 + 32)
        assert(m.count == 32)
        assert(rnd.count == 32)
        var N = Byte(0)
        let tHat = Vector.ByteDecode(ek, 12)
        let rho = Bytes(ek[ek.count - Kyber.rhoSize ..< ek.count])
        var AhatT = Matrix(self.k)
        for i in 0 ..< self.k {
            for j in 0 ..< self.k {
                AhatT.vector[i].polynomial[j] = SampleNTT(XOF(.XOF128, rho + [Byte(i), Byte(j)]))
            }
        }
        var r = Vector(self.k)
        for i in 0 ..< self.k {
            r.polynomial[i] = SamplePolyCBD(Kyber.PRF(rnd, N, self.eta1), self.eta1)
            N += 1
        }
        var e1 = Vector(self.k)
        for i in 0 ..< self.k {
            e1.polynomial[i] = SamplePolyCBD(Kyber.PRF(rnd, N, self.eta2), self.eta2)
            N += 1
        }
        let e2 = SamplePolyCBD(Kyber.PRF(rnd, N, self.eta2), self.eta2)
        let rHat = r.NTT()
        let u = (AhatT * rHat).INTT() + e1
        let my = Polynomial.ByteDecode(m, 1).Decompress(1)
        let v = (tHat * rHat).INTT() + e2 + my
        let c1 = u.Compress(self.du).ByteEncode(self.du)
        let c2 = v.Compress(self.dv).ByteEncode(self.dv)
        return c1 + c2
    }

    //  [FIPS203] - Algorithm 14
    func PKEDecrypt(_ dk: Bytes, _ ct: Bytes) -> Bytes {
        assert(dk.count == self.k384)
        assert(ct.count == (self.du * self.k + self.dv) * 32)
        let index = self.du * self.k << 5
        let u = Vector.ByteDecode(ct.slice(0, index).bytes, self.du).Decompress(self.du)
        let v = Polynomial.ByteDecode(ct.slice(index, self.dv << 5).bytes, self.dv).Decompress(self.dv)
        let sHat = Vector.ByteDecode(dk, 12)
        let w = v - (sHat * u.NTT()).INTT()
        return w.Compress(1).ByteEncode(1)
    }

    // [FIPS203] - Algorithm 15
    func KEMKeyGen(_ seed: Bytes) -> (ek: Bytes, dk: Bytes) {
        assert(seed.count == 0 || seed.count == 64)
        var z = Bytes(repeating: 0, count: 32)
        var s1: Bytes
        if seed.count == 0 {
            s1 = []
            Kyber.randomBytes(&z)
        } else {
            s1 = seed.slice(0, 32).bytes
            z = seed.slice(32, 32).bytes
        }
        let (ek, dk) = PKEKeyGen(s1)
        return (ek, dk + ek + Kyber.H(ek) + z)
    }
    
    // [FIPS203] - Algorithm 16
    func KEMEncaps(_ seed: Bytes, _ ek: Bytes) -> (K: Bytes, ct: Bytes) {
        assert(seed.count == 0 || seed.count == 32)
        assert(ek.count == self.k384 + 32)
        var m = Bytes(repeating: 0, count: 32)
        if seed.count == 0 {
            Kyber.randomBytes(&m)
        } else {
            m = seed
        }
        let (K, r) = Kyber.G(m + Kyber.H(ek))
        let ct = PKEEncrypt(ek, m, r)
        return (K, ct)
    }

    // [FIPS203] - Algorithm 17
    func KEMDecaps(_ ct: Bytes, _ dk: Bytes) -> Bytes {
        assert(ct.count == (self.du * self.k + self.dv) * 32)
        assert(dk.count == self.k768 + 96)
        let dkPKE = dk.slice(0, self.k384).bytes
        let ekPKE = dk.slice(self.k384, self.k384 + 32).bytes
        let h = dk.slice(self.k768 + 32, 32).bytes
        let z = dk.slice(self.k768 + 64, 32).bytes
        let m = PKEDecrypt(dkPKE, ct)
        let (K, r) = Kyber.G(m + h)
        let K_ = Kyber.J(z + ct)
        let ct_ = PKEEncrypt(ekPKE, m, r)
        return Equal(ct, ct_) ? K : K_
    }

    // Constant-time comparison of c1 and c2
    func Equal(_ c1: Bytes, _ c2: Bytes) -> Bool {
        assert(c1.count == c2.count)
        var equal = true
        for i in 0 ..< c1.count {
            equal = equal && (c1[i] == c2[i])
        }
        return equal
    }
 
    
    // Arithmetic modulo Kyber.Q
    
    // Addition modulo Kyber.Q
    static func addModQ(_ a: Int, _ b: Int) -> Int {
        assert(0 <= a && a < Kyber.Q)
        assert(0 <= b && b < Kyber.Q)
        let x = a + b
        return x < Kyber.Q ? x : x - Kyber.Q
    }
    
    // Subtraction modulo Kyber.Q
    static func subModQ(_ a: Int, _ b: Int) -> Int {
        assert(0 <= a && a < Kyber.Q)
        assert(0 <= b && b < Kyber.Q)
        let x = a - b
        return x < 0 ? x + Kyber.Q : x
    }
    
    // Barrett reduction stuff
    static let bq = (1 << 32) / Kyber.Q

    // Reduce modulo Kyber.Q using Barrett reduction
    static func reduceModQ(_ x: Int) -> Int {
        assert(0 <= x && x < Kyber.Q * Kyber.Q)
        let t = x - ((x * bq) >> 32) * Kyber.Q
        return t < Kyber.Q ? t : t - Kyber.Q
    }

}
