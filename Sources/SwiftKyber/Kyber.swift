//
//  Kyber.swift
//  SwiftKyberTest
//
//  Created by Leif Ibsen on 09/10/2023.
//

import Foundation
import ASN1

/// Unsigned 8 bit value
public typealias Byte = UInt8
/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

/// The Kyber structure contains three static members *K512*, *K768* and *K1024*
/// corresponding to the three defined Kyber instances. There is no public constructor,
/// so it is not possible to create other instances.
public struct Kyber {
    
    // MARK: Kyber instances
    
    /// The Kyber512 instance
    public static let K512 = Kyber(KyberParameters.k512)

    /// The Kyber768 instance
    public static let K768 = Kyber(KyberParameters.k768)

    /// The Kyber1024 instance
    public static let K1024 = Kyber(KyberParameters.k1024)

    
    // MARK: Stored properties

    /// The Kyber OID
    public internal(set) var OID: ASN1ObjectIdentifier!


    // MARK: Methods
    
    /// Generates a public key and a secret key
    ///
    /// - Returns: The public key *pk* and the secret key *sk*
    public func GenerateKeyPair() -> (pk: PublicKey, sk: SecretKey) {
        let (pk, sk) = CCAKEM_KeyGen([])
        do {
            return (try PublicKey(bytes: pk), try SecretKey(bytes: sk))
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

    static let N = 256
    static let N32 = 32
    static let Q = 3329
    static let rhoSize = 32
    static let hSize = 32
    static let zSize = 32

    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let sSize: Int
    let tSize: Int
    let publicKeySize: Int
    let secretKeySize: Int
    let cipherTextSize: Int

    init(_ kp: KyberParameters) {
        self.k = kp.k
        self.eta1 = kp.eta1
        self.eta2 = kp.eta2
        self.du = kp.du
        self.dv = kp.dv
        self.sSize = self.k * 384
        self.tSize = self.k * 384
        self.publicKeySize = self.tSize + Kyber.rhoSize
        self.secretKeySize = self.sSize + self.publicKeySize + Kyber.hSize + Kyber.zSize
        self.cipherTextSize = (self.k * self.du + self.dv) * Kyber.N32
        self.OID = kp.oid
    }
    
    static func Round(_ a: Int, _ b: Int) -> Int {
        let (q, r) = a.quotientAndRemainder(dividingBy: b)
        return r * 2 >= b ? q + 1 : q
    }
    
    static func Compress(_ x: Int, _ d: Int) -> Int {
        assert(0 <= x && x < Kyber.Q)
        assert(0 <= d && d < 12)
        return Kyber.Round(x << d, Kyber.Q) & (1 << d - 1)
    }
    
    static func Decompress(_ x: Int, _ d: Int) -> Int {
        assert(0 <= x && x < Kyber.Q)
        assert(0 <= d && d < 12)
        return Kyber.Round(x * Kyber.Q, 1 << d)
    }

    static func H(_ seed: Bytes) -> Bytes {
        let sha = SHA3_256()
        sha.update(seed)
        return sha.digest()
    }
    
    static func G(_ seed: Bytes) -> (Bytes, Bytes) {
        let sha = SHA3_512()
        sha.update(seed)
        let x = sha.digest()
        return (Bytes(x[0 ..< 32]), Bytes(x[32 ..< 64]))
    }
    
    static func PRF(_ seed: Bytes, _ n: Int) -> Bytes {
        let shake = SHAKE256()
        shake.update(seed)
        return shake.digest(n)
    }

    static func KDF(_ seed: Bytes) -> Bytes {
        let shake = SHAKE256()
        shake.update(seed)
        return shake.digest(32)
    }
    
    // [KYBER] - Algorithm 1
    static func Parse(_ xof: XOF) -> [Int] {
        var a = [Int](repeating: 0, count: Kyber.N)
        var j = 0
        while j < Kyber.N {
            let b = xof.read(3)
            let b0 = Int(b[0])
            let b1 = Int(b[1])
            let b2 = Int(b[2])
            let d1 = b0 + (b1 & 0xf) << 8
            let d2 = b1 >> 4 + b2 << 4
            if d1 < Kyber.Q {
                a[j] = d1
                j += 1
            }
            if d2 < Kyber.Q && j < Kyber.N {
                a[j] = d2
                j += 1
            }
        }
        return a
    }

    // [KYBER] - Algorithm 2
    static func CBD(_ x: Bytes) -> Polynomial {
        assert(x.count == 128 || x.count == 192)
        let onebits: [Int] = [0, 1, 1, 2, 1, 2, 2, 3]
        var f = [Int](repeating: 0, count: Kyber.N)
        var a: Int
        var b: Int
        var bitNo = 0
        if x.count == 128 {
            for i in 0 ..< Kyber.N {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    a = Int(x[byteNo] & 0x3)
                    b = Int((x[byteNo] >> 2) & 0x3)
                case 4:
                    a = Int((x[byteNo] >> 4) & 0x3)
                    b = Int((x[byteNo] >> 6) & 0x3)
                default:
                    fatalError("CBD")
                }
                bitNo += 4
                f[i] = Polynomial.sub(onebits[a], onebits[b])
            }
        } else {
            for i in 0 ..< Kyber.N {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    a = Int(x[byteNo] & 0x7)
                    b = Int((x[byteNo] >> 3) & 0x7)
                case 2:
                    a = Int((x[byteNo] >> 2) & 0x7)
                    b = Int((x[byteNo] >> 5) & 0x7)
                case 4:
                    a = Int((x[byteNo] >> 4) & 0x7)
                    b = Int((x[byteNo] >> 7) & 0x1 | ((x[byteNo + 1] & 0x3) << 1))
                case 6:
                    a = Int((x[byteNo] >> 6) & 0x3 | ((x[byteNo + 1] & 0x1) << 2))
                    b = Int((x[byteNo + 1] >> 1) & 0x7)
                default:
                    fatalError("CBD")
                }
                bitNo += 6
                f[i] = Polynomial.sub(onebits[a], onebits[b])
            }
        }
        return Polynomial(f)
    }

    // [KYBER] - Algorithm 3
    static func Decode(_ bytes: Bytes) -> [Int] {
        assert(bytes.count & 0x1f == 0)
        let l = bytes.count >> 5
        var x = [Int](repeating: 0, count: Kyber.N)
        for i in 0 ..< x.count {
            let il = i * l
            for j in 0 ..< l {
                x[i] += (Int(bytes[(il + j) >> 3] >> ((il + j) & 0x7)) & 1) << j
            }
        }
        return x
    }

    static func Encode(_ x: [Int], _ l: Int) -> Bytes {
        assert(x.count == Kyber.N)
        assert(0 < l && l <= 12)
        var b = Bytes(repeating: 0, count: l << 5)
        for i in 0 ..< x.count {
            let il = i * l
            for j in 0 ..< l {
                if x[i] & (1 << j) != 0 {
                    b[(il + j) >> 3] |= 1 << ((il + j) & 0x7)
                }
            }
        }
        return b
    }

    // [KYBER] - Algorithm 4
    func CPAPKE_KeyGen(_ seed: Bytes = []) -> (pk: Bytes, sk: Bytes) {
        assert(seed.count == 0 || seed.count == 32)
        var d = Bytes(repeating: 0, count: 32)
        if seed.count == 0 {
            Kyber.randomBytes(&d)
        } else {
            d = seed
        }
        let (rho, sigma) = Kyber.G(d)
        var N = 0
        var Ahat = Matrix(self.k)
        for row in 0 ..< self.k {
            for col in 0 ..< self.k {
                Ahat.vector[row].polynomial[col] = Polynomial(Kyber.Parse(XOF(rho + [Byte(col), Byte(row)])))
            }
        }
        var s = Vector(self.k)
        for i in 0 ..< self.k {
            s.polynomial[i] = Kyber.CBD(Kyber.PRF(sigma + [Byte(N)], self.eta1 << 6))
            N += 1
        }
        var e = Vector(self.k)
        for i in 0 ..< self.k {
            e.polynomial[i] = Kyber.CBD(Kyber.PRF(sigma + [Byte(N)], self.eta1 << 6))
            N += 1
        }
        let sHat = s.NTT()
        let tHat = Ahat * sHat + e.NTT()
        let pk = tHat.Encode(12) + rho
        let sk = sHat.Encode(12)
        return (pk, sk)
    }
    
    //  [KYBER] - Algorithm 5
    func CPAPKE_Enc(_ pk: Bytes, _ m: Bytes, _ coins: Bytes) -> Bytes {
        assert(pk.count == 12 * self.k * Kyber.N32 + 32)
        assert(m.count == 32)
        assert(coins.count == 32)
        var N = 0
        let tHat = Vector.Decode(pk, 12)
        let rho = Bytes(pk[pk.count - 32 ..< pk.count])
        var AhatT = Matrix(self.k)
        for row in 0 ..< self.k {
            for col in 0 ..< self.k {
                AhatT.vector[row].polynomial[col] = Polynomial(Kyber.Parse(XOF(rho + [Byte(row), Byte(col)])))
            }
        }
        var r = Vector(self.k)
        for i in 0 ..< self.k {
            r.polynomial[i] = Kyber.CBD(Kyber.PRF(coins + [Byte(N)], self.eta1 << 6))
            N += 1
        }
        let rHat = r.NTT()
        var e1 = Vector(self.k)
        for i in 0 ..< self.k {
            e1.polynomial[i] = Kyber.CBD(Kyber.PRF(coins + [Byte(N)], self.eta2 << 6))
            N += 1
        }
        let e2 = Kyber.CBD(Kyber.PRF(coins + [Byte(N)], self.eta2 << 6))
        let u = ((AhatT * rHat).INTT() + e1).Compress(self.du)
        let v = ((tHat * rHat).INTT() + e2 + Polynomial(Kyber.Decode(m)).Decompress(1)).Compress(self.dv)
        return u.Encode(self.du) + v.Encode(self.dv)
    }

    //  [KYBER] - Algorithm 6
    func CPAPKE_Dec(_ sk: Bytes, _ ct: Bytes) -> Bytes {
        assert(sk.count == 12 * self.k * Kyber.N32)
        assert(ct.count == (self.du * self.k + self.dv) * Kyber.N32)
        let index = self.du * self.k * Kyber.N32
        let u = Vector.Decode(Bytes(ct[0 ..< index]), self.du).Decompress(self.du)
        let v = Polynomial(Kyber.Decode(Bytes(ct[index ..< ct.count]))).Decompress(self.dv)
        let sHat = Vector.Decode(sk, 12)
        return (v - (sHat * u.NTT()).INTT()).Compress(1).Encode(1)
    }

    // [KYBER] - Algorithm 7
    func CCAKEM_KeyGen(_ seed: Bytes) -> (pk: Bytes, sk: Bytes) {
        assert(seed.count == 0 || seed.count == 64)
        var z = Bytes(repeating: 0, count: 32)
        var s1: Bytes
        if seed.count == 0 {
            s1 = []
            Kyber.randomBytes(&z)
        } else {
            s1 = Bytes(seed[0 ..< 32])
            z = Bytes(seed[32 ..< 64])
        }
        let (pk, sk) = CPAPKE_KeyGen(s1)
        return (pk, sk + pk + Kyber.H(pk) + z)
    }
    
    // [KYBER] - Algorithm 8
    func CCAKEM_Enc(_ pk: PublicKey, _ seed: Bytes) -> (ct: Bytes, K: Bytes) {
        assert(seed.count == 0 || seed.count == 32)
        var m = Bytes(repeating: 0, count: 32)
        if seed.count == 0 {
            Kyber.randomBytes(&m)
        } else {
            m = seed
        }
        m = Kyber.H(m)
        let (_K, r) = Kyber.G(m + Kyber.H(pk.bytes))
        let ct = CPAPKE_Enc(pk.bytes, m, r)
        let K = Kyber.KDF(_K + Kyber.H(ct))
        return (ct, K)
    }

    // [KYBER] - Algorithm 9
    func CCAKEM_Dec(_ ct: Bytes, _ sk: SecretKey) -> Bytes {
        let m = CPAPKE_Dec(sk.s, ct)
        let (K, r) = Kyber.G(m + sk.h)
        let _ct = CPAPKE_Enc(sk.t + sk.rho, m, r)
        return Kyber.select(ct, _ct, Kyber.KDF(K + Kyber.H(ct)), Kyber.KDF(sk.z + Kyber.H(ct)))
    }

    // Constant-time comparison of c1 and c2
    static func select(_ c1: Bytes, _ c2: Bytes, _ ifEqual: Bytes, _ ifNotEqual: Bytes) -> Bytes {
        assert(c1.count == c2.count)
        var equal = true
        for i in 0 ..< c1.count {
            equal = equal && (c1[i] == c2[i])
        }
        return equal ? ifEqual : ifNotEqual
    }
 
}
