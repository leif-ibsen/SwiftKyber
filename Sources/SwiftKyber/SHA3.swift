//
//  File.swift
//  
//
//  Created by Leif Ibsen on 04/10/2023.
//

typealias Limb = UInt64
typealias Limbs = [UInt64]

class SHA3 {
    
    let RC_CONSTANTS: Limbs = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008]

    let digestLength: Int
    var buffer: Bytes
    var S: Bytes
    var totalBytes: Int
    var bytes: Int
    var state: Bytes
    var lanes: Limbs

    init(_ bufferLength: Int, _ digestLength: Int) {
        self.digestLength = digestLength
        self.buffer = Bytes(repeating: 0, count: bufferLength)
        self.S = Bytes(repeating: 0, count: 200)
        self.totalBytes = 0
        self.bytes = 0
        self.state = Bytes(repeating: 0, count: 200)
        self.lanes = Limbs(repeating: 0, count: 25)
    }

    func reset() {
        for i in 0 ..< self.buffer.count {
            self.buffer[i] = 0
        }
        for i in 0 ..< self.S.count {
            self.S[i] = 0
        }
        for i in 0 ..< self.state.count {
            self.state[i] = 0
        }
        self.totalBytes = 0
        self.bytes = 0
    }

    func update(_ input: Bytes) {
        var remaining = input.count
        var ndx = 0
        while remaining > 0 {
            let a = remaining < self.buffer.count - self.bytes ? remaining : self.buffer.count - self.bytes
            for i in 0 ..< a {
                self.buffer[self.bytes + i] = input[ndx + i]
            }
            self.bytes += a
            ndx += a
            remaining -= a
            if self.bytes == self.buffer.count {
                for i in 0 ..< self.buffer.count {
                    self.S[i] ^= self.buffer[i]
                }
                doBuffer()
                self.bytes = 0
            }
        }
        self.totalBytes += input.count
    }

    func digest() -> Bytes {
        var padBytes = Bytes(repeating: 0, count: self.buffer.count - self.bytes % self.buffer.count)
        padBytes[0] = 0x06
        padBytes[padBytes.count - 1] |= 0x80
        self.update(padBytes)

        assert(self.totalBytes % self.buffer.count == 0)

        let Z = Bytes(self.S[0 ..< self.digestLength])
        self.reset()
        return Z
    }

    func doBuffer() {
        toLanes()
        for i in 0 ..< 24 {
            theta()
            phiRho()
            chi()
            iota(i)
        }
        fromLanes()
    }

    func toLanes() {
        for y in 0 ..< 5 {
            for x in 0 ..< 5 {
                var b = Limb(0)
                for i in 0 ..< 8 {
                    b |= Limb(self.S[8 * (5 * y + x) + i]) << (i * 8)
                }
                self.lanes[5 * y + x] = b
            }
        }
    }

    func fromLanes() {
        for y in 0 ..< 5 {
            for x in 0 ..< 5 {
                var b = self.lanes[5 * y + x]
                for i in 0 ..< 8 {
                    self.S[8 * (5 * y + x) + i] = Byte(b & 0xff)
                    b >>= 8
                }
            }
        }
    }

    func theta() {
        let c0 = self.lanes[0] ^ self.lanes[5] ^ self.lanes[10] ^ self.lanes[15] ^ self.lanes[20]
        let c1 = self.lanes[1] ^ self.lanes[6] ^ self.lanes[11] ^ self.lanes[16] ^ self.lanes[21]
        let c2 = self.lanes[2] ^ self.lanes[7] ^ self.lanes[12] ^ self.lanes[17] ^ self.lanes[22]
        let c3 = self.lanes[3] ^ self.lanes[8] ^ self.lanes[13] ^ self.lanes[18] ^ self.lanes[23]
        let c4 = self.lanes[4] ^ self.lanes[9] ^ self.lanes[14] ^ self.lanes[19] ^ self.lanes[24]
        let d0 = c4 ^ SHA3.rotateLeft(c1, 1)
        let d1 = c0 ^ SHA3.rotateLeft(c2, 1)
        let d2 = c1 ^ SHA3.rotateLeft(c3, 1)
        let d3 = c2 ^ SHA3.rotateLeft(c4, 1)
        let d4 = c3 ^ SHA3.rotateLeft(c0, 1)
        for y in stride(from: 0, through: 20, by: 5) {
            self.lanes[y] ^= d0
            self.lanes[y + 1] ^= d1
            self.lanes[y + 2] ^= d2
            self.lanes[y + 3] ^= d3
            self.lanes[y + 4] ^= d4
        }
    }
    
    func phiRho() {
        let tmp = SHA3.rotateLeft(self.lanes[10], 3)
        self.lanes[10] = SHA3.rotateLeft(self.lanes[1], 1)
        self.lanes[1] = SHA3.rotateLeft(self.lanes[6], 44)
        self.lanes[6] = SHA3.rotateLeft(self.lanes[9], 20)
        self.lanes[9] = SHA3.rotateLeft(self.lanes[22], 61)
        self.lanes[22] = SHA3.rotateLeft(self.lanes[14], 39)
        self.lanes[14] = SHA3.rotateLeft(self.lanes[20], 18)
        self.lanes[20] = SHA3.rotateLeft(self.lanes[2], 62)
        self.lanes[2] = SHA3.rotateLeft(self.lanes[12], 43)
        self.lanes[12] = SHA3.rotateLeft(self.lanes[13], 25)
        self.lanes[13] = SHA3.rotateLeft(self.lanes[19], 8)
        self.lanes[19] = SHA3.rotateLeft(self.lanes[23], 56)
        self.lanes[23] = SHA3.rotateLeft(self.lanes[15], 41)
        self.lanes[15] = SHA3.rotateLeft(self.lanes[4], 27)
        self.lanes[4] = SHA3.rotateLeft(self.lanes[24], 14)
        self.lanes[24] = SHA3.rotateLeft(self.lanes[21], 2)
        self.lanes[21] = SHA3.rotateLeft(self.lanes[8], 55)
        self.lanes[8] = SHA3.rotateLeft(self.lanes[16], 45)
        self.lanes[16] = SHA3.rotateLeft(self.lanes[5], 36)
        self.lanes[5] = SHA3.rotateLeft(self.lanes[3], 28)
        self.lanes[3] = SHA3.rotateLeft(self.lanes[18], 21)
        self.lanes[18] = SHA3.rotateLeft(self.lanes[17], 15)
        self.lanes[17] = SHA3.rotateLeft(self.lanes[11], 10)
        self.lanes[11] = SHA3.rotateLeft(self.lanes[7], 6)
        self.lanes[7] = tmp
    }
    
    func chi() {
        for y in stride(from: 0, through: 20, by: 5) {
            let ay0 = self.lanes[y]
            let ay1 = self.lanes[y + 1]
            let ay2 = self.lanes[y + 2]
            let ay3 = self.lanes[y + 3]
            let ay4 = self.lanes[y + 4]
            self.lanes[y] = ay0 ^ ((~ay1) & ay2)
            self.lanes[y + 1] = ay1 ^ ((~ay2) & ay3)
            self.lanes[y + 2] = ay2 ^ ((~ay3) & ay4)
            self.lanes[y + 3] = ay3 ^ ((~ay4) & ay0)
            self.lanes[y + 4] = ay4 ^ ((~ay0) & ay1)
        }
    }
    
    func iota(_ r: Int) {
        self.lanes[0] ^= RC_CONSTANTS[r]
    }

    static func rotateLeft(_ x: Limb, _ n: Int) -> Limb {
        return (x << n) | (x >> (64 - n))
    }

}

class SHA3_128: SHA3 {

    init() {
        super.init(168, 16)
    }
}

class SHA3_256: SHA3 {

    init() {
        super.init(136, 32)
    }
}

class SHA3_512: SHA3 {

    init() {
        super.init(72, 64)
    }

}
