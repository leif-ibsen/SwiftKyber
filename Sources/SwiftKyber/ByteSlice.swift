//
//  ByteSlice.swift
//  Slice
//
//  Created by Leif Ibsen on 09/12/2023.
//

struct ByteSlice {
    
    var array: Bytes
    var from: Int
    
    init(_ array: Bytes) {
        self.array = array
        self.from = 0
    }
    
    mutating func next(_ n: Int) -> Bytes {
        let bytes = Bytes(self.array[self.from ..< self.from + n])
        self.from += n
        return bytes
    }
    
}


extension Array where Element == Byte {
    
    func sliced() -> ByteSlice {
        return ByteSlice(self)
    }
    
}
