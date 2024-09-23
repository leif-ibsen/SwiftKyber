# Key Management

##

SwiftKyber keys can be stored in their PEM encoded ASN1 representation and recreated later.

### Example

```swift
import SwiftKyber

let (encapKey, decapKey) = Kyber.GenerateKeyPair(kind: .K512)

let decapKeyPem = decapKey.pem
let encapKeyPem = encapKey.pem

print(decapKeyPem)
print()
print(encapKeyPem)
print()

let newDecapKey = try DecapsulationKey(pem: decapKeyPem)
let newEncapKey = try EncapsulationKey(pem: encapKeyPem)

assert(newDecapKey == decapKey)
assert(newEncapKey == encapKey)

print(newDecapKey)
print(newEncapKey)
```

Giving (for example):

```
-----BEGIN PRIVATE KEY-----
MIIGeAIBADALBglghkgBZQMEBAEEggZkBIIGYOKakyORXJ02HKoFvIjIsMFcgTWBGu0kFgfZh9H3
W0KVi9lWTH5qMnW0FpK6hdZVhQIhcvBURJrrRZMyLwEQxrbsSLgqhFFIBMQWHIKjD4wQetDDj8xl

... 25 more lines

T5wmCJUSlQ0WQzlgRwz5Lnl3liaKnOejXVJu8peHW07Ee5RZwry5YvRaoFNKT8BctgwxQTSoJ4D8
ANRuWRW1IyezWDtPFsVjjGnszbO5P28GRLSdkEKU7maG1RH/elloBgrwncJ2THbhfl6JRbAIGRQb
oqHoizNTNA==
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
MIIDMjALBglghkgBZQMEBAEDggMhAIMKhBaHPxpxKz/UtBWgGEbnNMvnSiqSwuahlG0chnx6rA2j
D5QHsY6mtRdFDqmGDY+lcKw1FqtzzGG6gc2ouyIgOlwSbRbTQmWnvwYABuBjCGipH8YCUoessGLa

... 10 more lines

M2wxrlBYcUJ6f1+BnZx1fR0qarpYvs4IpihQuscoTx46hFfDpxlAsto2xDBMcFCgIA/RcE8nLDAx
GZCAS1GTgtSTXRcrv6E1BzmnuYRIeahmT5wmCJUSlQ0WQzlgRwz5Lnl3liaKnOejXVJu8peHW07E
e5RZwry5YvRaoFNKT8BctgwxQTSoJ4D8
-----END PUBLIC KEY-----

Sequence (3):
  Integer: 0
  Sequence (1):
    Object Identifier: 2.16.840.1.101.3.4.4.1
  Octet String (1636): 04 82 06 60 e2 9a 93 23 91 5c 9d 36 1c aa 05 bc 88 c8 b0 c1 5c 81 
  35 81 1a ed 24 16 07 d9 87 d1 f7 5b 42 95 8b d9 56 4c 7e 6a 32 75 b4 16 92 ba 85 d6 55
  
  ... 1500 more bytes
  
  c2 bc b9 62 f4 5a a0 53 4a 4f c0 5c b6 0c 31 41 34 a8 27 80 fc 00 d4 6e 59 15 b5 23 27
  b3 58 3b 4f 16 c5 63 8c 69 ec cd b3 b9 3f 6f 06 44 b4 9d 90 42 94 ee 66 86 d5 11 ff 7a
  59 68 06 0a f0 9d c2 76 4c 76 e1 7e 5e 89 45 b0 08 19 14 1b a2 a1 e8 8b 33 53 34

Sequence (2):
  Sequence (1):
    Object Identifier: 2.16.840.1.101.3.4.4.1
  Bit String (6400): 10000011 00001010 10000100 00010110 10000111 00111111 00011010 
   01110001 00101011 00111111 11010100 10110100 00010101 10100000 00011000 01000110
   11100111 00110100 11001011 11100111 01001010 00101010 10010010 11000010 11100110
  
   ... 6008 more bits
  
   01111011 10010100 01011001 11000010 10111100 10111001 01100010 11110100 01011010
   10100000 01010011 01001010 01001111 11000000 01011100 10110110 00001100 00110001
   01000001 00110100 10101000 00100111 10000000 11111100
```