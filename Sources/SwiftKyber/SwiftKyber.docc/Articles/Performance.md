# Performance

## 

SwiftKyber's key generation, encapsulation and decapsulation performance was measured on an iMac 2021, Apple M1 chip.

The table below shows the times in milliseconds for the three Kyber kinds.

| Kind        | GenerateKeyPair | Encapsulate | Decapsulate |
|:------------|----------------:|------------:|------------:|
| K512        | 0.20 mSec       | 0.13 mSec   | 0.18 mSec   |
| K768        | 0.30 mSec       | 0.21 mSec   | 0.27 mSec   |
| K1024       | 0.44 mSec       | 0.32 mSec   | 0.39 mSec   |

