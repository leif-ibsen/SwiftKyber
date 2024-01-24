# Performance

## 

SwiftKyber's key generation, encapsulation and decapsulation performance was measured on an iMac 2021, Apple M1 chip.
The table below shows the times in milli seconds for the three Kyber instances.

| Instance    | GenerateKeyPair | Encapsulate | Decapsulate |
|-------------|-----------------|-------------|-------------|
| Kyber.K512  | 0.15 mSec       | 0.13 mSec   | 0.18 mSec   |
| Kyber.K768  | 0.24 mSec       | 0.21 mSec   | 0.27 mSec   |
| Kyber.K1024 | 0.36 mSec       | 0.32 mSec   | 0.39 mSec   |

