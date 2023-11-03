// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftKyber",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftKyber",
            targets: ["SwiftKyber"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "../BigInt", from: "1.14.0"),
        .package(url: "../ASN1", from: "2.2.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftKyber",
            dependencies: ["BigInt", "ASN1"]),
        .testTarget(
            name: "SwiftKyberTests",
            dependencies: ["SwiftKyber"],
            resources: [.copy("Resources/kyber512.kat"), .copy("Resources/kyber768.kat"), .copy("Resources/kyber1024.kat")]),
    ]
)
