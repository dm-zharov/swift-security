// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftSecurity",
    platforms: [.iOS(.v14), .macOS(.v11), .macCatalyst(.v14), .watchOS(.v7), .tvOS(.v14)],
    products: [
        .library(
            name: "SwiftSecurity",
            targets: ["SwiftSecurity"]
        ),
    ],
    targets: [
        .target(
            name: "SwiftSecurity",
            dependencies: []
        ),
    ]
)
