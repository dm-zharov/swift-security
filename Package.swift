// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-security",
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
            dependencies: [],
            swiftSettings: [.enableUpcomingFeature("StrictConcurrency")]
        ),
        .testTarget(
            name: "SwiftSecurityTests",
            dependencies: [
                .target(name: "SwiftSecurity"),
            ],
            resources: [.process("Resources")]
        ),
    ]
)
