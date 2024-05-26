//
//  AccessPolicyTests.swift
//  SwiftSecurityTests
//
//  Created by Dmitriy Zharov on 24.01.2024.
//

import XCTest
import Security

@testable import SwiftSecurity

final class AccessPolicyTests: XCTestCase {
    func testAccessibility() throws {
        do {
            let accessPolicy = AccessPolicy(.whenPasscodeSetThisDeviceOnly)
            XCTAssertEqual(accessPolicy.accessible?.rawValue, String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.whenUnlocked)
            XCTAssertEqual(accessPolicy.accessible?.rawValue, String(kSecAttrAccessibleWhenUnlocked))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.whenUnlockedThisDeviceOnly)
            XCTAssertEqual(accessPolicy.accessible?.rawValue, String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.afterFirstUnlock)
            XCTAssertEqual(accessPolicy.accessible?.rawValue, String(kSecAttrAccessibleAfterFirstUnlock))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.afterFirstUnlockThisDeviceOnly)
            XCTAssertEqual(accessPolicy.accessible?.rawValue, String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly))
            XCTAssertNil(try accessPolicy.accessControl)
        }
    }
    
    func testAccessControl() {
        do {
            let accessPolicy = AccessPolicy(.afterFirstUnlock, options: .biometryAny)
            XCTAssertNotNil(try accessPolicy.accessControl)
        }
    }
}
