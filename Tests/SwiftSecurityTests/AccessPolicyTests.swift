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
            XCTAssertEqual(accessPolicy.accessibility, String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.whenUnlocked)
            XCTAssertEqual(accessPolicy.accessibility, String(kSecAttrAccessibleWhenUnlocked))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.whenUnlockedThisDeviceOnly)
            XCTAssertEqual(accessPolicy.accessibility, String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.afterFirstUnlock)
            XCTAssertEqual(accessPolicy.accessibility, String(kSecAttrAccessibleAfterFirstUnlock))
            XCTAssertNil(try accessPolicy.accessControl)
        }
        do {
            let accessPolicy = AccessPolicy(.afterFirstUnlockThisDeviceOnly)
            XCTAssertEqual(accessPolicy.accessibility, String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly))
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
