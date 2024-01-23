//
//  KeychainTests.swift
//  SwiftSecurityTests
//
//  Created by Dmitriy Zharov on 23.01.2024.
//

import XCTest

@testable import SwiftSecurity

final class KeychainTests: XCTestCase {
    override func tearDown() {
        do {
            try Keychain.default.removeAll()
        } catch {
            XCTFail()
        }
    }
    
    func tests() throws {
        // given
        let keychain = Keychain.default
        let query = SecItemQuery.credential(for: "OpenAI")
        let password = "password"

        do {
            let data: String? = try keychain.retrieve(query)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        do {
            try keychain.store(password, query: query)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        do {
            let data: Data? = try keychain.retrieve(query)
            XCTAssertNotNil(data)
            XCTAssertEqual(data, password.data(using: .utf8))
        }
        
        do {
            try keychain.remove(query)
            let data: Data? = try keychain.retrieve(query)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}
