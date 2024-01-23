//
//  KeychainTests.swift
//  SwiftSecurityTests
//
//  Created by Dmitriy Zharov on 23.01.2024.
//

import XCTest
import CryptoKit

@testable import SwiftSecurity

final class KeychainTests: XCTestCase {
    override func setUp() {
        self.addTeardownBlock {
            try? Keychain.default.removeAll()
        }
    }
    
    #if os(macOS)
    func testAccessGroup() throws {
        do {
            // when
            try Keychain.default.store("password", query: .credential(for: "OpenAI"))
            
            // then
            XCTAssertNotNil({ () -> Data? in
                return try? Keychain(
                    accessGroup: .keychainGroup(teamID: "J59EP59PB8", nameID: "dev.zharov.TestHost")
                ).retrieve(.credential(for: "OpenAI"))
            }())
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    #else
    func testAccessGroup() throws {
        do {
            // given
            let keychain = Keychain.default
            
            // when
            try keychain.store("password", query: .credential(for: "OpenAI"))
            
            // then
            XCTAssertNotNil({ () -> Data? in
                return try? keychain.retrieve(.credential(for: "OpenAI"))
            }())
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        do {
            // given
            let keychain = Keychain(accessGroup: .appGroupID("group.dev.zharov.TestHost"))

            // when
            try keychain.store("password", query: .credential(for: "OpenAI"))
            
            // then
            XCTAssertNotNil({ () -> Data? in
                try? keychain.retrieve(.credential(for: "OpenAI"))
            }())
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    #endif
    
    func testGenericPassword() throws {
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
            if let info = try keychain.info(for: query) {
                XCTAssertNotNil(info.service)
            } else {
                XCTFail()
            }
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
    
    func testInternetPassword() throws {
        let keychain = Keychain.default
        let query = SecItemQuery.credential(for: "username", space: .website("https://example.com"))
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
    
    func testSecKey() throws {
        let keychain = Keychain.default

        var query = SecItemQuery<SecKey>()
        query.keyClass = .private
        query.keyType = .ecsecPrimeRandom
        query.keySizeInBits = 256
        
        let privateKey = P256.KeyAgreement.PrivateKey()

        do {
            let data: P256.KeyAgreement.PrivateKey? = try keychain.retrieve(query)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        do {
            try keychain.store(privateKey, query: query)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        do {
            let data: P256.KeyAgreement.PrivateKey? = try keychain.retrieve(query)
            XCTAssertNotNil(data)
            XCTAssertEqual(data?.x963Representation, privateKey.x963Representation)
        }
        
        do {
            try keychain.remove(query)
            let data: P256.KeyAgreement.PrivateKey? = try keychain.retrieve(query)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}
