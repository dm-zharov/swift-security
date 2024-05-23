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
    
    func testGenericPassword() throws {
        // Keychain
        let keychain = Keychain.default

        // Query
        var query = SecItemQuery<GenericPassword>()
        query.synchronizable = true
        query.label = "label"
        query.account = "account"
        query.description = "description"
        query.comment = "comment"
        
        // Secret
        let password = "password"
        
        // Store item
        do {
            try keychain.store(password, query: query)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Check item info
        do {
            if let info = try keychain.info(for: query) {
                XCTAssertEqual(info.synchronizable, true)
                XCTAssertEqual(info.label, "label")
                XCTAssertEqual(info.account, "account")
                XCTAssertEqual(info.description, "description")
                XCTAssertEqual(info.comment, "comment")
            } else {
                XCTFail()
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Retrieve item
        do {
            let data: String? = try keychain.retrieve(query)
            XCTAssertEqual(data, password)
        }
        
        // Remove item
        do {
            let success = try keychain.remove(query)
            let data: Data? = try keychain.retrieve(query)
            XCTAssertTrue(success)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testInternetPassword() throws {
        // Keychain
        let keychain = Keychain.default
        
        // Query
        var query = SecItemQuery<InternetPassword>()
        query.synchronizable = false
        query.label = "Credential"
        query.account = "username"
        query.authenticationMethod = .httpBasic
        query.path = "/admin"
        query.port = 443
        query.protocol = .https
        query.server = "example.com"
        
        // Secret
        let password = "password"
        
        // Store item
        do {
            try keychain.store(password, query: query)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Get item info
        do {
            if let info = try keychain.info(for: query) {
                XCTAssertEqual(info.synchronizable, false)
                XCTAssertEqual(info.label, "Credential")
                XCTAssertEqual(info.account, "username")
                XCTAssertEqual(info.authenticationMethod, .httpBasic)
                XCTAssertEqual(info.path, "/admin")
                XCTAssertEqual(info.protocol, .https)
                XCTAssertEqual(info.server, "example.com")
            } else {
                XCTFail()
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Retrieve item
        do {
            let data: Data? = try keychain.retrieve(query)
            XCTAssertNotNil(data)
            XCTAssertEqual(data, password.data(using: .utf8))
        }
        
        // Remove item
        do {
            let success = try keychain.remove(query)
            let data: Data? = try keychain.retrieve(query)
            XCTAssertTrue(success)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testSecKey() throws {
        // Keychain
        let keychain = Keychain.default

        // Query
        var query = SecItemQuery<SecKey>()
        query.synchronizable = true
        query.keyClass = .private
        query.keyType = .ecsecPrimeRandom
        query.keySizeInBits = 256
        query.applicationLabel = "applicationLabel".data(using: .utf8)!
        
        // Secret
        let privateKey = P256.KeyAgreement.PrivateKey()

        // Store
        do {
            try keychain.store(privateKey, query: query)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Get item info
        do {
            if let info = try keychain.info(for: query) {
                XCTAssertEqual(info.synchronizable, true)
                XCTAssertEqual(info.keySizeInBits, 256)
                XCTAssertEqual(info.applicationLabel, "applicationLabel".data(using: .utf8)!)
                XCTAssertEqual(info.canEncrypt, false)
                XCTAssertEqual(info.canDecrypt, true)
                XCTAssertEqual(info.canDerive, true)
            } else {
                XCTFail()
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Retrieve item
        do {
            let data: P256.KeyAgreement.PrivateKey? = try keychain.retrieve(query)
            XCTAssertEqual(data?.x963Representation, privateKey.x963Representation)
        }
        
        // Remove item
        do {
            let success = try keychain.remove(query)
            let data: P256.KeyAgreement.PrivateKey? = try keychain.retrieve(query)
            XCTAssertTrue(success)
            XCTAssertNil(data)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testSecCertificate() {
        // Keychain
        let keychain = Keychain.default
        
        // Certificate
        let certificateFileURL = Bundle.main.url(forResource: "www.apple.com.root", withExtension: "der")!
        let certificateData = try! Data(contentsOf: certificateFileURL)

        let certificate: Certificate

        do {
            certificate = try Certificate(derRepresentation: certificateData)
        } catch {
            XCTFail(error.localizedDescription)
            return
        }
        
        // Store
        do {
            try keychain.store(certificate, query: .certificate(for: "Root CA"))
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Retrieve
        do {
            let certificate: Certificate? = try keychain.retrieve(.certificate(for: "Root CA"))
            XCTAssertNotNil(certificate)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Remove
        do {
            let query: SecItemQuery<SecCertificate> = .certificate(for: "Root CA")
            let success = try keychain.remove(query)
            let certificate: Certificate? = try keychain.retrieve(query)
            XCTAssertTrue(success)
            XCTAssertNil(certificate)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testSecIdentity() {
        // Keychain
        let keychain = Keychain.default
        
        // PKCS #12 Blob
        let pkcs12FileURL = Bundle.main.url(forResource: "badssl", withExtension: "p12")!
        let pkcs12Data = try! Data(contentsOf: pkcs12FileURL)

        // Import with wrong passphrase
        XCTAssertThrowsError(try keychain.import(pkcs12Data, passphrase: "random"))
        
        // Import
        let identity: Identity

        do {
            let result = try keychain.import(pkcs12Data, passphrase: "badssl.com")

            XCTAssertTrue(result.count == 1)
            let importItem = result[0]
            
            XCTAssertNotNil(importItem.identity)
            identity = importItem.identity!
        } catch {
            XCTFail(error.localizedDescription)
            return
        }
        
        // Store
        do {
            try keychain.store(identity, query: .identity(for: "badssl"))
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Retrieve
        do {
            let identity: Identity? = try keychain.retrieve(.identity(for: "badssl"))
            XCTAssertNotNil(identity)
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Remove
        do {
            let query: SecItemQuery<SecIdentity> = .identity(for: "badssl")
            let success = try keychain.remove(query)
            let identity: Identity? = try keychain.retrieve(query)
            XCTAssertTrue(success)
            XCTAssertNil(identity)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func retrieveKeyReferenceMathingPersistentReference() {
        // Keychain
        let keychain = Keychain.default
        
        // Secret
        let privateKey = P256.KeyAgreement.PrivateKey()

        // Store
        do {
            if case let .persistentReference(data) = try keychain.store(
                privateKey, returning: .persistentReference, query: .privateKey(for: "Alice")
            ) {
                // Retrieve
                let reference: SecKey? = try keychain.retrieveKeyReference(matching: data)
                XCTAssertNotNil(reference)
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func retrieveCertificateReferenceMatchingPersistentReference() {
        // Keychain
        let keychain = Keychain.default
        
        // Certificate
        let certificateURL = Bundle.main.url(forResource: "www.apple.com.root", withExtension: "der")!
        let certificateData = try! Data(contentsOf: certificateURL)

        let certificate: Certificate
        do {
            certificate = try Certificate(derRepresentation: certificateData)
        } catch {
            XCTFail(error.localizedDescription)
            return
        }

        // Store
        do {
            if case let .persistentReference(data) = try keychain.store(
                certificate, returning: .persistentReference, query: .certificate(for: "Root CA")
            ) {
                // Retrieve
                let reference: SecCertificate? = try keychain.retrieveCertificateReference(matching: data)
                XCTAssertNotNil(reference)
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testConvenientSyntax() throws {
        // Keychain
        let keychain = Keychain.default
        
        // Store
        do {
            try keychain.store("password", query: .credential(for: "service"))
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Check
        let data1 = try keychain.retrieve(.credential(for: "service"))
        let data2: Data? = try keychain.retrieve(.credential(for: "service"))
        XCTAssertEqual(data1, data2)
        
        // Remove
        do {
            try keychain.remove(.credential(for: "service"))
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testRemoveAll() throws {
        // Keychain
        let keychain = Keychain.default
        
        // Store
        do {
            try keychain.store("password", query: .credential(for: "service"))
            try keychain.store("password", query: .credential(for: "username", space: .website("https://example.com")))
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Remove
        do {
            try keychain.removeAll()
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        // Check
        do {
            let genericPassword: Data? = try keychain.retrieve(.credential(for: "service"))
            let internetPassword: Data? = try keychain.retrieve(
                .credential(for: "username", space: .website("https://example.com"))
            )
            XCTAssertNil(genericPassword)
            XCTAssertNil(internetPassword)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testAccessGroup() throws {
        /**
         Sharing within default keychain group.
         For current project configuration this is first `Keychain Sharing Group`, which is `${TeamIdentifierPrefix}CFBundleIdentifier`
         This group is automatically generated for all platforms, except macOS.
         */
        do {
            try Keychain.default.store("password", query: .credential(for: "OpenAI"))
            
            // Retrieve item
            XCTAssertNotNil({ () -> Data? in
                return try? Keychain(
                    accessGroup: .keychainGroup(teamID: "J59EP59PB8", nameID: "dev.zharov.TestHost")
                ).retrieve(.credential(for: "OpenAI"))
            }())
        } catch {
            XCTFail(error.localizedDescription)
        }
        
        #if !os(macOS)
        /**
         Sharing within App Group.
         This behavior is not present on macOS.
         */
        do {
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
        #endif
    }
}
