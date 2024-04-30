//
//  SecItemStore.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public protocol SecItemStore {
    func retrieve<SecItem>(_ returnType: SecReturnType, query: SecItemQuery<SecItem>, authenticationContext: LAContext?) throws -> SecValue<SecItem>?
    func retrieveAll<SecItem>(_ returnType: SecReturnType, query: SecItemQuery<SecItem>) throws -> [SecValue<SecItem>]
    func removeAll() throws
}

public extension SecItemStore {
    func info<SecItem>(for query: SecItemQuery<SecItem>, authenticationContext: LAContext? = nil) throws -> SecItemInfo<SecItem>? {
        if let value = try retrieve(.info, query: query, authenticationContext: authenticationContext), case let .dictionary(info) = value {
            return info
        } else {
            return nil
        }
    }
}

// MARK: - Data

public protocol SecDataStore: SecItemStore {
    // MARK: - Generic Password
    
    func store<T: SecDataConvertible>(_ data: T, returning returnType: SecReturnType, query: SecItemQuery<GenericPassword>, accessPolicy: AccessPolicy) throws -> SecValue<GenericPassword>?
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<GenericPassword>) throws -> Bool
    
    // MARK: - Internet Password
    
    func store<T: SecDataConvertible>(_ data: T, query: SecItemQuery<InternetPassword>, accessPolicy: AccessPolicy) throws
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<InternetPassword>) throws -> Bool
}

public extension SecDataStore {
    func store<T: SecDataConvertible>(_ data: T, query: SecItemQuery<GenericPassword>, accessPolicy: AccessPolicy) throws {
        try self.store(data, returning: [], query: query, accessPolicy: accessPolicy)
    }
    
    func retrieve(_ query: SecItemQuery<GenericPassword>) throws -> Data? {
        try self.retrieve<Data>(query, authenticationContext: nil)
    }

    func retrieve(_ query: SecItemQuery<InternetPassword>) throws -> Data? {
        try self.retrieve<Data>(query, authenticationContext: nil)
    }
}

// MARK: - SecKey

public protocol SecKeyStore: SecItemStore {
    func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>, accessPolicy: AccessPolicy) throws
    func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<SecKey>) throws -> Bool
}

// MARK: - SecCertificate

public protocol SecCertificateStore: SecItemStore {
    func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>, accessPolicy: AccessPolicy) throws
    func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<SecCertificate>) throws -> Bool
}

// MARK: - SecIdentity

public protocol SecIdentityStore: SecItemStore {
    func `import`<T: SecIdentityConvertible>(_ data: T, passphrase: String) throws -> [PKCS12.SecImportItem]
    func store(_ item: PKCS12.SecImportItem, query: SecItemQuery<SecIdentity>, accessPolicy: AccessPolicy) throws
    func retrieve(_ query: SecItemQuery<SecIdentity>, authenticationContext: LAContext?) throws -> SecIdentity?
    func remove(_ query: SecItemQuery<SecIdentity>) throws -> Bool
}
