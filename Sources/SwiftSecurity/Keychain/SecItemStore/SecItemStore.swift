//
//  SecItemStore.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import LocalAuthentication

public protocol SecItemStore {
    func removeAll() throws
}

// MARK: - SecData

public protocol SecDataStore: SecItemStore {
    // MARK: - Generic
    
    func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>, accessControl: AccessControl) throws
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<GenericPassword>) throws -> Bool
    
    // MARK: - Internet
    
    func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>, accessControl: AccessControl) throws
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<InternetPassword>) throws -> Bool
}

// MARK: - SecKey

public protocol SecKeyStore: SecItemStore {
    func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>, accessControl: AccessControl) throws
    func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<SecKey>) throws -> Bool
}

// MARK: - SecCertificate

public protocol SecCertificateStore: SecItemStore {
    func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>, accessControl: AccessControl) throws
    func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext?) throws -> T?
    func remove(_ query: SecItemQuery<SecCertificate>) throws -> Bool
}

// MARK: - SecIdentity

public protocol SecIdentityStore: SecItemStore {
    func `import`<T: SecIdentityConvertible>(_ data: T, passphrase: String) throws -> [PKCS12.SecImportItem]
}
