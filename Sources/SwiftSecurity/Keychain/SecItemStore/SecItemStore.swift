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
