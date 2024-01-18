//
//  SecItemStore.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation

// MARK: - SecData

public protocol SecDataStore {
    // MARK: - Generic
    
    func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>) throws -> T?
    func remove(query: SecItemQuery<GenericPassword>) throws -> Bool
    
    // MARK: - Internal
    
    func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>) throws
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>) throws -> T?
    func remove(query: SecItemQuery<InternetPassword>) throws -> Bool
}

// MARK: - SecKey

public protocol SecKeyStore {
    func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>) throws
    func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>) throws -> T?
    func remove(query: SecItemQuery<SecKey>) throws -> Bool
}
