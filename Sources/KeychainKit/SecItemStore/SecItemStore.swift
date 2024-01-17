//
//  SecItemStore.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation

public protocol SecItemStore {
    // MARK: - Generic Password
    
    func store<T: GenericPasswordConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws
    func retrieve<T: GenericPasswordConvertible>(_ query: SecItemQuery<GenericPassword>) throws -> T?
    
    // MARK: - Internet Password
    
    func store<T: GenericPasswordConvertible>(_ key: T, query: SecItemQuery<InternetPassword>) throws
    func retrieve<T: GenericPasswordConvertible>(_ query: SecItemQuery<InternetPassword>) throws -> T?
    
    // MARK: - SecKey
    
    func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>) throws
    func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>) throws -> T?
}
