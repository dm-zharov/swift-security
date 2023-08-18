//
//  SecKeyStore.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation

protocol SecKeyStore {
    // MARK: - Sec Key
    
    func storeKey<T: SecKeyConvertible>(_ key: T, label: String) throws
    func retrieveKey<T: SecKeyConvertible>(_ label: String) throws -> T?
    @discardableResult
    func removeKey(label: String) -> Bool
    
    // MARK: - Generic Password
    
    func storeKey<T: GenericPasswordConvertible>(_ key: T, account: String) throws
    func retrieveKey<T: GenericPasswordConvertible>(_ account: String) throws -> T?
    @discardableResult
    func removeKey(account: String) -> Bool
    
    // MARK: - Any
    
    @discardableResult
    func removeAll() -> Bool
}
