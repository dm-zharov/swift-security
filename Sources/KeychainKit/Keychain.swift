//
//  Keychain.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation

enum KeychainError: Error {
    case missingSecKeyRepresentation
    case keychainWriteFailed(description: String)
    case keychainReadFailed(description: String)
    case secKeyConversionFailed
}

class Keychain: SecItemStore {
    func store(_ query: [String: Any]) throws {
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.keychainWriteFailed(description: "\(status)")
        }
    }
    
    func retrieve(_ query: [String: Any]) throws -> AnyObject? {
        var secItem: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &secItem) {
        case errSecSuccess:
            return secItem
        case errSecItemNotFound:
            return nil
        case let status:
            throw KeychainError.keychainReadFailed(description: status.description)
        }
    }
}

// MARK: - Generic Password

extension Keychain {
    func store<T: GenericPasswordConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws {
        var attributes = query.attributes
        attributes[kSecClass as String] = kSecClassGenericPassword
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes)
    }
    
    func retrieve<T: GenericPasswordConvertible>(_ query: SecItemQuery<GenericPassword>) throws -> T? {
        var attributes = query.attributes
        attributes[kSecClass as String] = kSecClassGenericPassword
        attributes[kSecReturnData as String] = true
        
        guard let data = try retrieve(attributes) as? Data else {
            return nil
        }
        return try T(rawRepresentation: data)  // Convert back to a key.
    }
}

// MARK: - Internet Password

extension Keychain {
    func store<T: GenericPasswordConvertible>(_ key: T, query: SecItemQuery<InternetPassword>) throws {
        var attributes = query.attributes
        attributes[kSecClass as String] = kSecClassInternetPassword
        attributes[kSecValueData as String] = key.rawRepresentation

        try store(attributes)
    }
    
    func retrieve<T: GenericPasswordConvertible>(_ query: SecItemQuery<InternetPassword>) throws -> T? {
        var attributes = query.attributes
        attributes[kSecClass as String] = kSecClassInternetPassword
        attributes[kSecReturnData as String] = true
        
        guard let data = try retrieve(attributes) as? Data else {
            return nil
        }
        return try T(rawRepresentation: data)  // Convert back to a key.
    }
}

// MARK: - Sec Key

extension Keychain {
    func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>) throws {
        var attributes = query.attributes
        attributes[kSecClass as String] = kSecClassKey
        if let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, nil) {
            attributes[kSecValueRef as String] = secKey
        } else {
            throw KeychainError.missingSecKeyRepresentation
        }

        try store(attributes)
    }
    
    func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>) throws -> T? {
        var attributes = query.attributes
        attributes[kSecClass as String] = kSecClassKey
        attributes[kSecReturnRef as String] = true
        
        guard let secItem = try retrieve(attributes) else {
            return nil
        }

        let secKey = secItem as! SecKey

        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw KeychainError.missingSecKeyRepresentation
        }
        
        do {
            return try T(x963Representation: data)
        } catch  {
            throw KeychainError.secKeyConversionFailed
        }
    }
}
