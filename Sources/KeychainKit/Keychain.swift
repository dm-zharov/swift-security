//
//  Keychain.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation

class Keychain: SecKeyStore {
    enum Errors: Error {
        case missingSecKeyRepresentation
        case keychainWriteFailed(description: String)
        case keychainReadFailed(description: String)
        case secKeyConversionFailed
    }
}

// MARK: - Sec Key

extension Keychain {
    func storeKey<T: SecKeyConvertible>(_ key: T, label: String) throws {
        let attributes = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate
        ] as [String: Any]

        guard let secKey = SecKeyCreateWithData(
            key.x963Representation as CFData,
            attributes as CFDictionary,
            nil
        ) else {
            throw Errors.missingSecKeyRepresentation
        }
        
        let query = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: label,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
            kSecUseDataProtectionKeychain: true,
            kSecValueRef: secKey
        ] as [String: Any]

        // Add the key to the keychain.
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Errors.keychainWriteFailed(description: "\(status)")
        }
    }
    
    func retrieveKey<T: SecKeyConvertible>(_ label: String) throws -> T? {
        let query = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationLabel: label,
            kSecUseDataProtectionKeychain: true,
            kSecReturnRef: true
        ] as [String: Any]
        
        var item: CFTypeRef?
        var secKey: SecKey
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            secKey = item as! SecKey
        case errSecItemNotFound:
            return nil
        case let status:
            throw Errors.keychainReadFailed(description: status.description)
        }
        
        // Convert the SecKey into a CryptoKit key.
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw Errors.missingSecKeyRepresentation
        }
        
        do {
            return try T(x963Representation: data)
        } catch  {
            throw Errors.secKeyConversionFailed
        }
    }
    
    @discardableResult
    func removeKey(label: String) -> Bool {
        let query = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationLabel: label
        ] as [String: Any]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}

// MARK: - Generic Password

extension Keychain {
    func storeKey<T: GenericPasswordConvertible>(_ key: T, account: String) throws {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
            kSecUseDataProtectionKeychain: true,
            kSecValueData: key.rawRepresentation
        ] as [String: Any]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Errors.keychainWriteFailed(description: "\(status)")
        }
    }
    
    func retrieveKey<T: GenericPasswordConvertible>(_ account: String) throws -> T? {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
            kSecReturnData: true
        ] as [String: Any]

        // Find and cast the result as data.
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data else { return nil }
            return try T(rawRepresentation: data)  // Convert back to a key.
        case errSecItemNotFound:
            return nil
        case let status:
            throw Errors.keychainReadFailed(description: status.description)
        }
    }
    
    @discardableResult
    func removeKey(account: String) -> Bool {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account
        ] as [String: Any]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}

// MARK: - Common

extension Keychain {
    @discardableResult
    func removeAll() -> Bool {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecMatchLimit: kSecMatchLimitAll
        ] as [String: Any]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}
