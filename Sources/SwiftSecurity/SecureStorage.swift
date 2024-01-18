//
//  CredentialStorage.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation

public class SecureStorage {
    private func store(_ query: [String: Any]) throws {
        switch SecItemAdd(query as CFDictionary, nil){
        case errSecSuccess:
            return
        case let status:
            throw SecureStorageError.failedToWriteItem(description: status.debugDescription)
        }
    }
    
    private func retrieve(_ query: [String: Any]) throws -> AnyObject? {
        var secItem: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &secItem) {
        case errSecSuccess:
            return secItem
        case errSecItemNotFound:
            return nil
        case let status:
            throw SecureStorageError.failedToReadItem(description: status.debugDescription)
        }
    }
    
    private func remove(_ query: [String: Any]) throws -> Bool {
        switch SecItemDelete(query as CFDictionary) {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        case let status:
            throw SecureStorageError.failedToRemoveItem(description: status.debugDescription)
        }
    }
    
    private init() { }
}

extension SecureStorage {
    public static let `default` = SecureStorage()
}

// MARK: - Generic Password

extension SecureStorage: GenericPasswordStore {
    public func store<T: GenericPasswordConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes)
    }
    
    public func retrieve<T: GenericPasswordConvertible>(_ query: SecItemQuery<GenericPassword>) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        
        if let authenticationContext = query.authenticationContext {
            /**
             Prevent system UI from automatically requesting `Touch ID/Face ID` authentication.
             Just in case someone passes here an ``LAContext`` instance without a prior ``evaluateAccessControl`` call.
             */
            attributes[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        guard let data = try retrieve(attributes) as? Data else {
            return nil
        }
        return try T(rawRepresentation: data)  // Convert back to a key.
    }
    
    @discardableResult
    public func remove(query: SecItemQuery<GenericPassword>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - Internet Password

extension SecureStorage: InternetPasswordStore {
    public func store<T: GenericPasswordConvertible>(_ key: T, query: SecItemQuery<InternetPassword>) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes)
    }
    
    public func retrieve<T: GenericPasswordConvertible>(_ query: SecItemQuery<InternetPassword>) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        
        guard let data = try retrieve(attributes) as? Data else {
            return nil
        }
        return try T(rawRepresentation: data)  // Convert back to a key.
    }
    
    @discardableResult
    public func remove(query: SecItemQuery<InternetPassword>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - Sec Key

extension SecureStorage: SecKeyStore {
    public func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>) throws {
        var attributes = query.attributes
        
        var error: Unmanaged<CFError>?
        if let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) {
            attributes[kSecValueRef as String] = secKey
        } else {
            throw SecureStorageError.missingSecKeyRepresentation
        }

        try store(attributes)
    }
    
    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        guard let secItem = try retrieve(attributes) else {
            return nil
        }

        let secKey = secItem as! SecKey

        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw SecureStorageError.missingSecKeyRepresentation
        }
        
        do {
            return try T(x963Representation: data)
        } catch  {
            throw SecureStorageError.failedSecKeyConversion
        }
    }
    
    @discardableResult
    public func remove(query: SecItemQuery<SecKey>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

extension OSStatus: CustomDebugStringConvertible {
    public var debugDescription: String {
        if let debugDescription = SecCopyErrorMessageString(self, nil) as String? {
            return debugDescription
        } else {
            return description
        }
    }
}
