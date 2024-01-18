//
//  Keychain.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import LocalAuthentication

public class Keychain {
    private let accessGroup: String?

    private init(accessGroup: String?) {
        self.accessGroup = nil
    }
}

public extension Keychain {
    // MARK: - Public
    
    public static let `default` = Keychain(accessGroup: nil)
    
    /**
     Create.
     
     - Parameter accessGroup: The corresponding value indicates the item’s one and only access group.
     
     For an app to access a keychain item, one of the groups to which the app belongs must be the item’s group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string
     - The strings in the [App Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     Two or more apps that are in the same access group can share keychain items. For more details, see Sharing access to keychain items among a collection of apps.
     */
    public convenience init(accessGroup: String) {
        assert(!accessGroup.isEmpty)
        self.init(accessGroup: accessGroup)
    }
}

// MARK: - Generic Password

extension Keychain: SecDataStore {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>) throws -> T? {
        try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        
        if let authenticationContext {
            attributes[kSecUseAuthenticationContext as String] = authenticationContext
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

extension Keychain {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>) throws -> T? {
        try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        
        if let authenticationContext {
            attributes[kSecUseAuthenticationContext as String] = authenticationContext
            attributes[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
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

extension Keychain: SecKeyStore {
    public func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>) throws {
        var attributes = query.attributes
        
        var error: Unmanaged<CFError>?
        if let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) {
            attributes[kSecValueRef as String] = secKey
        } else {
            throw SwiftSecurityError.missingSecKeyRepresentation
        }

        try store(attributes)
    }
    
    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>) throws -> T? {
        try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        if let authenticationContext {
            attributes[kSecUseAuthenticationContext as String] = authenticationContext
            attributes[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        guard let secItem = try retrieve(attributes) else {
            return nil
        }

        let secKey = secItem as! SecKey

        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw SwiftSecurityError.missingSecKeyRepresentation
        }
        
        do {
            return try T(x963Representation: data)
        } catch  {
            throw SwiftSecurityError.failedSecKeyConversion
        }
    }
    
    @discardableResult
    public func remove(query: SecItemQuery<SecKey>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - Common

extension Keychain {
    private func store(_ query: [String: Any]) throws {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        
        switch SecItemAdd(query as CFDictionary, nil){
        case errSecSuccess:
            return
        case let status:
            throw SwiftSecurityError.failedToWriteItem(description: status.debugDescription)
        }
    }
    
    private func retrieve(_ query: [String: Any]) throws -> AnyObject? {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        
        var secItem: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &secItem) {
        case errSecSuccess:
            return secItem
        case errSecItemNotFound:
            return nil
        case let status:
            throw SwiftSecurityError.failedToReadItem(description: status.debugDescription)
        }
    }
    
    private func remove(_ query: [String: Any]) throws -> Bool {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        
        switch SecItemDelete(query as CFDictionary) {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        case let status:
            throw SwiftSecurityError.failedToRemoveItem(description: status.debugDescription)
        }
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
