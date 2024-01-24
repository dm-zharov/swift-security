//
//  Keychain.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public struct Keychain: Hashable, Codable, Sendable {
    private let accessGroup: String?

    private init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }
}

extension Keychain {
    public static let `default` = Keychain(accessGroup: .default)
    
    /**
     Create.
     
     - Parameter accessGroup: The corresponding value indicates the item’s one and only access group.
     
     For an app to access a keychain item, one of the groups to which the app belongs must be the item’s group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string
     - The strings in the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     Two or more apps that are in the same access group can share keychain items. For more details, see Sharing access to keychain items among a collection of apps.
     */
    public init(accessGroup: AccessGroup) {
        switch accessGroup {
        case .default:
            self.init(accessGroup: nil)
        case let .keychainGroup(teamID: teamID, nameID: nameID):
            self.init(accessGroup: "\(teamID).\(nameID)")
        case let .appGroupID(nameID):
            self.init(accessGroup: "\(nameID)")
        case .token:
            self.init(accessGroup: kSecAttrAccessGroupToken as String)
        }
    }
}

// MARK: - GenericPassword

extension Keychain: SecDataStore {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws {
        try store(key, query: query, accessPolicy: .default)
    }
    
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>, accessPolicy: SecAccessPolicy) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes, accessPolicy: accessPolicy)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>) throws -> T? {
        return try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        
        guard let data = try retrieve(attributes, authenticationContext: authenticationContext) as? Data else {
            return nil
        }

        return try T(rawRepresentation: data)  // Convert back to a key.
    }
    
    @discardableResult
    public func remove(_ query: SecItemQuery<GenericPassword>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - InternetPassword

extension Keychain {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>) throws {
        try store(key, query: query, accessPolicy: .default)
    }
    
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>, accessPolicy: SecAccessPolicy) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes, accessPolicy: accessPolicy)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>) throws -> T? {
        return try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        
        guard let data = try retrieve(attributes, authenticationContext: authenticationContext) as? Data else {
            return nil
        }

        return try T(rawRepresentation: data)  // Convert back to a key.
    }
    
    @discardableResult
    public func remove(_ query: SecItemQuery<InternetPassword>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - SecKey

extension Keychain: SecKeyStore {
    public func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>) throws {
        try store(key, query: query, accessPolicy: .default)
    }
    
    public func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>, accessPolicy: SecAccessPolicy) throws {
        var attributes = query.attributes
        
        var error: Unmanaged<CFError>?
        if let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) {
            attributes[kSecValueRef as String] = secKey
        } else {
            if let error = error?.takeUnretainedValue() {
                throw SwiftSecurityError(error: error)
            } else {
                throw SwiftSecurityError(rawValue: errSecBadReq)
            }
        }

        try store(attributes, accessPolicy: accessPolicy)
    }
    
    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>) throws -> T? {
        return try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        guard let result = try retrieve(attributes, authenticationContext: authenticationContext) else {
            return nil
        }

        let secKey = result as! SecKey

        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            if let error = error?.takeUnretainedValue() {
                throw SwiftSecurityError(error: error)
            } else {
                throw SwiftSecurityError(rawValue: errSecBadReq)
            }
        }

        return try T(x963Representation: data)
    }
    
    @discardableResult
    public func remove(_ query: SecItemQuery<SecKey>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - SecCertificate

extension Keychain: SecCertificateStore {
    public func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>) throws {
        try store(data, query: query, accessPolicy: .default)
    }
    
    public func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>, accessPolicy: SecAccessPolicy) throws {
        guard let certificate = SecCertificateCreateWithData(nil, data.derRepresentation as CFData) else {
            throw SwiftSecurityError(rawValue: errSecConversionError)
        }
        
        var attributes = query.attributes
        attributes[kSecValueRef as String] = certificate
        
        try store(attributes, accessPolicy: accessPolicy)
    }
    
    public func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>) throws -> T? {
        return try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        guard let result = try retrieve(attributes, authenticationContext: authenticationContext) else {
            return nil
        }
        
        let certificate = result as! SecCertificate
        let data = SecCertificateCopyData(certificate) as Data
    
        return try T(derRepresentation: data)
    }
    
    @discardableResult
    public func remove(_ query: SecItemQuery<SecCertificate>) throws -> Bool {
        let attributes = query.attributes

        return try remove(attributes)
    }
}

// MARK: - SecIdentity

extension Keychain: SecIdentityStore {
    public func `import`<T: SecIdentityConvertible>(_ data: T, passphrase: String) throws -> [PKCS12.SecImportItem] {
        let attributes = [kSecImportExportPassphrase as String: passphrase]
        
        var result: CFArray?
        switch SecPKCS12Import(data.pkcs12Representation as CFData, attributes as CFDictionary, &result) {
        case errSecSuccess:
            if let items = result as? Array<[String: Any]> {
                return items.map { item in
                    PKCS12.SecImportItem(attributes: item)
                }
            } else {
                return []
            }
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    public func store(_ item: PKCS12.SecImportItem, query: SecItemQuery<SecIdentity>) throws {
        try store(item, query: query, accessPolicy: .default)
    }
    
    public func store(_ item: PKCS12.SecImportItem, query: SecItemQuery<SecIdentity>, accessPolicy: SecAccessPolicy) throws {
        guard let identity = item.identity else {
            throw SwiftSecurityError(rawValue: errSecMissingValue)
        }
        
        var attributes = query.attributes
        attributes[kSecValueRef as String] = identity
        
        try store(attributes, accessPolicy: accessPolicy)
    }
    
    public func retrieve(_ query: SecItemQuery<SecIdentity>) throws -> SecIdentity? {
        return try retrieve(query, authenticationContext: nil)
    }
    
    public func retrieve(_ query: SecItemQuery<SecIdentity>, authenticationContext: LAContext?) throws -> SecIdentity? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        return try retrieve(attributes, authenticationContext: authenticationContext) as! SecIdentity?
    }
    
    @discardableResult
    public func remove(_ query: SecItemQuery<SecIdentity>) throws -> Bool {
        let attributes = query.attributes
        return try remove(attributes)
    }
}

// MARK: - Common

extension Keychain: SecItemStore {
    public func info<SecItem>(for query: SecItemQuery<SecItem>) throws -> SecItemInfo<SecItem>? {
        return try info(for: query, authenticationContext: nil)
    }
    
    public func info<SecItem>(for query: SecItemQuery<SecItem>, authenticationContext: LAContext?) throws -> SecItemInfo<SecItem>? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnAttributes as String] = true
        
        guard let result = try retrieve(attributes, authenticationContext: nil) as? [String: Any] else {
            return nil
        }
        
        return SecItemInfo<SecItem>(result)
    }
    
    public func removeAll() throws {
        try remove(SecItemQuery<GenericPassword>())
        try remove(SecItemQuery<InternetPassword>())
        try remove(SecItemQuery<SecKey>())
        try remove(SecItemQuery<SecCertificate>())
        try remove(SecItemQuery<SecIdentity>())
    }
}

private extension Keychain {
    func store(_ query: [String: Any], accessPolicy: SecAccessPolicy) throws {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        query[kSecAttrAccessControl as String] = try accessPolicy.accessControl
        query[kSecAttrAccessible as String] = accessPolicy.accessibility
        
        switch SecItemAdd(query as CFDictionary, nil) {
        case errSecSuccess:
            return
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    func retrieve(_ query: [String: Any], authenticationContext: LAContext?) throws -> AnyObject? {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        var result: AnyObject?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            return result
        case errSecItemNotFound:
            return nil
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    @discardableResult
    func remove(_ query: [String: Any]) throws -> Bool {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        
        switch SecItemDelete(query as CFDictionary) {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
}

extension Keychain: CustomStringConvertible {
    public var description: String {
        return "Keychain(accessGroup: \(accessGroup ?? ".default"))"
    }
}

extension Keychain: CustomDebugStringConvertible {
    public var debugDescription: String {
        #if os(watchOS) || os(tvOS)
        let context: LAContext? = nil
        #else
        let context: LAContext? = LAContext()
        context?.localizedReason = "A debugger is requesting access to the protected items stored in the keychain."
        #endif
        
        func retrieveAll<S: SecItem>(_ query: SecItemQuery<S>) -> Array<[String: Any]> where S: SecItem {
            var attributes = query.attributes
            attributes[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
            attributes[kSecMatchLimit as String] = kSecMatchLimitAll
            attributes[kSecReturnAttributes as String] = true
            
            if let items = try? retrieve(attributes, authenticationContext: context) as? Array<[String: Any]> {
                return items
            } else {
                return []
            }
        }
        
        var attributes: Array<[String: Any]> = []
        attributes.append(contentsOf: retrieveAll(SecItemQuery<GenericPassword>()))
        attributes.append(contentsOf: retrieveAll(SecItemQuery<InternetPassword>()))
        attributes.append(contentsOf: retrieveAll(SecItemQuery<SecKey>()))
        attributes.append(contentsOf: retrieveAll(SecItemQuery<SecCertificate>()))
        attributes.append(contentsOf: retrieveAll(SecItemQuery<SecIdentity>()))
        
        return attributes.debugDescription
    }
}

#if os(watchOS) || os(tvOS)
public struct LAContext {
    @available(watchOS, unavailable)
    @available(tvOS, unavailable)
    public init() { }
}
#endif
