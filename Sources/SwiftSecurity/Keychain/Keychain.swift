//
//  Keychain.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import LocalAuthentication

public struct Keychain: Hashable, Codable, Sendable {
    private let accessGroup: String?

    private init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }
}

public extension Keychain {
    static let `default` = Keychain(accessGroup: .default)
    
    /**
     Create.
     
     - Parameter accessGroup: The corresponding value indicates the item’s one and only access group.
     
     For an app to access a keychain item, one of the groups to which the app belongs must be the item’s group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string
     - The strings in the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     Two or more apps that are in the same access group can share keychain items. For more details, see Sharing access to keychain items among a collection of apps.
     */
    init(accessGroup: AccessGroup) {
        switch accessGroup {
        case .default:
            self.init(accessGroup: nil)
        case .keychainGroup(let teamID, let nameID):
            self.init(accessGroup: "\(teamID).\(nameID)")
        case .appID:
            self.init(accessGroup: Bundle.main.bundleIdentifier)
        case .appGroupID(let groupID):
            self.init(accessGroup: groupID)
        }
    }
}

// MARK: - GenericPassword

extension Keychain: SecDataStore {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>) throws {
        try store(key, query: query, accessControl: AccessControl())
    }
    
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>, accessControl: AccessControl) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes, accessControl: accessControl.rawValue)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext? = nil) throws -> T? {
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
        try store(key, query: query, accessControl: AccessControl())
    }
    
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>, accessControl: AccessControl) throws {
        var attributes = query.attributes
        attributes[kSecValueData as String] = key.rawRepresentation
        
        try store(attributes, accessControl: accessControl.rawValue)
    }
    
    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext? = nil) throws -> T? {
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
        try store(key, query: query, accessControl: AccessControl())
    }
    
    public func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>, accessControl: AccessControl) throws {
        var attributes = query.attributes
        
        var error: Unmanaged<CFError>?
        if let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) {
            attributes[kSecValueRef as String] = secKey
        } else {
            throw SwiftSecurityError.missingSecKeyRepresentation
        }

        try store(attributes, accessControl: accessControl.rawValue)
    }
    
    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext? = nil) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        guard let secItem = try retrieve(attributes, authenticationContext: authenticationContext) else {
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
    public func remove(_ query: SecItemQuery<SecKey>) throws -> Bool {
        let attributes = query.attributes
        return try remove(attributes)
    }
}

// MARK: - SecCertificate

extension Keychain: SecCertificateStore {
    public func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>) throws {
        try store(data, query: query, accessControl: AccessControl())
    }
    
    public func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>, accessControl: AccessControl) throws {
        guard let certificate = SecCertificateCreateWithData(nil, data.derRepresentation as CFData) else {
            throw SwiftSecurityError.failedSecCertificateConversion(
                description: "Data parameter is not a valid DER-encoded X.509 certificate."
            )
        }
        
        var attributes = query.attributes
        attributes[kSecValueRef as String] = certificate
        
        try store(attributes, accessControl: accessControl.rawValue)
    }
    
    public func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext?) throws -> T? {
        var attributes = query.attributes
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnRef as String] = true
        
        guard let secItem = try retrieve(attributes, authenticationContext: authenticationContext) else {
            return nil
        }
        
        let certificate = secItem as! SecCertificate
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
        
        var secResult: CFArray?
        switch SecPKCS12Import(data.pkcs12Representation as CFData, attributes as CFDictionary, &secResult) {
        case errSecSuccess:
            if let items = secResult as? Array<[String: Any]> {
                return items.map { item in
                    PKCS12.SecImportItem(attributes: item)
                }
            } else {
                return []
            }
        case let status:
            throw SwiftSecurityError.failedToWriteItem(description: status.debugDescription)
        }
    }
}

// MARK: - Common

extension Keychain: SecItemStore {
    public func removeAll() throws {
        
    }
}

internal extension Keychain {
    func store(_ query: [String: Any], accessControl: SecAccessControl) throws {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        query[kSecAttrAccessControl as String] = accessControl
        
        switch SecItemAdd(query as CFDictionary, nil) {
        case errSecSuccess:
            return
        case let status:
            throw SwiftSecurityError.failedToWriteItem(description: status.debugDescription)
        }
    }
    
    func retrieve(_ query: [String: Any], authenticationContext: LAContext?) throws -> CFTypeRef? {
        var query = query
        query[kSecAttrAccessGroup as String] = accessGroup
        
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        var secItem: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &secItem) {
        case errSecSuccess:
            return secItem as CFTypeRef
        case errSecItemNotFound:
            return nil
        case let status:
            throw SwiftSecurityError.failedToReadItem(description: status.debugDescription)
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
            throw SwiftSecurityError.failedToRemoveItem(description: status.debugDescription)
        }
    }
    
}

extension Keychain: CustomDebugStringConvertible {
    public var debugDescription: String {
        ""
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
