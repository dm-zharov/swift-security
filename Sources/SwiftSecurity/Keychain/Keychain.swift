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

/// Securely store small chunks of data on behalf of the user.
public struct Keychain: Hashable, Codable, Sendable {
    private let accessGroup: AccessGroup

    /**
     Keychain Storage Specifier.
     
     - Parameter accessGroup: The corresponding value indicates the item’s one and only access group.
     
     For an app to access a keychain item, one of the groups to which the app belongs must be the item’s group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string
     - The strings in the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     Two or more apps that are in the same access group can share keychain items. For more details, see Sharing access to keychain items among a collection of apps.
     */
    public init(accessGroup: AccessGroup) {
        self.accessGroup = accessGroup
    }
}

public extension Keychain {
    /**
     The system considers the first item in the list of access groups to be the app’s default access group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string.
     - The strings in the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     - SeeAlso: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    */
    static let `default` = Keychain(accessGroup: .default)
}

// MARK: - Common

extension Keychain: SecItemStore {
    public func info<SecItem>(for query: SecItemQuery<SecItem>, authenticationContext: LAContext? = nil) throws -> SecItemInfo<SecItem>? {
        var attributes = query.attributes
        attributes[search: .matchLimit] = kSecMatchLimitOne as String
        
        guard let result = try retrieve(.none, with: attributes, authenticationContext: nil) as? [String: Any] else {
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

// MARK: - GenericPassword

extension Keychain: SecDataStore {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<GenericPassword>, accessPolicy: SecAccessPolicy = .default) throws {
        try store(.data(key.rawRepresentation), with: query.attributes, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext? = nil) throws -> T? {
        var attributes = query.attributes
        attributes[search: .matchLimit] = kSecMatchLimitOne as String

        guard let data = try retrieve(.data, with: attributes, authenticationContext: authenticationContext) as? Data else {
            return nil
        }
        return try T(rawRepresentation: data)  // Convert back to a key.
    }

    @discardableResult
    public func remove(_ query: SecItemQuery<GenericPassword>) throws -> Bool {
        return try remove(query.attributes)
    }
}

// MARK: - InternetPassword

extension Keychain {
    public func store<T: SecDataConvertible>(_ key: T, query: SecItemQuery<InternetPassword>, accessPolicy: SecAccessPolicy = .default) throws {
        try store(.data(key.rawRepresentation), with: query.attributes, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext? = nil) throws -> T? {
        var attributes = query.attributes
        attributes[search: .matchLimit] = kSecMatchLimitOne as String

        guard let data = try retrieve(.data, with: attributes, authenticationContext: authenticationContext) as? Data else {
            return nil
        }
        return try T(rawRepresentation: data)  // Convert back to a key.
    }

    @discardableResult
    public func remove(_ query: SecItemQuery<InternetPassword>) throws -> Bool {
        return try remove(query.attributes)
    }
}

// MARK: - SecKey

extension Keychain: SecKeyStore {
    public func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>, accessPolicy: SecAccessPolicy = .default) throws {
        var error: Unmanaged<CFError>?
        guard
            let secKey = SecKeyCreateWithData(key.x963Representation as CFData, query.attributes as CFDictionary, &error)
        else {
            if let error = error?.takeUnretainedValue() {
                throw SwiftSecurityError(error: error)
            } else {
                throw SwiftSecurityError(rawValue: errSecBadReq)
            }
        }

        try store(.reference(secKey), with: query.attributes, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext? = nil) throws -> T? {
        var attributes = query.attributes
        attributes[search: .matchLimit] = kSecMatchLimitOne as String
        
        guard let result = try retrieve(.reference, with: attributes, authenticationContext: authenticationContext) else {
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
        return try remove(query.attributes)
    }
}

// MARK: - SecCertificate

extension Keychain: SecCertificateStore {
    public func store<T: SecCertificateConvertible>(_ data: T, query: SecItemQuery<SecCertificate>, accessPolicy: SecAccessPolicy = .default) throws {
        guard let certificate = SecCertificateCreateWithData(nil, data.derRepresentation as CFData) else {
            throw SwiftSecurityError(rawValue: errSecConversionError)
        }
        try store(.reference(certificate), with: query.attributes, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext? = nil) throws -> T? {
        var attributes = query.attributes
        attributes[search: .matchLimit] = kSecMatchLimitOne as String
        
        guard let result = try retrieve(.reference, with: attributes, authenticationContext: authenticationContext) else {
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

    public func store(_ item: PKCS12.SecImportItem, query: SecItemQuery<SecIdentity>, accessPolicy: SecAccessPolicy = .default) throws {
        guard let identity = item.identity else {
            throw SwiftSecurityError(rawValue: errSecMissingValue)
        }
        try store(.reference(identity), with: query.attributes, accessPolicy: accessPolicy)
    }

    public func retrieve(_ query: SecItemQuery<SecIdentity>, authenticationContext: LAContext? = nil) throws -> SecIdentity? {
        var attributes = query.attributes
        attributes[search: .matchLimit] = kSecMatchLimitOne as String
        
        guard let result = try retrieve(.reference, with: attributes, authenticationContext: authenticationContext) else {
            return nil
        }
        
        let secIdentity = result as! SecIdentity

        return secIdentity
    }
    
    @discardableResult
    public func remove(_ query: SecItemQuery<SecIdentity>) throws -> Bool {
        return try remove(query.attributes)
    }
}

// MARK: - Private

private extension Keychain {
    func store(_ value: SecValue, with attributes: [String: Any], accessPolicy: SecAccessPolicy) throws {
        var attributes = attributes
        attributes[.accessGroup] = accessGroup.rawValue
        attributes[.accessControl] = try accessPolicy.accessControl
        attributes[.accessible] = accessPolicy.accessibility
        
        switch value {
        case .data(let data):
            attributes[kSecValueData as String] = data
        case .reference(let reference):
            attributes[kSecValueRef as String] = reference
        case .persistentReference:
            throw SwiftSecurityError(rawValue: errSecBadReq)
        }
        
        switch SecItemAdd(attributes as CFDictionary, nil) {
        case errSecSuccess:
            return
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    func retrieve(_ type: SecValueType?, with attributes: [String: Any], authenticationContext: LAContext?) throws -> AnyObject? {
        var attributes = attributes
        attributes[.accessGroup] = accessGroup.rawValue
        
        if let authenticationContext {
            attributes[kSecUseAuthenticationContext as String] = authenticationContext
            attributes[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        switch type {
        case .data:
            attributes[kSecReturnData as String] = true
        case .reference:
            attributes[kSecReturnRef as String] = true
        case .persistentReference:
            attributes[kSecReturnPersistentRef as String] = true
        case .none:
            attributes[kSecReturnAttributes as String] = true
        }
        
        var result: AnyObject?
        switch SecItemCopyMatching(attributes as CFDictionary, &result) {
        case errSecSuccess:
            return result
        case errSecItemNotFound:
            return nil
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    @discardableResult
    func remove(_ attributes: [String: Any]) throws -> Bool {
        var attributes = attributes
        attributes[.accessGroup] = accessGroup.rawValue
        
        switch SecItemDelete(attributes as CFDictionary) {
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
        return "Keychain(accessGroup: \(accessGroup.rawValue ?? ".default"))"
    }
}

extension Keychain: CustomDebugStringConvertible {
    public var debugDescription: String {
        #if os(tvOS)
        let context: LAContext? = nil
        #elseif os(watchOS)
        let context: LAContext? = LAContext()
        #else
        let context: LAContext? = LAContext()
        context?.localizedReason = "A debugger is requesting access to the protected items stored in the keychain."
        #endif
        
        func info<SecItem>(matching query: SecItemQuery<SecItem>) -> [SecItemInfo<SecItem>] {
            var attributes = query.attributes
            attributes[.synchronizable] = kSecAttrSynchronizableAny
            attributes[search: .matchLimit] = kSecMatchLimitAll
            
            if let items = try? retrieve(.none, with: attributes, authenticationContext: context) as? Array<[String: Any]> {
                return items.map { result in
                    SecItemInfo<SecItem>(result)
                }
            } else {
                return []
            }
        }
        
        let gps: [SecItemInfo<GenericPassword>] = info(matching: SecItemQuery<GenericPassword>())
        let ips: [SecItemInfo<InternetPassword>] = info(matching: SecItemQuery<InternetPassword>())
        let sks: [SecItemInfo<SecKey>] = info(matching: SecItemQuery<SecKey>())
        let scs: [SecItemInfo<SecCertificate>] = info(matching: SecItemQuery<SecCertificate>())
        let sis: [SecItemInfo<SecIdentity>] = info(matching: SecItemQuery<SecIdentity>())
        
        var strings: [String] = []
        strings.append(contentsOf: gps.map(\.debugDescription))
        strings.append(contentsOf: ips.map(\.debugDescription))
        strings.append(contentsOf: sks.map(\.debugDescription))
        strings.append(contentsOf: scs.map(\.debugDescription))
        strings.append(contentsOf: sis.map(\.debugDescription))
        
        return strings.debugDescription
    }
}

extension Keychain {
    struct DebugFormatStyle: FormatStyle {
        typealias FormatInput = [String: Any]
        typealias FormatOutput = String
        
        func format(_ attributes: [String: Any]) -> String {
            attributes.map { rawKey, rawValue in
                let key = SecItemAttr(rawValue: rawKey)
                if let rawString = rawValue as? String, let description = description(of: rawString, for: key) {
                    return "\(key.description): \(description)"
                } else {
                    return "\(key.description): \(rawValue)"
                }
            }.debugDescription
        }
        
        private func description(of rawValue: String, for attribute: SecItemAttr) -> String? {
            switch attribute {
            case .accessible:
                return SecAccessPolicy.Accessibility(rawValue: rawValue)?.description
            case .protocolType:
                return ProtocolType(rawValue: rawValue)?.description
            case .authenticationType:
                return AuthenticationMethod(rawValue: rawValue)?.description
            case .keyClass:
                return KeyType(rawValue: rawValue)?.description
            case .keyType:
                return KeyCipher(rawValue: rawValue)?.description
            case .tokenID:
                return TokenID(rawValue: rawValue)?.description
            #if os(macOS)
            case .prf:
                return PRFHmacAlg(rawValue: rawValue)?.description
            #endif
            case .class:
                return SecItemClass(rawValue: rawValue)?.description
            default:
                return nil
            }
        }
    }
}

#if os(tvOS)
public struct LAContext {
    @available(watchOS, unavailable)
    @available(tvOS, unavailable)
    public init() { }
}
#endif
