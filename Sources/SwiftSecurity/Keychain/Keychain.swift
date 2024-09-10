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
     
     Two or more apps that are in the same access group can share keychain items. For more details, see [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps/).
     */
    public init(accessGroup: AccessGroup) {
        self.accessGroup = accessGroup
    }
}

public extension Keychain {
    /**
     Keychain with default access group.

     The system considers the first item in the list of access groups to be the app’s default access group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string
     - The strings in the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     - SeeAlso: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    */
    static let `default` = Keychain(accessGroup: .default)
}

// MARK: - Common

extension Keychain: SecItemStore {
    public func retrieve<SecItem>(
        _ returnType: SecReturnType,
        query: SecItemQuery<SecItem>,
        authenticationContext: LAContext? = nil
    ) throws -> SecValue<SecItem>? {
        var query = query
        query.accessGroup = accessGroup.rawValue
        query[search: .matchLimit] = kSecMatchLimitOne as String
        
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        if returnType.contains(.data) {
            query[kSecReturnData as String] = true
        }
        if returnType.contains(.info) {
            query[kSecReturnAttributes as String] = true
        }
        if returnType.contains(.reference) {
            query[kSecReturnRef as String] = true
        }
        if returnType.contains(.persistentReference) {
            query[kSecReturnPersistentRef as String] = true
        }
        
        var result: AnyObject?
        switch SecItemCopyMatching(query.rawValue as CFDictionary, &result) {
        case errSecSuccess:
            switch returnType {
            case .data:
                if let data = result as? Data {
                    return .data(data)
                } else {
                    return nil
                }
            case .reference:
                if let result = result as? SecItem {
                    return .reference(result)
                } else {
                    return nil
                }
            case .persistentReference:
                if let data = result as? Data {
                    return .persistentReference(data)
                } else {
                    return nil
                }
            default:
                if let attributes = result as? [String: Any] {
                    return .dictionary(SecItemInfo<SecItem>(rawValue: attributes))
                } else {
                    return nil
                }
            }
        case errSecItemNotFound:
            return nil
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    public func retrieve<SecItem>(
        _ returnType: SecReturnType,
        matching value: SecValue<SecItem>,
        authenticationContext: LAContext? = nil
    ) throws -> SecValue<SecItem>? {
        var query: SecItemQuery<SecItem>
        
        switch value {
        case let .reference(reference):
            query = SecItemQuery(value: reference)
        case let .persistentReference(data):
            query = SecItemQuery(persistentValue: data)
        case .data, .dictionary:
            // Searching on data is not supported.
            throw SwiftSecurityError.invalidParameter
        }
        
        return try retrieve(returnType, query: query, authenticationContext: authenticationContext)
    }
    
    public func retrieveAll<SecItem>(
        _ returnType: SecReturnType = .all,
        query: SecItemQuery<SecItem>,
        authenticationContext: LAContext? = nil
    ) throws -> [SecValue<SecItem>] {
        var query = query
        query.accessGroup = accessGroup.rawValue
        query[search: .matchLimit] = kSecMatchLimitAll
        
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        if returnType.contains(.data) {
            query[kSecReturnData as String] = true
        }
        if returnType.contains(.info) {
            query[kSecReturnAttributes as String] = true
        }
        if returnType.contains(.reference) {
            query[kSecReturnRef as String] = true
        }
        if returnType.contains(.persistentReference) {
            query[kSecReturnPersistentRef as String] = true
        }
        
        var result: AnyObject?
        switch SecItemCopyMatching(query.rawValue as CFDictionary, &result) {
        case errSecSuccess:
            switch returnType {
            case .data:
                if let dataList = result as? [Data] {
                    return dataList.map { data in
                        return .data(data)
                    }
                } else {
                    return []
                }
            case .reference:
                if let objectList = result as? [AnyObject] {
                    return objectList.map { reference in
                        return .reference(reference as! SecItem)
                    }
                } else {
                    return []
                }
            case .persistentReference:
                if let dataList = result as? [Data] {
                    return dataList.map { data in
                        return .persistentReference(data)
                    }
                } else {
                    return []
                }
            default:
                if let dictionaryList = result as? Array<[String: Any]> {
                    return dictionaryList.map { attributes in
                        return .dictionary(SecItemInfo<SecItem>(rawValue: attributes))
                    }
                } else {
                    return []
                }
            }
        case errSecItemNotFound:
            return []
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    @discardableResult
    public func remove<SecItem>(_ query: SecItemQuery<SecItem>) throws -> Bool {
        var query = query
        query.accessGroup = accessGroup.rawValue
        
        switch SecItemDelete(query.rawValue as CFDictionary) {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        case let status:
            // Searching on data is not supported.
            throw SwiftSecurityError(rawValue: status)
        }
    }
    
    @discardableResult
    public func remove<SecItem>(matching value: SecValue<SecItem>) throws -> Bool {
        var query: SecItemQuery<SecItem>
        
        switch value {
        case let .reference(reference):
            query = SecItemQuery(value: reference)
        case let .persistentReference(data):
            query = SecItemQuery(persistentValue: data)
        case .data, .dictionary:
            throw SwiftSecurityError.invalidParameter
        }
        
        return try remove(query)
    }
    
    public func removeAll(includingSynchronizableCredentials: Bool = false) throws {
        var gps = SecItemQuery<GenericPassword>()
        var ips = SecItemQuery<InternetPassword>()
        var sks = SecItemQuery<SecKey>()
        var scs = SecItemQuery<SecCertificate>()
        var sis = SecItemQuery<SecIdentity>()
        
        if includingSynchronizableCredentials {
            gps[.synchronizable] = kSecAttrSynchronizableAny
            ips[.synchronizable] = kSecAttrSynchronizableAny
            sks[.synchronizable] = kSecAttrSynchronizableAny
            scs[.synchronizable] = kSecAttrSynchronizableAny
            sis[.synchronizable] = kSecAttrSynchronizableAny
        }
        
        try remove(gps)
        try remove(ips)
        try remove(sks)
        try remove(scs)
        try remove(sis)
    }
}

// MARK: - GenericPassword

extension Keychain: SecDataStore {
    public func store<T: SecDataConvertible>(_ data: T, query: SecItemQuery<GenericPassword>, accessPolicy: AccessPolicy = .default) throws {
        _ = try self.store(data, returning: [], query: query, accessPolicy: accessPolicy)
    }
    
    public func store<T: SecDataConvertible>(
        _ data: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<GenericPassword>,
        accessPolicy: AccessPolicy = .default
    ) throws -> SecValue<GenericPassword>? {
        try store(.data(data.rawRepresentation), returning: returnType, query: query, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext? = nil) throws -> T? {
        if let value = try retrieve(.data, query: query, authenticationContext: authenticationContext), case let .data(data) = value {
            return try T(rawRepresentation: data)  // Convert back to a key.
        } else {
            return nil
        }
    }
}

// MARK: - InternetPassword

extension Keychain {
    public func store<T: SecDataConvertible>(_ data: T, query: SecItemQuery<InternetPassword>, accessPolicy: AccessPolicy = .default) throws {
        _ = try self.store(data, returning: [], query: query, accessPolicy: accessPolicy)
    }
    
    public func store<T: SecDataConvertible>(
        _ data: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<InternetPassword>,
        accessPolicy: AccessPolicy = .default
    ) throws -> SecValue<InternetPassword>? {
        try store(.data(data.rawRepresentation), returning: returnType, query: query, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext? = nil) throws -> T? {
        guard
            let value = try retrieve(.data, query: query, authenticationContext: authenticationContext),
            case let .data(data) = value
        else {
            return nil
        }
        return try T(rawRepresentation: data)
    }
}

// MARK: - SecKey

extension Keychain: SecKeyStore {
    public func store<T: SecKeyRepresentable>(_ key: T, query: SecItemQuery<SecKey>, accessPolicy: AccessPolicy = .default) throws {
        _ = try store(key, returning: [], query: query, accessPolicy: accessPolicy)
    }
    
    public func store<T: SecKeyRepresentable>(
        _ key: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<SecKey>,
        accessPolicy: AccessPolicy = .default
    ) throws -> SecValue<SecKey>? {
        guard
            /// If key type specified in query, it should match with type from key's descriptor.  Refer to `.key(for:descriptor:)`
            query.keyType == nil || query.keyType == key.secKeyDescriptor.keyType,
            /// If key class specified in query, it should match with class from key's descriptor.
            query.keyClass == nil || query.keyClass == key.secKeyDescriptor.keyClass
        else {
            /// You most likely tried to store a public key as a private key. While it might be accepted by the keychain, it could lead to confusion.
            throw SwiftSecurityError.invalidParameter
        }
        return try store(.reference(key.secKey), returning: returnType, query: query, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecKeyRepresentable>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext? = nil) throws -> T? {
        guard
            let value = try retrieve(.reference, query: query, authenticationContext: authenticationContext),
            case let .reference(secKey) = value
        else {
            return nil
        }

        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey as SecKey, &error) as Data? else {
            if let error = error?.takeRetainedValue() {
                throw SwiftSecurityError(error: error)
            }
            throw SwiftSecurityError.invalidParameter
        }

        return try T(x963Representation: data)
    }
}

// MARK: - SecCertificate

extension Keychain: SecCertificateStore {
    public func store<T: SecCertificateConvertible>(
        _ certificate: T,
        query: SecItemQuery<SecCertificate>,
        accessPolicy: AccessPolicy = .default
    ) throws {
        _ = try store(certificate, returning: [], query: query, accessPolicy: accessPolicy)
    }
    
    public func store<T: SecCertificateConvertible>(
        _ certificate: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<SecCertificate>,
        accessPolicy: AccessPolicy = .default
    ) throws -> SecValue<SecCertificate>? {
        return try store(.reference(certificate.secCertificate), returning: returnType, query: query, accessPolicy: accessPolicy)
    }

    public func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext? = nil) throws -> T? {
        guard
            let value = try retrieve(.reference, query: query, authenticationContext: authenticationContext),
            case let .reference(secCertificate) = value
        else {
            return nil
        }
        return T(certificate: secCertificate)
    }
}

// MARK: - SecIdentity

extension Keychain: SecIdentityStore {
    public func store<T: SecIdentityConvertible>(
        _ identity: T,
        query: SecItemQuery<SecIdentity>,
        accessPolicy: AccessPolicy = .default
    ) throws {
        try store(.reference(identity.secIdentity), query: query, accessPolicy: accessPolicy)
    }
    
    public func retrieve<T: SecIdentityConvertible>(
        _ query: SecItemQuery<SecIdentity>,
        authenticationContext: LAContext? = nil
    ) throws -> T? {
        guard
            let value = try retrieve(.reference, query: query, authenticationContext: authenticationContext),
            case let .reference(secIdentity) = value
        else {
            return nil
        }
        return T(identity: secIdentity)
    }
}

// MARK: - Private

private extension Keychain {
    @discardableResult
    func store<SecItem>(
        _ value: SecValue<SecItem>,
        returning returnType: SecReturnType = [],
        query: SecItemQuery<SecItem>,
        accessPolicy: AccessPolicy = .default
    ) throws -> SecValue<SecItem>? {
        var query = query
        query.accessGroup = accessGroup.rawValue
        query.accessControl = try accessPolicy.accessControl
        query.accessible = accessPolicy.accessible
        
        if returnType.contains(.data) {
            query[kSecReturnData as String] = true
        }
        if returnType.contains(.info) {
            query[kSecReturnAttributes as String] = true
        }
        if returnType.contains(.reference) {
            query[kSecReturnRef as String] = true
        }
        if returnType.contains(.persistentReference) {
            query[kSecReturnPersistentRef as String] = true
        }
        
        switch value {
        case .data(let data):
            query[kSecValueData as String] = data
        case .reference(let reference):
            query[kSecValueRef as String] = reference
        case .dictionary, .persistentReference:
            throw SwiftSecurityError.invalidParameter
        }
        
        var result: AnyObject?
        switch SecItemAdd(query.rawValue as CFDictionary, &result) {
        case errSecSuccess:
            switch returnType {
            case .data:
                if let data = result as? Data {
                    return .data(data)
                } else {
                    return nil
                }
            case .reference:
                if let result {
                    return .reference(result as! SecItem)
                } else {
                    return nil
                }
            case .persistentReference:
                if let data = result as? Data {
                    return .persistentReference(data)
                } else {
                    return nil
                }
            default:
                if let attributes = result as? [String: Any] {
                    return .dictionary(SecItemInfo<SecItem>(rawValue: attributes))
                } else {
                    return nil
                }
            }
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
            var query = query
            query[.synchronizable] = kSecAttrSynchronizableAny
            
            if let items = try? retrieveAll(query: query) {
                return items.compactMap { value in
                    if case let .dictionary(info) = value {
                        return info
                    } else {
                        return nil
                    }
                }
            } else {
                return []
            }
        }
        
        let gps: [SecItemInfo<GenericPassword>]  = info(matching: SecItemQuery<GenericPassword>())
        let ips: [SecItemInfo<InternetPassword>] = info(matching: SecItemQuery<InternetPassword>())
        let sks: [SecItemInfo<SecKey>]           = info(matching: SecItemQuery<SecKey>())
        let scs: [SecItemInfo<SecCertificate>]   = info(matching: SecItemQuery<SecCertificate>())
        let sis: [SecItemInfo<SecIdentity>]      = info(matching: SecItemQuery<SecIdentity>())
        
        var strings: [String] = []
        strings.append(contentsOf: gps.map(\.debugDescription))
        strings.append(contentsOf: ips.map(\.debugDescription))
        strings.append(contentsOf: sks.map(\.debugDescription))
        strings.append(contentsOf: scs.map(\.debugDescription))
        strings.append(contentsOf: sis.map(\.debugDescription))

        return strings.joined(separator: "\n\n")
    }
}

extension Keychain {
    struct DebugFormatStyle: FormatStyle {
        typealias FormatInput = [String: Any]
        typealias FormatOutput = String
        
        func format(_ attributes: [String: Any]) -> String {
            attributes.map { rawKey, rawValue in
                let key = SecItemAttrKey(rawValue: rawKey)
                return "\(key.description): \(description(of: rawValue, for: key) ?? "nil")"
            }.debugDescription
        }
        
        private func description(of value: Any, for attribute: SecItemAttrKey) -> Any? {
            guard let rawValue = value as? String else {
                return value
            }
            
            switch attribute {
            case .accessible:
                return AccessPolicy.Accessibility(rawValue: rawValue)
            case .protocolType:
                return ProtocolType(rawValue: rawValue)
            case .authenticationType:
                return AuthenticationType(rawValue: rawValue)
            case .keyClass:
                return KeyClass(rawValue: rawValue)
            case .keyType:
                return KeyType(rawValue: rawValue)
            case .tokenID:
                return TokenID(rawValue: rawValue)
            case .class:
                return SecItemClass(rawValue: rawValue)
            default:
                return rawValue.isEmpty ? nil : rawValue
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
