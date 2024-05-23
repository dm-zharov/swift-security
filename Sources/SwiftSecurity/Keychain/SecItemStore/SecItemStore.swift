//
//  SecItemStore.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public protocol SecItemStore {
    /// Returns the first item that match a search query, or copies attributes of specific item.
    /// - Parameters:
    ///   - returnType: One or more return types. Use the values of ``SecReturnType`` to indicate whether you seek the item’s attributes,
    ///   the item’s data, a reference to the data, a persistent reference to the data, or a combination of these.
    ///   - query: An object that describes the query. See ``SecItemQuery``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the first found item. The exact value of the result depends on the return type values supplied as `returnType`.
    func retrieve<SecItem>(
        _ returnType: SecReturnType,
        query: SecItemQuery<SecItem>,
        authenticationContext: LAContext?
    ) throws -> SecValue<SecItem>?

    /// Returns items that match a search query, or copies attributes of specific items.
    /// - Parameters:
    ///   - returnType: One or more return types. Use the values of ``SecReturnType`` to indicate whether you seek the item’s attributes,
    ///   the item’s data, a reference to the data, a persistent reference to the data, or a combination of these.
    ///   - query: An object that describes the query. See ``SecItemQuery``.
    /// - Returns: On return, the found items. The exact value of the result depends on the return type values supplied as `returnType`.
    func retrieveAll<SecItem>(
        _ returnType: SecReturnType,
        query: SecItemQuery<SecItem>,
        authenticationContext: LAContext?
    ) throws -> [SecValue<SecItem>]
    
    /// Removes all items from store.
    /// - Parameter includingSynchronizableCredentials: The corresponding value representing a value that indicates whether credentials
    /// which contain the `synchronizable: true` attribute should be removed. Affects all copies of the item, not just the one on your local device.
    func removeAll(includingSynchronizableCredentials: Bool) throws
}

public extension SecItemStore {
    /// Returns the attributes of first found item that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the attributes of first found item.
    func info<SecItem>(for query: SecItemQuery<SecItem>, authenticationContext: LAContext? = nil) throws -> SecItemInfo<SecItem>? {
        if let value = try retrieve(
            .info, query: query, authenticationContext: authenticationContext
        ), case let .dictionary(info) = value {
            return info
        } else {
            return nil
        }
    }
}

// MARK: - SecData

public protocol SecDataStore: SecItemStore {
    // MARK: Generic Password
    
    /// Stores the secret data with specified query.
    /// - Parameters:
    ///   - data: The secret data.
    ///   - query: An object that describes the search. See ``SecItemQuery<GenericPassword>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    func store<T: SecDataConvertible>(_ data: T, query: SecItemQuery<GenericPassword>, accessPolicy: AccessPolicy) throws
    
    /// Stores the secret data with specified query.
    /// - Parameters:
    ///   - data: The secret data.
    ///   - returnType: One or more return types. Use the values of ``SecReturnType`` to indicate whether you seek the item’s attributes,
    ///   the item’s data, a reference to the data, a persistent reference to the data, or a combination of these.
    ///   - query: An object that describes the search. See ``SecItemQuery<GenericPassword>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    /// - Returns: On return, the result. The exact value of the result depends on the return type values supplied as `returnType`.
    func store<T: SecDataConvertible>(
        _ data: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<GenericPassword>,
        accessPolicy: AccessPolicy
    ) throws -> SecValue<GenericPassword>?

    /// Returns the first secret data that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<GenericPassword>``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the found secure data.
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<GenericPassword>, authenticationContext: LAContext?) throws -> T?

    /// Removes the first secret data that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<GenericPassword>``.
    /// - Returns: On return, the status of removal.
    func remove(_ query: SecItemQuery<GenericPassword>) throws -> Bool
    
    // MARK: Internet Password
    
    /// Stores the web credential with specified query.
    /// - Parameters:
    ///   - data: The secret data.
    ///   - query: An object that describes the search. See ``SecItemQuery<InternetPassword>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    func store<T: SecDataConvertible>(_ data: T, query: SecItemQuery<InternetPassword>, accessPolicy: AccessPolicy) throws
    
    /// Stores the web credential with specified query.
    /// - Parameters:
    ///   - data: The web credential.
    ///   - returnType: One or more return types. Use the values of ``SecReturnType`` to indicate whether you seek the item’s attributes,
    ///   the item’s data, a reference to the data, a persistent reference to the data, or a combination of these.
    ///   - query: An object that describes the query. See ``SecItemQuery<InternetPassword>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    /// - Returns: On return, the result. The exact value of the result depends on the return type values supplied as `returnType`.
    func store<T: SecDataConvertible>(
        _ data: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<InternetPassword>,
        accessPolicy: AccessPolicy
    ) throws -> SecValue<InternetPassword>?

    /// Returns the first web credential that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<InternetPassword>``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the found web credential.
    func retrieve<T: SecDataConvertible>(_ query: SecItemQuery<InternetPassword>, authenticationContext: LAContext?) throws -> T?
    
    /// Removes the first secret data that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<InternetPassword>``.
    /// - Returns: On return, the status of removal.
    func remove(_ query: SecItemQuery<InternetPassword>) throws -> Bool
}

// MARK: Convinient

extension SecDataStore {    
    /// Returns the first secret data that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<GenericPassword>``.
    /// - Returns: On return, the first found secure data.
    public func retrieve(_ query: SecItemQuery<GenericPassword>) throws -> Data? {
        try self.retrieve<Data>(query, authenticationContext: nil)
    }

    /// Returns the first web credential that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<InternetPassword>``.
    /// - Returns: On return, the first found web credential.
    public func retrieve(_ query: SecItemQuery<InternetPassword>) throws -> Data? {
        try self.retrieve<Data>(query, authenticationContext: nil)
    }
}

// MARK: - SecKey

public protocol SecKeyStore: SecItemStore {
    /// Stores the key with specified query.
    /// - Parameters:
    ///   - data: The key.
    ///   - query: An object that describes the search. See ``SecItemQuery<SecKey>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    func store<T: SecKeyConvertible>(_ key: T, query: SecItemQuery<SecKey>, accessPolicy: AccessPolicy) throws
    
    /// Stores the key with specified query.
    /// - Parameters:
    ///   - data: The key.
    ///   - returnType: One or more return types. Use the values of ``SecReturnType`` to indicate whether you seek the item’s attributes,
    ///   the item’s data, a reference to the data, a persistent reference to the data, or a combination of these.
    ///   - query: An object that describes the query. See ``SecItemQuery<SecKey>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    /// - Returns: On return, the result. The exact value of the result depends on the return type values supplied as `returnType`.
    func store<T: SecKeyConvertible>(
        _ key: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<SecKey>,
        accessPolicy: AccessPolicy
    ) throws -> SecValue<SecKey>?
    
    /// Returns the first key that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<SecKey>``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the first found key.
    func retrieve<T: SecKeyConvertible>(_ query: SecItemQuery<SecKey>, authenticationContext: LAContext?) throws -> T?
    
    /// Removes the first key that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<SecKey>``.
    /// - Returns: On return, the status of removal.
    /// - Important: Removing a private key that matches a public key in an existing certificate can ‘remove’ a digital identity (``SecIdentity``).
    func remove(_ query: SecItemQuery<SecKey>) throws -> Bool
}

// MARK: - SecCertificate

public protocol SecCertificateStore: SecItemStore {
    /// Stores the X.509 certificate with specified query.
    /// - Parameters:
    ///   - data: The X.509 certificate.
    ///   - query: An object that describes the search. See ``SecItemQuery<SecCertificate>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    func store<T: SecCertificateConvertible>(_ certificate: T, query: SecItemQuery<SecCertificate>, accessPolicy: AccessPolicy) throws
    
    /// Stores the X.509 certificate with specified query.
    /// - Parameters:
    ///   - data: The X.509 certificate.
    ///   - returnType: One or more return types. Use the values of ``SecReturnType`` to indicate whether you seek the item’s attributes,
    ///   the item’s data, a reference to the data, a persistent reference to the data, or a combination of these.
    ///   - query: An object that describes the query. See ``SecItemQuery<SecCertificate>``.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    /// - Returns: On return, the result. The exact value of the result depends on the return type values supplied as `returnType`.
    func store<T: SecCertificateConvertible>(
        _ certificate: T,
        returning returnType: SecReturnType,
        query: SecItemQuery<SecCertificate>,
        accessPolicy: AccessPolicy
    ) throws -> SecValue<SecCertificate>?
    
    /// Returns the first X.509 certificate that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<SecCertificate>``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the first found X.509 certificate.
    func retrieve<T: SecCertificateConvertible>(_ query: SecItemQuery<SecCertificate>, authenticationContext: LAContext?) throws -> T?
    
    /// Removes the first X.509 certificate that match a search query.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<SecCertificate>``.
    /// - Returns: On return, the status of removal.
    /// - Important: Removing a certificate with a public key matching an existing private key can ‘remove’ a digital identity (``SecIdentity``).
    func remove(_ query: SecItemQuery<SecCertificate>) throws -> Bool
}

// MARK: - SecIdentity

public protocol SecIdentityStore: SecItemStore {
    /// Imports the contents of PKCS #12 file (often with a p12 extension).
    /// - Parameters:
    ///   - data: The PKCS #12 data you wish to decode.
    ///   - passphrase: A passphrase to be used when importing from PKCS#12 data.
    /// - Important: Do not bundle passwords with your app in any form. Doing so is insecure, because no matter how carefully you try to obscure a password,
    /// a motivated attacker will find a way to mimic the operations you use to reveal it for your own purposes.
    /// Instead, prompt the user for a password when you need it, or read it from the secure storage offered by a keychain.
    /// - Returns: On return, the list of each item (identity or certificate) in the PKCS #12 blob.
    func `import`(_ data: PKCS12.Blob, passphrase: String) throws -> [SecImportItemInfo]
    
    /// Stores the digital identity with specified query.
    ///
    /// A digital identity is the combination of a certificate and the private key that matches the public key within that certificate.
    /// The system stores these components separately.
    /// - Parameters:
    ///   - identityReference: The reference to ``SecIdentity``. Could be retrieved after PKCS #12 blob import from ``SecImportItemInfo``.
    ///   - query: An object that describes the search. See ``SecItemQuery<SecIdentity>``. You store an identity as you would a certificate.
    ///   - accessPolicy: The protection policy to use when creating the associated access control object.
    func store<T: SecIdentityConvertible>(_ identity: T, query: SecItemQuery<SecIdentity>, accessPolicy: AccessPolicy) throws
    
    /// Returns the first digital identity that match a search query.
    ///
    /// A digital identity is the combination of a certificate and the private key that matches the public key within that certificate.
    /// The system stores these components separately.
    /// - Parameters:
    ///   - query: An object that describes the query. See ``SecItemQuery<SecIdentity>``.
    ///   - authenticationContext: A local authentication context.
    /// - Returns: On return, the first found digital identity.
    func retrieve<T: SecIdentityConvertible>(_ query: SecItemQuery<SecIdentity>, authenticationContext: LAContext?) throws -> T?

    /// Removes the first digital identity that match a search query.
    ///
    /// A digital identity is the combination of a certificate and the private key that matches the public key within that certificate.
    /// The system stores these components separately.
    /// - Important: Removing a digital identity removes its certificate. It might also remove the private key,
    /// depending on whether that private key is used by a different digital identity.
    func remove(_ query: SecItemQuery<SecIdentity>) throws -> Bool
}

// MARK: PKCS #12 Blob

public enum PKCS12 {
    /// PKCS #12–formatted blob (the content of PKCS #12 file, often with a p12 extension).
    public typealias Blob = Data
}
