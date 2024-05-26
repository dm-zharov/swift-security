//
//  SecItemQuery.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

public struct SecItemQuery<Value> where Value: SecItem {
    private(set) var rawValue: [String: Any]
    
    var `class`: SecItemClass? {
        get {
            if let value = self[.class] as? String {
                return SecItemClass(rawValue: value)
            } else {
                return nil
            }
        }
        set {
            self[.class] = newValue?.rawValue
        }
    }
    
    private init(class: SecItemClass) {
        self.rawValue = [
            kSecClass: `class`.rawValue,
            kSecUseDataProtectionKeychain: true, // The data protection key affects operations only in macOS.
        ] as [String: Any]
    }
}

// MARK: - Convenient

public extension SecItemQuery {
    /// A query for a credential with specified service.
    /// - Note: The most popular type of query. Suitable for tokens, non-ANSI CryptoKit keys and other sensitive data types.
    /// - Parameters:
    ///   - service: A service associated with the item.
    ///   - synchronizable: A value indicating whether the item synchronizes through iCloud.
    ///   See [Developer Documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
    /// - Returns: ``SecItemQuery<GenericPassword>``.
    static func credential(for service: String, synchronizable: Bool? = nil) -> SecItemQuery<GenericPassword> {
        var query = SecItemQuery<GenericPassword>()
        query.service = service
        if let synchronizable {
            query.synchronizable = synchronizable
        }
        return query
    }
    
    /// A query for a web credential with specified account and server, or an area on the server that requires authentication.
    /// - Note: Suitable for websites with user logins.
    /// - Parameters:
    ///   - account: An account name.
    ///   - space: A server or an area on a server, that requires authentication.
    ///   - synchronizable: A boolean value indicating whether the item synchronizes through iCloud.
    ///   See [Developer Documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
    /// - Returns: ``SecItemQuery<InternetPassword>``.
    static func credential(for user: String, space: WebProtectionSpace, synchronizable: Bool? = nil) -> SecItemQuery<InternetPassword> {
        var query = SecItemQuery<InternetPassword>()
        query.account = user
        query.server = space.host
        query.port = space.port
        query.path = space.path
        query.protocol = space.protocol
        query.securityDomain = space.securityDomain
        query.authenticationType = space.authenticationType
        if let synchronizable {
            query.synchronizable = synchronizable
        }
        return query
    }
    
    /// A query for a private-key for elliptic curve cryptography (ANSI x9.63).
    /// - Note: Suitable for P256, P384, P521 CryptoKit Keys.
    /// - Parameters:
    ///   - applicationTag: An application tag that you can use to identify the key within store.
    ///   - synchronizable: A boolean value indicating whether the item synchronizes through iCloud.
    ///   See [Developer Documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
    /// - Returns: ``SecItemQuery<SecKey>``.
    static func privateKey(for applicationTag: String? = nil, synchronizable: Bool? = nil) -> SecItemQuery<SecKey> {
        var query = SecItemQuery<SecKey>()
        query.keyClass = .private
        query.keyType = .ecsecPrimeRandom
        if let applicationTag {
            query.applicationTag = applicationTag.data(using: .utf8)!
        }
        if let synchronizable {
            query.synchronizable = synchronizable
        }
        return query
    }
    
    /// A query for a X.509 certificate.
    /// - Parameters:
    ///   - label: An label that you can use to make it easier to search for the certificate later.
    ///   - synchronizable: A boolean value indicating whether the item synchronizes through iCloud.
    ///   See [Developer Documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
    /// - Returns: ``SecItemQuery<SecCertificate>``.
    static func certificate(for label: String? = nil, synchronizable: Bool? = nil) -> SecItemQuery<SecCertificate> {
        var query = SecItemQuery<SecCertificate>()
        if let label {
            query.label = label
        }
        return query
    }
    
    /// A query for an identity, the pair of X.509 certificate and corresponding private key.
    /// - Parameters:
    ///   - label: An label that you can use to make it easier to search for the identity later.
    ///   - synchronizable: A boolean value indicating whether the item synchronizes through iCloud.
    ///   See [Developer Documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
    /// - Returns: ``SecItemQuery<SecIdentity>``.
    static func identity(for label: String? = nil, synchronizable: Bool? = nil) -> SecItemQuery<SecIdentity> {
        var query = SecItemQuery<SecIdentity>()
        if let label {
            query.label = label
        }
        return query
    }
}

// MARK: - Instantiation

extension SecItemQuery {
    /// A query for credential with specified service.
    public init() where Value == GenericPassword {
        self.init(class: .genericPassword)
    }
    
    /// A query for a web credential.
    public init() where Value == InternetPassword {
        self.init(class: .internetPassword)
    }
    
    /// A query for a key.
    public init() where Value == SecKey {
        self.init(class: .key)
    }
    
    /// A query for a X.509 certificate.
    public init() where Value == SecCertificate {
        self.init(class: .certificate)
    }
    
    /// A query for an identity.
    public init() where Value == SecIdentity {
        self.init(class: .identity)
    }
}

// MARK: - Common

public extension SecItemQuery {
    /**
     The corresponding value indicates whether the item in question is synchronized to other devices through iCloud.
     
     The following caveats apply when you specify this key:
     - You can set the key on tvOS, but tvOS doesn’t synchronize your app’s keychain items through iCloud.
     - Updating or deleting items using the key affects all copies of the item, not just the one on your local device. Be sure that it makes sense to use the same password on all devices before making a password synchronizable.
     - Items stored or obtained using the key may not also specify an ``AccessPolicy`` value that is incompatible with syncing (namely, those whose names end with `...ThisDeviceOnly`).
     */
    var synchronizable: PrimaryKey<Bool>? {
        get { self[.synchronizable] as? Bool }
        set { self[.synchronizable] = newValue }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    ///
    /// - Note: - Note: On macOS, this shows up in the `Name` field in the info window in `Keychain Access` (accessed via File > Get Info)
    var label: String? {
        get { self[.label] as? String }
        set { self[.label] = newValue }
    }
}

internal extension SecItemQuery {
    /// The corresponding value indicates the item’s one and only access group.
    var accessGroup: PrimaryKey<String>? {
        get { self[.accessGroup] as? String }
        set { self[.accessGroup] = newValue }
    }
    
    /// The corresponding value contains access control conditions for the item.
    var accessControl: SecAccessControl? {
        get { self[.accessControl] as! SecAccessControl? }
        set { self[.accessControl] = newValue }
    }
    
    /// The corresponding value indicates the item’s one and only access group.
    var accessible: AccessPolicy.Accessibility? {
        get {
            if let rawValue = self[.accessible] as? String {
                return AccessPolicy.Accessibility(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.accessible] = newValue?.rawValue }
    }
}

#if os(tvOS)
public extension SecItemQuery {
    /// The corresponding value indicates whether to store the data in a keychain available to anyone who uses the device.
    @available(tvOS 16.0, *)
    var useUserIndependentKeychain: Bool? {
        get { self[.useUserIndependentKeychain] as? Bool }
        set { self[.useUserIndependentKeychain] = newValue }
    }
}
#endif

// MARK: - GenericPassword

public extension SecItemQuery where Value == GenericPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: PrimaryKey<String>? {
        get { self[.account] as? String }
        set { self[.account] = newValue}
    }
    
    /// The corresponding value represents the service associated with this item.
    var service: PrimaryKey<String>? {
        get { self[.service] as? String }
        set { self[.service] = newValue }
    }
    
    // MARK: - Attributes
    
    /// The corresponding value contains a user-defined attribute.
    var generic: Data? {
        get { self[.generic] as? Data }
        set { self[.generic] = newValue }
    }
}

// MARK: - InternetPassword

public extension SecItemQuery where Value == InternetPassword {    
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: PrimaryKey<String>? {
        get { self[.account] as? String }
        set { self[.account] = newValue }
    }
    
    /// The corresponding value denotes the authentication scheme for this item.
    var authenticationType: PrimaryKey<AuthenticationType>? {
        get {
            if let value = self[.authenticationType] as? String {
                return AuthenticationType(rawValue: value)
            } else {
                return nil
            }
        }
        set { self[.authenticationType] = newValue?.rawValue }
    }
    
    /// The corresponding value represents a path, typically the path component of the URL.
    var path: PrimaryKey<String>? {
        get { self[.path] as? String }
        set { self[.path] = newValue }
    }
    
    /// The corresponding represents an Internet port number.
    var port: PrimaryKey<Int>? {
        get {
            if let number = self[.port] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                self[.port] = NSNumber(integerLiteral: newValue)
            } else {
                self[.port] = nil
            }
        }
    }
    
    /// The corresponding value denotes the protocol for this item.
    var `protocol`: PrimaryKey<ProtocolType>? {
        get {
            if let value = self[.protocolType] as? String {
                return ProtocolType(rawValue: value)
            } else {
                return nil
            }
        }
        set { self[.protocolType] = newValue?.rawValue }
    }
    
    /// The corresponding value represents the Internet security domain.
    var securityDomain: PrimaryKey<String>? {
        get { self[.securityDomain] as? String }
        set { self[.securityDomain] = newValue }
    }
    
    /// The corresponding value contains the server's domain name or IP address.
    var server: PrimaryKey<String>? {
        get { self[.server] as? String }
        set { self[.server] = newValue }
    }
}

// MARK: - Generic and Internet Password

public extension SecItemQuery where Value: SecData {
    // MARK: - Attributes
    
    /// The corresponding value specifies a user-visible string describing this kind of item (for example, "Disk image password").
    var description: String? {
        get { self[.description] as? String }
        set { self[.description] = newValue }
    }
    
    /// The corresponding value contains the user-editable comment for this item.
    var comment: String? {
        get { self[.comment] as? String }
        set { self[.comment] = newValue }
    }
    
    /// The corresponding value represents the item's creator. This number is the unsigned integer representation of a four-character code (for example, 'aCrt').
    var creator: FourCharCode? {
        get { self[.creator] as? FourCharCode }
        set { self[.creator] = newValue }
    }
    
    /// The corresponding value  represents the item's type. This number is the unsigned integer representation of a four-character code (for example, 'aTyp').
    var type: FourCharCode? {
        get { self[.type] as? FourCharCode }
        set { self[.type] = newValue }
    }
    
    /// The corresponding value is kCFBooleanTrue if the item is invisible (that is, should not be displayed).
    var isInvisible: Bool? {
        get { self[.isInvisible] as? Bool }
        set { self[.isInvisible] = newValue }
    }
    
    /**
     The corresponding value indicates whether there is a valid password associated with this keychain item.
     This is useful if your application doesn't want a password for some particular service to be stored in the keychain, but prefers that it always be entered by the user.
     */
    var isNegative: Bool? {
        get { self[.isNegative] as? Bool }
        set { self[.isNegative] = newValue }
    }
}

// MARK: - SecKey

public extension SecItemQuery where Value == SecKey {
    // MARK: - Primary
    
    /**
     The corresponding value contains a label for this item.
     This attribute is different from the ``label`` attribute, which is intended to be human-readable.
     Instead, this attribute is used to look up a key programmatically; in particular, for `public` and `private` keys, the value of this attribute is the hash of the public key.
     
     - Note: To form a digital identity, this value must match the ``publicKeyHash`` ('pkhh') attribute of the `SecCertificate`.
     */
    var applicationLabel: PrimaryKey<Data>? {
        get { self[.applicationLabel] as? Data }
        set { self[.applicationLabel] = newValue }
    }
    
    /// The corresponding value contains private tag data.
    ///
    /// - Note: On macOS, this shows up in the `Comments` field in the info window in `Keychain Access` (accessed via File > Get Info)
    var applicationTag: PrimaryKey<Data>? {
        get { self[.applicationTag] as? Data }
        set { self[.applicationTag] = newValue }
    }
    
    /// The corresponding value specifies a type of cryptographic key.
    var keyClass: PrimaryKey<KeyClass>? {
        get {
            if let rawValue = self[.keyClass] as? String {
                return KeyClass(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.keyClass] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the algorithm associated with this cryptographic key.
    var keyType: PrimaryKey<KeyType>? {
        get {
            if let rawValue = self[.keyType] as? String {
                return KeyType(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.keyType] = newValue?.rawValue }
    }

    /// The corresponding value indicates the total number of bits in this cryptographic key.
    var keySizeInBits: PrimaryKey<Int>? {
        get { self[.keySizeInBits] as? Int }
        set { self[.keySizeInBits] = newValue }
    }
    
    /// The corresponding value indicates the effective number of bits in this cryptographic key. For example, a DES key has a `keySizeInBits` of 64, but a `effectiveKeySize` of 56 bits.
    var effectiveKeySize: PrimaryKey<Int>? {
        get { self[.effectiveKeySize] as? Int }
        set { self[.effectiveKeySize] = newValue }
    }
    
    // MARK: - Usage
    
    /**
     Presence of this key indicates that the item is backed by an external store, as uniquely identified by the value. An item without this attribute is stored as normal in the keychain database.
     - Note: You can’t change this attribute after creating the keychain item. It isn’t possible to migrate existing items between stores.
     */
    var tokenID: TokenID? {
        get {
            if let rawValue = self[.tokenID] as? String {
                return TokenID(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.tokenID] = newValue?.rawValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to encrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`for private keys and `true` for public keys.
     */
    var canEncrypt: Bool? {
        get { self[.canEncrypt] as? Bool }
        set { self[.canEncrypt] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to decrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canDecrypt: Bool? {
        get { self[.canDecrypt] as? Bool }
        set { self[.canDecrypt] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to derive another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true`.
     */
    var canDerive: Bool? {
        get { self[.canDerive] as? Bool }
        set { self[.canDerive] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to create a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canSign: Bool? {
        get { self[.canSign] as? Bool }
        set { self[.canSign] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to verify a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canVerify: Bool? {
        get { self[.canVerify] as? Bool }
        set { self[.canVerify] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to wrap another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canWrap: Bool? {
        get { self[.canWrap] as? Bool }
        set { self[.canWrap] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to unwrap another key.
     On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canUnwrap: Bool? {
        get { self[.canUnwrap] as? Bool }
        set { self[.canUnwrap] = newValue }
    }
}

extension SecItemQuery: CustomDebugStringConvertible {
    public var debugDescription: String {
        return Keychain.DebugFormatStyle().format(rawValue)
    }
}

extension SecItemQuery {
    public subscript(attribute: String) -> Any? {
        get { rawValue[attribute] }
        set { rawValue[attribute] = newValue }
    }
}

extension SecItemQuery {
    subscript(key: SecItemAttrKey) -> Any? {
        get { self[key.rawValue] }
        set { self[key.rawValue] = newValue }
    }
    
    subscript(search key: SecItemSearchKey) -> Any? {
        get { self[key.rawValue] }
        set { self[key.rawValue] = newValue }
    }
}

// MARK: - Deprecetad

public extension SecItemQuery {
    /// A query for a credential with specified service.
    ///  - Parameters:
    ///   - account: An acount
    ///   - service: A service associated with the item.
    ///   - synchronizable: A boolean value indicating whether the item synchronizes through iCloud.
    /// - Returns: ``SecItemQuery<GenericPassword>``.
    @available(*, deprecated, message: "Use `SecItemQuery<GenericPassword>()` with specified `account` and `service` values")
    static func credential(for account: String, service: String?) -> SecItemQuery<GenericPassword> {
        var query = SecItemQuery<GenericPassword>()
        query.service = service
        query.account = account
        return query
    }
    
    /// A query for a private-key for elliptic curve cryptography (ANSI x9.63).
    /// - Parameters:
    ///   - applicationTag: An application tag that you can use to identify the key within store.
    ///   - synchronizable: A boolean value indicating whether the item synchronizes through iCloud.
    ///   See [Developer Documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
    /// - Returns: ``SecItemQuery<SecKey>``.
    @available(*, deprecated, renamed: "privateKey(for:)")
    static func privateKey(tag: String) -> SecItemQuery<SecKey> {
        return privateKey(for: tag, synchronizable: nil)
    }
}
