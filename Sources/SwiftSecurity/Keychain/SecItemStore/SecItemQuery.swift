//
//  SecItemQuery.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

public struct SecItemQuery<Value> where Value: SecItem {
    private(set) var attributes: [String: Any]
    
    private init(class: SecItemClass) {
        self.attributes = [
            kSecClass: `class`.rawValue,
            kSecUseDataProtectionKeychain: true, // This key affects only macOS.
        ] as [String: Any]
    }
}

// MARK: - Convenient

public extension SecItemQuery {
    /// A data-based credential for the specified service.
    /// - Note: GenericPassword.
    static func credential(for service: String) -> SecItemQuery<Value> where Value == GenericPassword {
        var query = SecItemQuery<GenericPassword>()
        query.service = service
        return query
    }
    
    /// A data-based credential for the specified account and service.
    /// - Note: GenericPassword.
    static func credential(for account: String, service: String?) -> SecItemQuery<Value> where Value == GenericPassword {
        var query = SecItemQuery<GenericPassword>()
        query.service = service
        query.account = account
        return query
    }
    
    /// A web credential for the specified account and server or an area on server, that requires authentication.
    /// - Note: InternetPassword.
    static func credential(for user: String, space: WebProtectionSpace) -> SecItemQuery<Value> where Value == InternetPassword {
        var query = SecItemQuery<InternetPassword>()
        query.account = user
        query.server = space.host
        query.port = space.port
        query.path = space.path
        query.protocol = space.protocol
        query.securityDomain = space.securityDomain
        query.authenticationMethod = space.authenticationMethod
        return query
    }
}

// MARK: - Instantiation

extension SecItemQuery {
    public init() where Value == GenericPassword {
        self.init(class: .genericPassword)
    }
    
    public init() where Value == InternetPassword {
        self.init(class: .internetPassword)
    }
    
    public init() where Value == SecKey {
        self.init(class: .key)
    }
    
    public init() where Value == SecCertificate {
        self.init(class: .certificate)
    }
    
    public init() where Value == SecIdentity {
        self.init(class: .identity)
    }
}

// MARK: - Common

public extension SecItemQuery {
    /// The corresponding value indicates whether the item in question is synchronized to other devices through iCloud.
    var synchronizable: Bool? {
        get { attributes[.synchronizable] as? Bool }
        set { attributes[.synchronizable] = newValue }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var label: String? {
        get { attributes[.label] as? String }
        set { attributes[.label] = newValue }
    }
}

#if os(tvOS)
public extension SecItemQuery {
    @available(tvOS 16.0, *)
    var useUserIndependentKeychain: Bool? {
        get { attributes[.useUserIndependentKeychain] as? Bool }
        set { attributes[.useUserIndependentKeychain] = newValue }
    }
}
#endif

// MARK: - GenericPassword

public extension SecItemQuery where Value == GenericPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: String? {
        get { attributes[.account] as? String }
        set { attributes[.account] = newValue }
    }
    
    /// The corresponding value represents the service associated with this item.
    var service: String? {
        get { attributes[.service] as? String }
        set { attributes[.service] = newValue }
    }
    
    // MARK: - Attributes
    
    /// The corresponding value contains a user-defined attribute.
    var generic: Data? {
        get { attributes[.generic] as? Data }
        set { attributes[.generic] = newValue }
    }
}

// MARK: - InternetPassword

public extension SecItemQuery where Value == InternetPassword {    
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: String? {
        get { attributes[.account] as? String }
        set { attributes[.account] = newValue }
    }
    
    /// The corresponding value denotes the authentication scheme for this item.
    var authenticationMethod: AuthenticationMethod? {
        get {
            if let value = attributes[.authenticationType] as? String {
                return AuthenticationMethod(rawValue: value)
            } else {
                return nil
            }
        }
        set { attributes[.authenticationType] = newValue?.rawValue }
    }
    
    /// The corresponding value represents a path, typically the path component of the URL.
    var path: String? {
        get { attributes[.path] as? String }
        set { attributes[.path] = newValue }
    }
    
    /// The corresponding represents an Internet port number.
    var port: Int? {
        get {
            if let number = attributes[.port] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                attributes[.port] = NSNumber(integerLiteral: newValue)
            } else {
                attributes[.port] = nil
            }
        }
    }
    
    /// The corresponding value denotes the protocol for this item.
    var `protocol`: ProtocolType? {
        get {
            if let value = attributes[.protocolType] as? String {
                return ProtocolType(rawValue: value)
            } else {
                return nil
            }
        }
        set { attributes[.protocolType] = newValue?.rawValue }
    }
    
    /// The corresponding value represents the Internet security domain.
    var securityDomain: String? {
        get { attributes[.securityDomain] as? String }
        set { attributes[.securityDomain] = newValue }
    }
    
    /// The corresponding value contains the server's domain name or IP address.
    var server: String? {
        get { attributes[.server] as? String }
        set { attributes[.server] = newValue }
    }
}

// MARK: - Generic and Internet Password

public extension SecItemQuery where Value: Password {
    // MARK: - Attributes
    
    /// The corresponding value specifies a user-visible string describing this kind of item (for example, "Disk image password").
    var description: String? {
        get { attributes[.description] as? String }
        set { attributes[.description] = newValue }
    }
    
    /// The corresponding value contains the user-editable comment for this item.
    var comment: String? {
        get { attributes[.comment] as? String }
        set { attributes[.comment] = newValue }
    }
    
    /// The corresponding value represents the item's creator. This number is the unsigned integer representation of a four-character code (for example, 'aCrt').
    var creator: FourCharCode? {
        get { attributes[.creator] as? FourCharCode }
        set { attributes[.creator] = newValue }
    }
    
    /// The corresponding value  represents the item's type. This number is the unsigned integer representation of a four-character code (for example, 'aTyp').
    var type: FourCharCode? {
        get { attributes[.type] as? FourCharCode }
        set { attributes[.type] = newValue }
    }
    
    /// The corresponding value is kCFBooleanTrue if the item is invisible (that is, should not be displayed).
    var isInvisible: Bool? {
        get { attributes[.isInvisible] as? Bool }
        set { attributes[.isInvisible] = newValue }
    }
    
    /**
     The corresponding value indicates whether there is a valid password associated with this keychain item.
     This is useful if your application doesn't want a password for some particular service to be stored in the keychain, but prefers that it always be entered by the user.
     */
    var isNegative: Bool? {
        get { attributes[.isNegative] as? Bool }
        set { attributes[.isNegative] = newValue }
    }
}

// MARK: - SecKey

public extension SecItemQuery where Value == SecKey {
    // MARK: - Primary
    
    /**
     The corresponding value contains a label for this item.
     This attribute is different from the ``label`` attribute, which is intended to be human-readable.
     Instead, this attribute is used to look up a key programmatically; in particular, for `public` and `private` keys, the value of this attribute is the hash of the public key.
     */
    var applicationLabel: Data? {
        get { attributes[.applicationLabel] as? Data }
        set { attributes[.applicationLabel] = newValue }
    }
    
    /// The corresponding value contains private tag data.
    var applicationTag: Data? {
        get { attributes[.applicationTag] as? Data }
        set { attributes[.applicationTag] = newValue }
    }
    
    /// The corresponding value specifies a type of cryptographic key.
    var keyClass: KeyType? {
        get {
            if let rawValue = attributes[.keyClass] as? String {
                return KeyType(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[.keyClass] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the algorithm associated with this cryptographic key.
    var keyType: KeyCipher? {
        get {
            if let rawValue = attributes[.keyType] as? String {
                return KeyCipher(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[.keyType] = newValue?.rawValue }
    }

    /// The corresponding value indicates the total number of bits in this cryptographic key.
    var keySizeInBits: Int? {
        get { attributes[.keySizeInBits] as? Int }
        set { attributes[.keySizeInBits] = newValue }
    }
    
    /// The corresponding value indicates the effective number of bits in this cryptographic key. For example, a DES key has a `keySizeInBits` of 64, but a `effectiveKeySize` of 56 bits.
    var effectiveKeySize: Int? {
        get { attributes[.effectiveKeySize] as? Int }
        set { attributes[.effectiveKeySize] = newValue }
    }
    
    /**
     Presence of this key indicates that the item is backed by an external store, as uniquely identified by the value. An item without this attribute is stored as normal in the keychain database.
     - Note: You can’t change this attribute after creating the keychain item. It isn’t possible to migrate existing items between stores.
     */
    var tokenID: TokenID? {
        get {
            if let rawValue = attributes[.tokenID] as? String {
                return TokenID(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[.tokenID] = newValue?.rawValue }
    }
    
    // MARK: - Usage
    
    /**
     The corresponding value indicates whether or not this cryptographic key or key pair should be stored in the default keychain at creation time.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`.
     */
    var isPermament: Bool? {
        get { attributes[.isPermament] as? Bool }
        set { attributes[.isPermament] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to encrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`for private keys and `true` for public keys.
     */
    var canEncrypt: Bool? {
        get { attributes[.canEncrypt] as? Bool }
        set { attributes[.canEncrypt] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to decrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canDecrypt: Bool? {
        get { attributes[.canDecrypt] as? Bool }
        set { attributes[.canDecrypt] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to derive another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true`.
     */
    var canDerive: Bool? {
        get { attributes[.canDerive] as? Bool }
        set { attributes[.canDerive] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to create a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canSign: Bool? {
        get { attributes[.canSign] as? Bool }
        set { attributes[.canSign] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to verify a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canVerify: Bool? {
        get { attributes[.canVerify] as? Bool }
        set { attributes[.canVerify] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to wrap another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canWrap: Bool? {
        get { attributes[.canWrap] as? Bool }
        set { attributes[.canWrap] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to unwrap another key.
     On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canUnwrap: Bool? {
        get { attributes[.canUnwrap] as? Bool }
        set { attributes[.canUnwrap] = newValue }
    }
}

#if os(macOS)
public extension SecItemQuery where Value == SecKey {
    /// The corresponding value indicates the pseudorandom function associated with this cryptographic key.
    var prf: PRFHmacAlg? {
        get {
            if let rawValue = attributes[.prf] as? String {
                return PRFHmacAlg(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[.prf] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the salt to use with this cryptographic key.
    var salt: Data? {
        get { attributes[.salt] as? Data }
        set { attributes[.salt] = newValue }
    }

    /// The corresponding value indicates the number of rounds to run the pseudorandom function specified by ``prf`` for a cryptographic key.
    var rounds: Int? {
        get {
            if let number = attributes[.rounds] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                attributes[.rounds] = NSNumber(integerLiteral: newValue)
            } else {
                attributes[.rounds] = nil
            }
        }
    }
}
#endif

public extension SecItemQuery {
    subscript(attribute: String) -> Any? {
        get { attributes[attribute] }
        set { attributes[attribute] = newValue }
    }
}

extension SecItemQuery: CustomDebugStringConvertible {
    public var debugDescription: String {
        attributes.debugDescription
    }
}
