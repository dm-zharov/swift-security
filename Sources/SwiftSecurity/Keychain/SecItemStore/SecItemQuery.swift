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
    
    private init(class: SecItemClass) {
        self.rawValue = [
            kSecClass: `class`.rawValue,
            kSecUseDataProtectionKeychain: true, // The data protection key affects operations only in macOS.
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
    /**
     The corresponding value indicates whether the item in question is synchronized to other devices through iCloud.
     
     The following caveats apply when you specify this key:
     - You can set the key on tvOS, but tvOS doesn’t synchronize your app’s keychain items through iCloud.
     - Updating or deleting items using the key affects all copies of the item, not just the one on your local device. Be sure that it makes sense to use the same password on all devices before making a password synchronizable.
     - Items stored or obtained using the key may not also specify a ``accessPolicy`` value that is incompatible with syncing (namely, those whose names end with ThisDeviceOnly).
     */
    var synchronizable: Bool? {
        get { self[.synchronizable] as? Bool }
        set { self[.synchronizable] = newValue }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var label: String? {
        get { self[.label] as? String }
        set { self[.label] = newValue }
    }
}

#if os(tvOS)
public extension SecItemQuery {
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
    var account: String? {
        get { self[.account] as? String }
        set { self[.account] = newValue }
    }
    
    /// The corresponding value represents the service associated with this item.
    var service: String? {
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
    var account: String? {
        get { self[.account] as? String }
        set { self[.account] = newValue }
    }
    
    /// The corresponding value denotes the authentication scheme for this item.
    var authenticationMethod: AuthenticationMethod? {
        get {
            if let value = self[.authenticationType] as? String {
                return AuthenticationMethod(rawValue: value)
            } else {
                return nil
            }
        }
        set { self[.authenticationType] = newValue?.rawValue }
    }
    
    /// The corresponding value represents a path, typically the path component of the URL.
    var path: String? {
        get { self[.path] as? String }
        set { self[.path] = newValue }
    }
    
    /// The corresponding represents an Internet port number.
    var port: Int? {
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
    var `protocol`: ProtocolType? {
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
    var securityDomain: String? {
        get { self[.securityDomain] as? String }
        set { self[.securityDomain] = newValue }
    }
    
    /// The corresponding value contains the server's domain name or IP address.
    var server: String? {
        get { self[.server] as? String }
        set { self[.server] = newValue }
    }
}

// MARK: - Generic and Internet Password

public extension SecItemQuery where Value: Password {
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
     */
    var applicationLabel: Data? {
        get { self[.applicationLabel] as? Data }
        set { self[.applicationLabel] = newValue }
    }
    
    /// The corresponding value contains private tag data.
    var applicationTag: Data? {
        get { self[.applicationTag] as? Data }
        set { self[.applicationTag] = newValue }
    }
    
    /// The corresponding value specifies a type of cryptographic key.
    var keyClass: KeyType? {
        get {
            if let rawValue = self[.keyClass] as? String {
                return KeyType(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.keyClass] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the algorithm associated with this cryptographic key.
    var keyType: KeyCipher? {
        get {
            if let rawValue = self[.keyType] as? String {
                return KeyCipher(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.keyType] = newValue?.rawValue }
    }

    /// The corresponding value indicates the total number of bits in this cryptographic key.
    var keySizeInBits: Int? {
        get { self[.keySizeInBits] as? Int }
        set { self[.keySizeInBits] = newValue }
    }
    
    /// The corresponding value indicates the effective number of bits in this cryptographic key. For example, a DES key has a `keySizeInBits` of 64, but a `effectiveKeySize` of 56 bits.
    var effectiveKeySize: Int? {
        get { self[.effectiveKeySize] as? Int }
        set { self[.effectiveKeySize] = newValue }
    }
    
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
    
    // MARK: - Usage
    
    /**
     The corresponding value indicates whether or not this cryptographic key or key pair should be stored in the default keychain at creation time.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`.
     */
    var isPermament: Bool? {
        get { self[.isPermament] as? Bool }
        set { self[.isPermament] = newValue }
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

#if os(macOS)
public extension SecItemQuery where Value == SecKey {
    /// The corresponding value indicates the pseudorandom function associated with this cryptographic key.
    var prf: PRFHmacAlg? {
        get {
            if let rawValue = self[.prf] as? String {
                return PRFHmacAlg(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { self[.prf] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the salt to use with this cryptographic key.
    var salt: Data? {
        get { self[.salt] as? Data }
        set { self[.salt] = newValue }
    }

    /// The corresponding value indicates the number of rounds to run the pseudorandom function specified by ``prf`` for a cryptographic key.
    var rounds: Int? {
        get {
            if let number = self[.rounds] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                self[.rounds] = NSNumber(integerLiteral: newValue)
            } else {
                self[.rounds] = nil
            }
        }
    }
}
#endif

extension SecItemQuery: CustomDebugStringConvertible {
    public var debugDescription: String {
        return Keychain.DebugFormatStyle().format(rawValue)
    }
}

public extension SecItemQuery {
    subscript(attribute: String) -> Any? {
        get { rawValue[attribute] }
        set { rawValue[attribute] = newValue }
    }
}

extension SecItemQuery {
    subscript(attribute: SwiftSecurity.SecItemAttr) -> Any? {
        get { self[attribute.rawValue] }
        set { self[attribute.rawValue] = newValue }
    }
    
    subscript(search attribute: SwiftSecurity.SecItemSearch) -> Any? {
        get { self[attribute.rawValue] }
        set { self[attribute.rawValue] = newValue }
    }
}
