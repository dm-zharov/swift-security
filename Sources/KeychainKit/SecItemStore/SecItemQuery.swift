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
    
    private init(itemClass: SecItemClass) {
        self.attributes = [
            kSecClass: itemClass.rawValue,
            kSecUseDataProtectionKeychain: true, // This key affects only macOS.
        ] as [String: Any]
    }
}

// MARK: - Creation

extension SecItemQuery {
    public init() where Value == GenericPassword {
        self.init(itemClass: .genericPassword)
    }
    
    public init() where Value == InternetPassword {
        self.init(itemClass: .internetPassword)
    }
    
    public init() where Value == SecKey {
        self.init(itemClass: .key)
    }
    
    public init() where Value == SecCertificate {
        self.init(itemClass: .certificate)
    }
    
    public init() where Value == SecIdentity {
        self.init(itemClass: .identity)
    }
}

// MARK: - Common

public extension SecItemQuery {
    /**
     The corresponding value indicates the item’s one and only access group.
     
     For an app to access a keychain item, one of the groups to which the app belongs must be the item’s group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string
     - The strings in the [App Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     Two or more apps that are in the same access group can share keychain items. For more details, see Sharing access to keychain items among a collection of apps.
     */
    var accessGroup: String? {
        get { attributes[kSecAttrAccessGroup as String] as? String }
        set { attributes[kSecAttrAccessGroup as String] = newValue }
    }
    
    /// The corresponding value indicates access control conditions for the item.
    var accessControl: AccessControl? {
        get {
            if let value = attributes[kSecAttrAccessControl as String] as? AnyObject {
                let rawValue = value as! SecAccessControl
                return AccessControl(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrAccessControl as String] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates whether the item in question is synchronized to other devices through iCloud.
    var synchronizable: Bool? {
        get { attributes[kSecAttrSynchronizable as String] as? Bool }
        set { attributes[kSecAttrSynchronizable as String] = newValue }
    }
    
    /// The corresponding value indicates when your app needs access to the data in a keychain item.
    var accessible: Accessible? {
        get {
            if let rawValue = attributes[kSecAttrAccessible as String] as? String {
                return Accessible(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrAccessible as String] = newValue?.rawValue }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var label: String? {
        get { attributes[kSecAttrLabel as String] as? String }
        set { attributes[kSecAttrLabel as String] = newValue }
    }
}

// MARK: - Password

public extension SecItemQuery where Value == GenericPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: String? {
        get { attributes[kSecAttrAccount as String] as? String }
        set { attributes[kSecAttrAccount as String] = newValue }
    }
    
    /// The corresponding value represents the service associated with this item.
    var service: String? {
        get { attributes[kSecAttrService as String] as? String }
        set { attributes[kSecAttrService as String] = newValue }
    }
    
    // MARK: - User
    
    /// The corresponding value contains a user-defined attribute.
    var generic: Data? {
        get { attributes[kSecAttrGeneric as String] as? Data }
        set { attributes[kSecAttrGeneric as String] = newValue }
    }
}

public extension SecItemQuery where Value == InternetPassword {    
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: String? {
        get { attributes[kSecAttrAccount as String] as? String }
        set { attributes[kSecAttrAccount as String] = newValue }
    }
    
    /// The corresponding value denotes the authentication scheme for this item.
    var authenticationType: AuthenticationType? {
        get {
            if let value = attributes[kSecAttrAuthenticationType as String] as? String {
                return AuthenticationType(rawValue: value)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrAuthenticationType as String] = newValue?.rawValue }
    }
    
    /// The corresponding value represents a path, typically the path component of the URL.
    var path: String? {
        get { attributes[kSecAttrPath as String] as? String }
        set { attributes[kSecAttrPath as String] = newValue }
    }
    
    /// The corresponding represents an Internet port number.
    var port: Int? {
        get {
            if let number = attributes[kSecAttrPort as String] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                attributes[kSecAttrPort as String] = NSNumber(integerLiteral: newValue)
            } else {
                attributes[kSecAttrPort as String] = nil
            }
        }
    }
    
    /// The corresponding value denotes the protocol for this item.
    var `protocol`: ProtocolType? {
        get {
            if let value = attributes[kSecAttrProtocol as String] as? String {
                return ProtocolType(rawValue: value)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrProtocol as String] = newValue?.rawValue }
    }
    
    /// The corresponding value represents the Internet security domain.
    var securityDomain: String? {
        get { attributes[kSecAttrSecurityDomain as String] as? String }
        set { attributes[kSecAttrSecurityDomain as String] = newValue }
    }
    
    /// The corresponding value contains the server's domain name or IP address.
    var server: String? {
        get { attributes[kSecAttrServer as String] as? String }
        set { attributes[kSecAttrServer as String] = newValue }
    }
}

extension SecItemQuery where Value: Password {
    // MARK: - User
    
    /// The corresponding value specifies a user-visible string describing this kind of item (for example, "Disk image password").
    var description: String? {
        get { attributes[kSecAttrDescription as String] as? String }
        set { attributes[kSecAttrDescription as String] = newValue }
    }
    
    /// The corresponding value contains the user-editable comment for this item.
    var comment: String? {
        get { attributes[kSecAttrComment as String] as? String }
        set { attributes[kSecAttrComment as String] = newValue }
    }
    
    /// The corresponding value represents the item's creator. This number is the unsigned integer representation of a four-character code (for example, 'aCrt').
    var creator: NSNumber? {
        get { attributes[kSecAttrCreator as String] as? NSNumber }
        set { attributes[kSecAttrCreator as String] = newValue }
    }
    
    /// The corresponding value  represents the item's type. This number is the unsigned integer representation of a four-character code (for example, 'aTyp').
    var type: NSNumber? {
        get { attributes[kSecAttrType as String] as? NSNumber }
        set { attributes[kSecAttrType as String] = newValue }
    }
    
    /// The corresponding value is kCFBooleanTrue if the item is invisible (that is, should not be displayed).
    var isInvisible: Bool? {
        get { attributes[kSecAttrIsInvisible as String] as? Bool }
        set { attributes[kSecAttrIsInvisible as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether there is a valid password associated with this keychain item.
     This is useful if your application doesn't want a password for some particular service to be stored in the keychain, but prefers that it always be entered by the user.
     */
    var isNegative: Bool? {
        get { attributes[kSecAttrIsNegative as String] as? Bool }
        set { attributes[kSecAttrIsNegative as String] = newValue }
    }
}

// MARK: - Sec Key

public extension SecItemQuery where Value == SecKey {
    // MARK: - Primary
    
    /**
     The corresponding value contains a label for this item.
     This attribute is different from the ``label`` attribute, which is intended to be human-readable.
     Instead, this attribute is used to look up a key programmatically; in particular, for `public` and `private` keys, the value of this attribute is the hash of the public key.
     */
    var applicationLabel: Data? {
        get { attributes[kSecAttrApplicationLabel as String] as? Data }
        set { attributes[kSecAttrApplicationLabel as String] = newValue }
    }
    
    /// The corresponding value contains private tag data.
    var applicationTag: Data? {
        get { attributes[kSecAttrApplicationTag as String] as? Data }
        set { attributes[kSecAttrApplicationTag as String] = newValue }
    }
    
    /// The corresponding value specifies a type of cryptographic key.
    var keyClass: KeyClass? {
        get {
            if let rawValue = attributes[kSecAttrKeyClass as String] as? String {
                return KeyClass(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrKeyClass as String] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the algorithm associated with this cryptographic key.
    var keyType: KeyType? {
        get {
            if let rawValue = attributes[kSecAttrKeyType as String] as? String {
                return KeyType(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrKeyType as String] = newValue?.rawValue }
    }

    /// The corresponding value indicates the total number of bits in this cryptographic key.
    var keySizeInBits: Int? {
        get { attributes[kSecAttrKeySizeInBits as String] as? Int }
        set { attributes[kSecAttrKeySizeInBits as String] = newValue }
    }

    var effectiveKeySize: Int? {
        get { attributes[kSecAttrEffectiveKeySize as String] as? Int }
        set { attributes[kSecAttrEffectiveKeySize as String] = newValue }
    }
    
    // MARK: - Security
    
    /**
     The corresponding value indicates whether or not this cryptographic key or key pair should be stored in the default keychain at creation time.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`.
     */
    var isPermament: Bool? {
        get { attributes[kSecAttrIsPermanent as String] as? Bool }
        set { attributes[kSecAttrIsPermanent as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to encrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`for private keys and `true` for public keys.
     */
    var canEncrypt: Bool? {
        get { attributes[kSecAttrCanEncrypt as String] as? Bool }
        set { attributes[kSecAttrCanEncrypt as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to decrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canDecrypt: Bool? {
        get { attributes[kSecAttrCanDecrypt as String] as? Bool }
        set { attributes[kSecAttrCanDecrypt as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to derive another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true`.
     */
    var canDerive: Bool? {
        get { attributes[kSecAttrCanDerive as String] as? Bool }
        set { attributes[kSecAttrCanDerive as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to create a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canSign: Bool? {
        get { attributes[kSecAttrCanSign as String] as? Bool }
        set { attributes[kSecAttrCanSign as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to verify a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canVerify: Bool? {
        get { attributes[kSecAttrCanVerify as String] as? Bool }
        set { attributes[kSecAttrCanVerify as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to wrap another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canWrap: Bool? {
        get { attributes[kSecAttrCanWrap as String] as? Bool }
        set { attributes[kSecAttrCanWrap as String] = newValue }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to unwrap another key.
     On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canUnwrap: Bool? {
        get { attributes[kSecAttrCanUnwrap as String] as? Bool }
        set { attributes[kSecAttrCanUnwrap as String] = newValue }
    }
}

#if os(macOS)
public extension SecItemQuery where Value == SecKey {
    /// The corresponding value indicates the pseudorandom function associated with this cryptographic key.
    var prf: PRFHmacAlg? {
        get {
            if let rawValue = attributes[kSecAttrPRF as String] as? String {
                return PRFHmacAlg(rawValue: rawValue)
            } else {
                return nil
            }
        }
        set { attributes[kSecAttrPRF as String] = newValue?.rawValue }
    }
    
    /// The corresponding value indicates the salt to use with this cryptographic key.
    var salt: Data? {
        get { attributes[kSecAttrSalt as String] as? Data }
        set { attributes[kSecAttrSalt as String] = newValue }
    }

    /// The corresponding value indicates the number of rounds to run the pseudorandom function specified by ``prf`` for a cryptographic key.
    var rounds: Int? {
        get {
            if let number = attributes[kSecAttrRounds as String] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                attributes[kSecAttrRounds as String] = NSNumber(integerLiteral: newValue)
            } else {
                attributes[kSecAttrRounds as String] = nil
            }
        }
    }
}
#endif
