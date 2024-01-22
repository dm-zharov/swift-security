//
//  SecItemInfo.swift
//
//
//  Created by Dmitriy Zharov on 22.01.2024.
//

import Foundation

public struct SecItemInfo<Value> where Value: SecItem {
    private(set) var attributes: [String: Any]
    
    internal init(_ attributes: [String: Any]) {
        self.attributes = attributes
    }
}

// MARK: - Common

public extension SecItemInfo {
    /// The corresponding value indicates the item’s one and only access group.
    var accessGroup: String? {
        get { attributes[kSecAttrAccessGroup as String] as? String }
    }
    
    /// The corresponding value contains access control conditions for the item.
    var accessControl: SecAccessControl? {
        get { attributes[kSecAttrAccessControl as String] as! SecAccessControl? }
    }
    
    /// The corresponding value indicates the item’s one and only access group.
    var accessible: SecAccessPolicy.Accessibility? {
        get {
            if let rawValue = attributes[kSecAttrAccessible as String] as? String {
                return SecAccessPolicy.Accessibility(rawValue: rawValue)
            } else {
                return nil
            }
        }
    }
    
    /// The corresponding value indicates whether the item in question is synchronized to other devices through iCloud.
    var synchronizable: Bool? {
        get { attributes[kSecAttrSynchronizable as String] as? Bool }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var label: String? {
        get { attributes[kSecAttrLabel as String] as? String }
    }
}

// MARK: - GenericPassword

public extension SecItemInfo where Value == GenericPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: String? {
        get { attributes[kSecAttrAccount as String] as? String }
    }
    
    /// The corresponding value represents the service associated with this item.
    var service: String? {
        get { attributes[kSecAttrService as String] as? String }
    }
    
    // MARK: - Attributes
    
    /// The corresponding value contains a user-defined attribute.
    var generic: Data? {
        get { attributes[kSecAttrGeneric as String] as? Data }
    }
}

// MARK: - InternetPassword

public extension SecItemInfo where Value == InternetPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: String? {
        get { attributes[kSecAttrAccount as String] as? String }
    }
    
    /// The corresponding value denotes the authentication scheme for this item.
    var authenticationMethod: AuthenticationMethod? {
        get {
            if let value = attributes[kSecAttrAuthenticationType as String] as? String {
                return AuthenticationMethod(rawValue: value)
            } else {
                return nil
            }
        }
    }
    
    /// The corresponding value represents a path, typically the path component of the URL.
    var path: String? {
        get { attributes[kSecAttrPath as String] as? String }
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
    }
    
    /// The corresponding value represents the Internet security domain.
    var securityDomain: String? {
        get { attributes[kSecAttrSecurityDomain as String] as? String }
    }
    
    /// The corresponding value contains the server's domain name or IP address.
    var server: String? {
        get { attributes[kSecAttrServer as String] as? String }
    }
}

// MARK: - Generic and Internet Password

public extension SecItemInfo where Value: Password {
    // MARK: - Attributes
    
    /// The corresponding value represents the date the item was created. Read only.
    var creationDate: Date? {
        get { attributes[kSecAttrCreationDate as String] as? Date }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var modificationDate: Date? {
        get { attributes[kSecAttrModificationDate as String] as? Date }
    }
    
    /// The corresponding value specifies a user-visible string describing this kind of item (for example, "Disk image password").
    var description: String? {
        get { attributes[kSecAttrDescription as String] as? String }
    }
    
    /// The corresponding value contains the user-editable comment for this item.
    var comment: String? {
        get { attributes[kSecAttrComment as String] as? String }
    }
    
    /// The corresponding value represents the item's creator. This number is the unsigned integer representation of a four-character code (for example, 'aCrt').
    var creator: NSNumber? {
        get { attributes[kSecAttrCreator as String] as? NSNumber }
    }
    
    /// The corresponding value  represents the item's type. This number is the unsigned integer representation of a four-character code (for example, 'aTyp').
    var type: NSNumber? {
        get { attributes[kSecAttrType as String] as? NSNumber }
    }
    
    /// The corresponding value is kCFBooleanTrue if the item is invisible (that is, should not be displayed).
    var isInvisible: Bool? {
        get { attributes[kSecAttrIsInvisible as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether there is a valid password associated with this keychain item.
     This is useful if your application doesn't want a password for some particular service to be stored in the keychain, but prefers that it always be entered by the user.
     */
    var isNegative: Bool? {
        get { attributes[kSecAttrIsNegative as String] as? Bool }
    }
}

// MARK: - SecKey

public extension SecItemInfo where Value == SecKey {
    // MARK: - Primary
    
    /**
     The corresponding value contains a label for this item.
     This attribute is different from the ``label`` attribute, which is intended to be human-readable.
     Instead, this attribute is used to look up a key programmatically; in particular, for `public` and `private` keys, the value of this attribute is the hash of the public key.
     */
    var applicationLabel: Data? {
        get { attributes[kSecAttrApplicationLabel as String] as? Data }
    }
    
    /// The corresponding value contains private tag data.
    var applicationTag: Data? {
        get { attributes[kSecAttrApplicationTag as String] as? Data }
    }
    
    /// The corresponding value specifies a type of cryptographic key.
    var keyClass: KeyType? {
        get {
            if let rawValue = attributes[kSecAttrKeyClass as String] as? String {
                return KeyType(rawValue: rawValue)
            } else {
                return nil
            }
        }
    }
    
    /// The corresponding value indicates the algorithm associated with this cryptographic key.
    var keyType: KeyCipher? {
        get {
            if let rawValue = attributes[kSecAttrKeyType as String] as? String {
                return KeyCipher(rawValue: rawValue)
            } else {
                return nil
            }
        }
    }

    /// The corresponding value indicates the total number of bits in this cryptographic key.
    var keySizeInBits: Int? {
        get { attributes[kSecAttrKeySizeInBits as String] as? Int }
    }

    var effectiveKeySize: Int? {
        get { attributes[kSecAttrEffectiveKeySize as String] as? Int }
    }
    
    // MARK: - Attributes
    
    /**
     The corresponding value indicates whether or not this cryptographic key or key pair should be stored in the default keychain at creation time.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`.
     */
    var isPermament: Bool? {
        get { attributes[kSecAttrIsPermanent as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to encrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`for private keys and `true` for public keys.
     */
    var canEncrypt: Bool? {
        get { attributes[kSecAttrCanEncrypt as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to decrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canDecrypt: Bool? {
        get { attributes[kSecAttrCanDecrypt as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to derive another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true`.
     */
    var canDerive: Bool? {
        get { attributes[kSecAttrCanDerive as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to create a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canSign: Bool? {
        get { attributes[kSecAttrCanSign as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to verify a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canVerify: Bool? {
        get { attributes[kSecAttrCanVerify as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to wrap another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canWrap: Bool? {
        get { attributes[kSecAttrCanWrap as String] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to unwrap another key.
     On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canUnwrap: Bool? {
        get { attributes[kSecAttrCanUnwrap as String] as? Bool }
    }
}

#if os(macOS)
public extension SecItemInfo where Value == SecKey {
    /// The corresponding value indicates the pseudorandom function associated with this cryptographic key.
    var prf: PRFHmacAlg? {
        get {
            if let rawValue = attributes[kSecAttrPRF as String] as? String {
                return PRFHmacAlg(rawValue: rawValue)
            } else {
                return nil
            }
        }
    }
    
    /// The corresponding value indicates the salt to use with this cryptographic key.
    var salt: Data? {
        get { attributes[kSecAttrSalt as String] as? Data }
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
    }
}
#endif

// MARK: - SecCertificate

public extension SecItemInfo where Value == SecCertificate {
    // MARK: - Primary
    
    /**
     The corresponding value denotes the certificate type (see the CSSM_CERT_TYPE enumeration in cssmtype.h).
     - Note: Read only.
     */
    var certificateType: NSNumber? {
        get { attributes[kSecAttrCertificateType as String] as? NSNumber }
    }
    
    /**
     The corresponding value contains the X.500 issuer name of a certificate.
     - Note: Read only.
     */
    var issuer: Data? {
        get { attributes[kSecAttrIssuer as String] as? Data }
    }
    
    /**
     The corresponding value contains the serial number data of a certificate.
     - Note: Read only.
     */
    var serialNumber: Data? {
        get { attributes[kSecAttrSerialNumber as String] as? Data }
    }

    // MARK: - Attributes
    
    /**
     The corresponding value denotes the certificate encoding (see the CSSM_CERT_ENCODING enumeration in cssmtype.h).
     - Note: Read only.
     */
    var certificateEncoding: NSNumber? {
        get { attributes[kSecAttrCertificateEncoding as String] as? NSNumber }
    }
    
    /**
     The corresponding value denotes the certificate encoding (see the CSSM_CERT_ENCODING enumeration in cssmtype.h).
     - Note: Read only.
     */
    var subject: Data? {
        get { attributes[kSecAttrSubject as String] as? Data }
    }
    
    /**
     The corresponding value contains the subject key ID of a certificate.
     - Note: Read only.
     */
    var subjectKeyID: Data? {
        get { attributes[kSecAttrSubjectKeyID as String] as? Data }
    }
    
    /**
     The corresponding value contains the hash of a certificate's public key..
     - Note: Read only.
     */
    var publicKeyHash: Data? {
        get { attributes[kSecAttrPublicKeyHash as String] as? Data }
    }
}

#if os(tvOS)
public extension SecItemInfo {
    @available(tvOS 16.0, *)
    var useUserIndependentKeychain: Bool? {
        get { attributes[kSecUseUserIndependentKeychain as String] as? String }
    }
}
#endif

public extension SecItemInfo {
    subscript(attribute: String) -> Any? {
        get { attributes[attribute] }
    }
}

extension SecItemInfo: CustomDebugStringConvertible {
    public var debugDescription: String {
        attributes.debugDescription
    }
}
