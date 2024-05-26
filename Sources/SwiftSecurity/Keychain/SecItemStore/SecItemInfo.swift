//
//  SecItemInfo.swift
//
//
//  Created by Dmitriy Zharov on 22.01.2024.
//

import Foundation

public struct SecItemInfo<Value>: RawRepresentable where Value: SecItem {
    public let rawValue: [String: Any]
    
    public init(rawValue: [String: Any]) {
        self.rawValue = rawValue
    }
}

// MARK: - Common

public extension SecItemInfo {
    /// The corresponding value indicates the item’s one and only access group.
    var accessGroup: PrimaryKey<String>? {
        get { self[.accessGroup] as? String }
    }
    
    /// The corresponding value contains access control conditions for the item.
    var accessControl: SecAccessControl? {
        get { self[.accessControl] as! SecAccessControl? }
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
    }
    
    /// The corresponding value indicates whether the item in question is synchronized to other devices through iCloud.
    var synchronizable: PrimaryKey<Bool>? {
        get { self[.synchronizable] as? Bool }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var label: String? {
        get { self[.label] as? String }
    }
    
    /// For keys and password items, the data is secret (encrypted) and may require the user to enter a password for access.
    var data: Data? {
        get { self[kSecValueData as String] as? Data }
    }
    
    /// Depending on the item class requested, the returned references may be of type `SecKey`, `SecCertificate`, `SecIdentity`, or `Data`.
    var reference: AnyObject? {
        get { self[kSecValueRef as String] as? AnyObject }
    }
    
    /// The bytes in this object can be stored by the caller and used on a subsequent invocation of the application (or even a different application) to retrieve the item referenced by it.
    var persistentReference: Data? {
        get { self[kSecValuePersistentRef as String] as? Data }
    }
}

#if os(tvOS)
public extension SecItemInfo {
    @available(tvOS 16.0, *)
    var useUserIndependentKeychain: Bool? {
        get { self[.useUserIndependentKeychain] as? Bool }
    }
}
#endif

// MARK: - GenericPassword

public extension SecItemInfo where Value == GenericPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: PrimaryKey<String>? {
        get { self[.account] as? String }
    }
    
    /// The corresponding value represents the service associated with this item.
    var service: PrimaryKey<String>? {
        get { self[.service] as? String }
    }
    
    // MARK: - Attributes
    
    /// The corresponding value contains a user-defined attribute.
    var generic: Data? {
        get { self[.generic] as? Data }
    }
}

// MARK: - InternetPassword

public extension SecItemInfo where Value == InternetPassword {
    // MARK: - Primary
    
    /// The corresponding value contains an account name.
    var account: PrimaryKey<String>? {
        get { self[.account] as? String }
    }
    
    /// The corresponding value denotes the authentication scheme for this item.
    var authenticationMethod: PrimaryKey<AuthenticationMethod>? {
        get {
            if let value = self[.authenticationType] as? String {
                return AuthenticationMethod(rawValue: value)
            } else {
                return nil
            }
        }
    }
    
    /// The corresponding value represents a path, typically the path component of the URL.
    var path: PrimaryKey<String>? {
        get { self[.path] as? String }
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
    }
    
    /// The corresponding value represents the Internet security domain.
    var securityDomain: PrimaryKey<String>? {
        get { self[.securityDomain] as? String }
    }
    
    /// The corresponding value contains the server's domain name or IP address.
    var server: PrimaryKey<String>? {
        get { self[.server] as? String }
    }
}

// MARK: - Generic and Internet Password

public extension SecItemInfo where Value: SecData {
    // MARK: - Attributes
    
    /// The corresponding value represents the date the item was created. Read only.
    var creationDate: Date? {
        get { self[.creationDate] as? Date }
    }
    
    /// The corresponding value contains the user-visible label for this item.
    var modificationDate: Date? {
        get { self[.modificationDate] as? Date }
    }
    
    /// The corresponding value specifies a user-visible string describing this kind of item (for example, "Disk image password").
    var description: String? {
        get { self[.description] as? String }
    }
    
    /// The corresponding value contains the user-editable comment for this item.
    var comment: String? {
        get { self[.comment] as? String }
    }
    
    /// The corresponding value represents the item's creator. This number is the unsigned integer representation of a four-character code (for example, 'aCrt').
    var creator: FourCharCode? {
        get { self[.creator] as? FourCharCode }
    }
    
    /// The corresponding value  represents the item's type. This number is the unsigned integer representation of a four-character code (for example, 'aTyp').
    var type: FourCharCode? {
        get { self[.type] as? FourCharCode }
    }
    
    /// The corresponding value is kCFBooleanTrue if the item is invisible (that is, should not be displayed).
    var isInvisible: Bool? {
        get { self[.isInvisible] as? Bool }
    }
    
    /**
     The corresponding value indicates whether there is a valid password associated with this keychain item.
     This is useful if your application doesn't want a password for some particular service to be stored in the keychain, but prefers that it always be entered by the user.
     */
    var isNegative: Bool? {
        get { self[.isNegative] as? Bool }
    }
}

// MARK: - SecKey

public extension SecItemInfo where Value == SecKey {
    // MARK: - Primary
    
    /**
     The corresponding value contains a label for this item.
     This attribute is different from the ``label`` attribute, which is intended to be human-readable.
     Instead, this attribute is used to look up a key programmatically; in particular, for `public` and `private` keys, the value of this attribute is the hash of the public key.
     
     - Note: To form a digital identity, this value must match the ``publicKeyHash`` ('pkhh') attribute of the `SecCertificate`.
     */
    var applicationLabel: PrimaryKey<Data>? {
        get { self[.applicationLabel] as? Data }
    }
    
    /// The corresponding value contains private tag data.
    var applicationTag: PrimaryKey<Data>? {
        get { self[.applicationTag] as? Data }
    }
    
    /// The corresponding value specifies a type of cryptographic key.
    var keyClass: PrimaryKey<KeyType>? {
        get {
            if let rawValue = self[.keyClass] as? String {
                return KeyType(rawValue: rawValue)
            } else {
                return nil
            }
        }
    }
    
    /// The corresponding value indicates the algorithm associated with this cryptographic key.
    var keyType: PrimaryKey<AlgorithmType>? {
        get {
            if let rawValue = self[.keyType] as? String {
                return AlgorithmType(rawValue: rawValue)
            } else {
                return nil
            }
        }
    }

    /// The corresponding value indicates the total number of bits in this cryptographic key.
    var keySizeInBits: PrimaryKey<Int>? {
        get { self[.keySizeInBits] as? Int }
    }

    var effectiveKeySize: PrimaryKey<Int>? {
        get { self[.effectiveKeySize] as? Int }
    }
    
    // MARK: - Usage
    
    /**
     The corresponding value indicates whether or not this cryptographic key or key pair should be stored in the default keychain at creation time.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`.
     */
    var isPermament: Bool? {
        get { self[.isPermament] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to encrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false`for private keys and `true` for public keys.
     */
    var canEncrypt: Bool? {
        get { self[.canEncrypt] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to decrypt data.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canDecrypt: Bool? {
        get { self[.canDecrypt] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to derive another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true`.
     */
    var canDerive: Bool? {
        get { self[.canDerive] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to create a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canSign: Bool? {
        get { self[.canSign] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to verify a digital signature.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canVerify: Bool? {
        get { self[.canVerify] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to wrap another key.
     - Note: On key creation, if not explicitly specified, this attribute defaults to `false` for private keys and `true` for public keys.
     */
    var canWrap: Bool? {
        get { self[.canWrap] as? Bool }
    }
    
    /**
     The corresponding value indicates whether this cryptographic key can be used to unwrap another key.
     On key creation, if not explicitly specified, this attribute defaults to `true` for private keys and `false` for public keys.
     */
    var canUnwrap: Bool? {
        get { self[.canUnwrap] as? Bool }
    }
}

// MARK: - SecCertificate

public extension SecItemInfo where Value == SecCertificate {
    // MARK: - Primary
    
    /**
     The corresponding value denotes the certificate type (see the CSSM_CERT_TYPE enumeration in cssmtype.h).
     - Note: Read only.
     */
    var certificateType: PrimaryKey<NSNumber>? {
        get { self[.certificateType] as? NSNumber }
    }
    
    /**
     The corresponding value contains the X.500 issuer name of a certificate.
     - Note: Read only.
     */
    var issuer: PrimaryKey<Data>? {
        get { self[.issuer] as? Data }
    }
    
    /**
     The corresponding value contains the serial number data of a certificate.
     - Note: Read only.
     */
    var serialNumber: PrimaryKey<Data>? {
        get { self[.serialNumber] as? Data }
    }

    // MARK: - Attributes
    
    /**
     The corresponding value denotes the certificate encoding (see the CSSM_CERT_ENCODING enumeration in cssmtype.h).
     - Note: Read only.
     */
    var certificateEncoding: NSNumber? {
        get { self[.certificateEncoding] as? NSNumber }
    }
    
    /**
     The corresponding value denotes the certificate encoding (see the CSSM_CERT_ENCODING enumeration in cssmtype.h).
     - Note: Read only.
     */
    var subject: Data? {
        get { self[.subject] as? Data }
    }
    
    /**
     The corresponding value contains the subject key ID of a certificate.
     - Note: Read only.
     */
    var subjectKeyID: Data? {
        get { self[.subjectKeyID] as? Data }
    }
    
    /**
     The corresponding value contains the hash of a certificate's public key.
     - Note: Read only. To form a digital identity, this value must match the ``applicationLabel`` ('klbl') attribute of the `SecKey`.
     */
    var publicKeyHash: Data? {
        get { self[.publicKeyHash] as? Data }
    }
}

extension SecItemInfo: CustomDebugStringConvertible {
    public var debugDescription: String {
        return Keychain.DebugFormatStyle().format(rawValue)
    }
}

extension SecItemInfo {
    public subscript(attribute: String) -> Any? {
        get { rawValue[attribute] }
    }
}

extension SecItemInfo {
    subscript(key: SecItemAttrKey) -> Any? {
        get { self[key.rawValue] }
    }
    
    subscript(search key: SecItemSearchKey) -> Any? {
        get { self[key.rawValue] }
    }
}
