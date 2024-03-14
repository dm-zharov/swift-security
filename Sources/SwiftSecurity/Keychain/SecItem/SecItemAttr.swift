//
//  SecItemAttr.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

/**
 Item Attribute Keys
 - SeeAlso: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values
 */
struct SecItemAttr: RawRepresentable {
    var rawValue: String
}

// MARK: - General Item Attribute Keys

extension SecItemAttr {
    static let accessControl       = SecItemAttr(rawValue: kSecAttrAccessControl as String)
    static let accessible          = SecItemAttr(rawValue: kSecAttrAccessible as String)
    static let accessGroup         = SecItemAttr(rawValue: kSecAttrAccessGroup as String)
    static let synchronizable      = SecItemAttr(rawValue: kSecAttrSynchronizable as String)
    static let creationDate        = SecItemAttr(rawValue: kSecAttrCreationDate as String)
    static let modificationDate    = SecItemAttr(rawValue: kSecAttrModificationDate as String)
    static let description         = SecItemAttr(rawValue: kSecAttrDescription as String)
    static let comment             = SecItemAttr(rawValue: kSecAttrComment as String)
    static let creator             = SecItemAttr(rawValue: kSecAttrCreator as String)
    static let type                = SecItemAttr(rawValue: kSecAttrType as String)
    static let label               = SecItemAttr(rawValue: kSecAttrLabel as String)
    static let isInvisible         = SecItemAttr(rawValue: kSecAttrIsInvisible as String)
    static let isNegative          = SecItemAttr(rawValue: kSecAttrIsNegative as String)
    static let syncViewHint        = SecItemAttr(rawValue: kSecAttrSyncViewHint as String)
    static let persistentReference = SecItemAttr(rawValue: kSecAttrPersistentReference as String)
    
    #if os(macOS)
    /// A key with a value that indicates access control list settings for the item.
    @available(macOS, unavailable, message: "This attribute couldn't be applied because `useDataProtectionKeychain` is consistently set to `true`")
    static let access = SecItemAttr(rawValue: kSecAttrAccess as String)
    #endif

    #if os(tvOS)
    @available(tvOS 16.0, *)
    static let useUserIndependentKeychain = SecItemAttr(rawValue: kSecUseUserIndependentKeychain)
    #endif
}

// MARK: - Password Attribute Keys

extension SecItemAttr {
    static let account             = SecItemAttr(rawValue: kSecAttrAccount as String)
    static let service             = SecItemAttr(rawValue: kSecAttrService as String)
    static let generic             = SecItemAttr(rawValue: kSecAttrGeneric as String)
    static let securityDomain      = SecItemAttr(rawValue: kSecAttrSecurityDomain as String)
    static let server              = SecItemAttr(rawValue: kSecAttrServer as String)
    static let protocolType        = SecItemAttr(rawValue: kSecAttrProtocol as String)
    static let authenticationType  = SecItemAttr(rawValue: kSecAttrAuthenticationType as String)
    static let port                = SecItemAttr(rawValue: kSecAttrPort as String)
    static let path                = SecItemAttr(rawValue: kSecAttrPath as String)
}

// MARK: - Certificate Attribute Keys

extension SecItemAttr {
    static let subject             = SecItemAttr(rawValue: kSecAttrSubject as String)
    static let issuer              = SecItemAttr(rawValue: kSecAttrIssuer as String)
    static let serialNumber        = SecItemAttr(rawValue: kSecAttrSerialNumber as String)
    static let subjectKeyID        = SecItemAttr(rawValue: kSecAttrSubjectKeyID as String)
    static let publicKeyHash       = SecItemAttr(rawValue: kSecAttrPublicKeyHash as String)
    static let certificateType     = SecItemAttr(rawValue: kSecAttrCertificateType as String)
    static let certificateEncoding = SecItemAttr(rawValue: kSecAttrCertificateEncoding as String)
}

// MARK: - Cryptographic Key Attribute Keys

extension SecItemAttr {
    static let keyClass            = SecItemAttr(rawValue: kSecAttrKeyClass as String)
    static let applicationLabel    = SecItemAttr(rawValue: kSecAttrApplicationLabel as String)
    static let applicationTag      = SecItemAttr(rawValue: kSecAttrApplicationTag as String)
    static let keyType             = SecItemAttr(rawValue: kSecAttrKeyType as String)
    static let keySizeInBits       = SecItemAttr(rawValue: kSecAttrKeySizeInBits as String)
    static let effectiveKeySize    = SecItemAttr(rawValue: kSecAttrEffectiveKeySize as String)
    static let tokenID             = SecItemAttr(rawValue: kSecAttrTokenID as String)
    
    #if os(macOS)
    static let prf                 = SecItemAttr(rawValue: kSecAttrPRF as String)
    static let salt                = SecItemAttr(rawValue: kSecAttrSalt as String)
    static let rounds              = SecItemAttr(rawValue: kSecAttrRounds as String)
    #endif
    
    // MARK: Usage
    
    static let isPermament         = SecItemAttr(rawValue: kSecAttrIsPermanent as String)
    static let isSensitive         = SecItemAttr(rawValue: kSecAttrIsSensitive as String)
    static let isExtractable       = SecItemAttr(rawValue: kSecAttrIsExtractable as String)
    static let canEncrypt          = SecItemAttr(rawValue: kSecAttrCanEncrypt as String)
    static let canDecrypt          = SecItemAttr(rawValue: kSecAttrCanDecrypt as String)
    static let canDerive           = SecItemAttr(rawValue: kSecAttrCanDerive as String)
    static let canSign             = SecItemAttr(rawValue: kSecAttrCanSign as String)
    static let canVerify           = SecItemAttr(rawValue: kSecAttrCanVerify as String)
    static let canWrap             = SecItemAttr(rawValue: kSecAttrCanWrap as String)
    static let canUnwrap           = SecItemAttr(rawValue: kSecAttrCanUnwrap as String)
}

extension Dictionary where Key == String {
    subscript(attribute: SwiftSecurity.SecItemAttr) -> Value? {
        get { self[attribute.rawValue] }
        set { self[attribute.rawValue] = newValue }
    }
}
