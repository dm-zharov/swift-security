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
struct SecItemAttr: Equatable, RawRepresentable {
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
    static let useUserIndependentKeychain = SecItemAttr(rawValue: kSecUseUserIndependentKeychain as String)
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

extension SecItemAttr {
    static let `class`                   = SecItemAttr(rawValue: kSecClass as String)
    static let useDataProtectionKeychain = SecItemAttr(rawValue: kSecUseDataProtectionKeychain as String)
}

extension SecItemAttr: CustomStringConvertible {
    var description: String {
        switch self {
        case .accessControl:
            return "Access Control"
        case .accessible:
            return "Accessible"
        case .accessGroup:
            return "Access Group"
        case .synchronizable:
            return "Synchronizable"
        case .creationDate:
            return "Creation Date"
        case .modificationDate:
            return "Modification Date"
        case .description:
            return "Description"
        case .comment:
            return "Comment"
        case .creator:
            return "Creator"
        case .type:
            return "Type"
        case .label:
            return "Label"
        case .isInvisible:
            return "Is Invisible"
        case .isNegative:
            return "Is Negative"
        case .syncViewHint:
            return "Sync View Hint"
        case .persistentReference:
            return "Persistent Reference"
        case .account:
            return "Account"
        case .service:
            return "Service"
        case .generic:
            return "Generic"
        case .securityDomain:
            return "Security Domain"
        case .server:
            return "Server"
        case .protocolType:
            return "Protocol"
        case .authenticationType:
            return "Authentication Type"
        case .port:
            return "Port"
        case .path:
            return "Path"
        case .subject:
            return "Subject"
        case .issuer:
            return "Issuer"
        case .serialNumber:
            return "Serial Number"
        case .subjectKeyID:
            return "Subject Key ID"
        case .publicKeyHash:
            return "Public Key Hash"
        case .certificateType:
            return "Certificate Type"
        case .certificateEncoding:
            return "Certificate Encoding"
        case .keyClass:
            return "Key Class"
        case .applicationLabel:
            return "Application Label"
        case .applicationTag:
            return "Application Tag"
        case .keyType:
            return "Key Type"
        case .keySizeInBits:
            return "Key Size In Bits"
        case .effectiveKeySize:
            return "Effective Key Size"
        case .tokenID:
            return "Token ID"
        #if os(macOS)
        case .prf:
            return "PRF"
        case .salt:
            return "Salt"
        case .rounds:
            return "Rounds"
        #endif
        case .isPermament:
            return "Is Permament"
        case .isSensitive:
            return "Is Sensitive"
        case .isExtractable:
            return "Is Extractable"
        case .canEncrypt:
            return "Can Encrypt"
        case .canDecrypt:
            return "Can Decrypt"
        case .canDerive:
            return "Can Derive"
        case .canSign:
            return "Can Sign"
        case .canVerify:
            return "Can Verify"
        case .canWrap:
            return "Can Wrap"
        case .canUnwrap:
            return "Can Unwrap"
        case .class:
            return "Class"
        case .useDataProtectionKeychain:
            return "Use Advanced Data Protection"
        default:
            #if os(tvOS)
            if #available(tvOS 16.0, *), self == .useUserIndependentKeychain {
                return "Use User Independent Keychain"
            }
            #endif
            return rawValue
        }
    }
}
