//
//  SecItemAttrKey.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

/**
 Item Attribute Key.
 - SeeAlso: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values
 */
struct SecItemAttrKey: Equatable, RawRepresentable {
    let rawValue: String
}

// MARK: - General Item Attribute Keys

extension SecItemAttrKey {
    static let accessControl       = SecItemAttrKey(rawValue: kSecAttrAccessControl as String)
    static let accessible          = SecItemAttrKey(rawValue: kSecAttrAccessible as String)
    static let accessGroup         = SecItemAttrKey(rawValue: kSecAttrAccessGroup as String)
    static let synchronizable      = SecItemAttrKey(rawValue: kSecAttrSynchronizable as String)
    static let creationDate        = SecItemAttrKey(rawValue: kSecAttrCreationDate as String)
    static let modificationDate    = SecItemAttrKey(rawValue: kSecAttrModificationDate as String)
    static let description         = SecItemAttrKey(rawValue: kSecAttrDescription as String)
    static let comment             = SecItemAttrKey(rawValue: kSecAttrComment as String)
    static let creator             = SecItemAttrKey(rawValue: kSecAttrCreator as String)
    static let type                = SecItemAttrKey(rawValue: kSecAttrType as String)
    static let label               = SecItemAttrKey(rawValue: kSecAttrLabel as String)
    static let isInvisible         = SecItemAttrKey(rawValue: kSecAttrIsInvisible as String)
    static let isNegative          = SecItemAttrKey(rawValue: kSecAttrIsNegative as String)
    static let syncViewHint        = SecItemAttrKey(rawValue: kSecAttrSyncViewHint as String)
    static let persistentReference = SecItemAttrKey(rawValue: kSecAttrPersistentReference as String)
    
    #if os(macOS)
    /// A key with a value that indicates access control list settings for the item.
    @available(macOS, unavailable, message: "Cannot be used when `useDataProtectionKeychain' is set to `true`")
    static let access = SecItemAttrKey(rawValue: kSecAttrAccess as String)
    #endif

    #if os(tvOS)
    @available(tvOS 16.0, *)
    static let useUserIndependentKeychain = SecItemAttrKey(rawValue: kSecUseUserIndependentKeychain as String)
    #endif
}

// MARK: - Password Attribute Keys

extension SecItemAttrKey {
    static let account             = SecItemAttrKey(rawValue: kSecAttrAccount as String)
    static let service             = SecItemAttrKey(rawValue: kSecAttrService as String)
    static let generic             = SecItemAttrKey(rawValue: kSecAttrGeneric as String)
    static let securityDomain      = SecItemAttrKey(rawValue: kSecAttrSecurityDomain as String)
    static let server              = SecItemAttrKey(rawValue: kSecAttrServer as String)
    static let protocolType        = SecItemAttrKey(rawValue: kSecAttrProtocol as String)
    static let authenticationType  = SecItemAttrKey(rawValue: kSecAttrAuthenticationType as String)
    static let port                = SecItemAttrKey(rawValue: kSecAttrPort as String)
    static let path                = SecItemAttrKey(rawValue: kSecAttrPath as String)
}

// MARK: - Certificate Attribute Keys

extension SecItemAttrKey {
    static let subject             = SecItemAttrKey(rawValue: kSecAttrSubject as String)
    static let issuer              = SecItemAttrKey(rawValue: kSecAttrIssuer as String)
    static let serialNumber        = SecItemAttrKey(rawValue: kSecAttrSerialNumber as String)
    static let subjectKeyID        = SecItemAttrKey(rawValue: kSecAttrSubjectKeyID as String)
    static let publicKeyHash       = SecItemAttrKey(rawValue: kSecAttrPublicKeyHash as String)
    static let certificateType     = SecItemAttrKey(rawValue: kSecAttrCertificateType as String)
    static let certificateEncoding = SecItemAttrKey(rawValue: kSecAttrCertificateEncoding as String)
}

// MARK: - Cryptographic Key Attribute Keys

extension SecItemAttrKey {
    static let keyClass            = SecItemAttrKey(rawValue: kSecAttrKeyClass as String)
    static let applicationLabel    = SecItemAttrKey(rawValue: kSecAttrApplicationLabel as String)
    static let applicationTag      = SecItemAttrKey(rawValue: kSecAttrApplicationTag as String)
    static let keyType             = SecItemAttrKey(rawValue: kSecAttrKeyType as String)
    static let keySizeInBits       = SecItemAttrKey(rawValue: kSecAttrKeySizeInBits as String)
    static let effectiveKeySize    = SecItemAttrKey(rawValue: kSecAttrEffectiveKeySize as String)
    static let tokenID             = SecItemAttrKey(rawValue: kSecAttrTokenID as String)
    
    #if os(macOS)
    static let prf                 = SecItemAttrKey(rawValue: kSecAttrPRF as String)
    static let salt                = SecItemAttrKey(rawValue: kSecAttrSalt as String)
    static let rounds              = SecItemAttrKey(rawValue: kSecAttrRounds as String)
    #endif
    
    // MARK: Usage
    
    static let isPermament         = SecItemAttrKey(rawValue: kSecAttrIsPermanent as String)
    static let isSensitive         = SecItemAttrKey(rawValue: kSecAttrIsSensitive as String)
    static let isExtractable       = SecItemAttrKey(rawValue: kSecAttrIsExtractable as String)
    static let canEncrypt          = SecItemAttrKey(rawValue: kSecAttrCanEncrypt as String)
    static let canDecrypt          = SecItemAttrKey(rawValue: kSecAttrCanDecrypt as String)
    static let canDerive           = SecItemAttrKey(rawValue: kSecAttrCanDerive as String)
    static let canSign             = SecItemAttrKey(rawValue: kSecAttrCanSign as String)
    static let canVerify           = SecItemAttrKey(rawValue: kSecAttrCanVerify as String)
    static let canWrap             = SecItemAttrKey(rawValue: kSecAttrCanWrap as String)
    static let canUnwrap           = SecItemAttrKey(rawValue: kSecAttrCanUnwrap as String)
}

extension SecItemAttrKey {
    static let `class`                   = SecItemAttrKey(rawValue: kSecClass as String)
    static let useDataProtectionKeychain = SecItemAttrKey(rawValue: kSecUseDataProtectionKeychain as String)
}

extension SecItemAttrKey {
    static let valueData          = SecItemAttrKey(rawValue: kSecValueData as String)
    static let valueRef           = SecItemAttrKey(rawValue: kSecValueRef as String)
    static let valuePersistentRef = SecItemAttrKey(rawValue: kSecValuePersistentRef as String)
}

extension SecItemAttrKey: CustomStringConvertible {
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
        case .valueData:
            return "Value (Data)"
        case .valueRef:
            return "Value (Reference)"
        case .valuePersistentRef:
            return "Value (Persistent Reference)"
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
