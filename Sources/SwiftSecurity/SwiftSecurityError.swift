//
//  SwiftSecurityError.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

/**
 General security errors returned by SwiftSecurity.
 */
public enum SwiftSecurityError: Error {
    /// Required entitlement isn't present.
    /// - Note: Check the ``AccessGroup`` for documentation.
    /// - SeeAlso: [Required entitlement is missing.](https://developer.apple.com/documentation/security/errsecmissingentitlement)
    case missingEntitlement
    
    /// No keychain is available. You may need to restart your device.
    case notAvailable
    
    /// The item already exists.
    case duplicateItem
    
    /// The parameter is invalid.
    case invalidParameter
    
    /// Authorization/Authentication failed.
    case authFailed
    
    /// User interaction is required.
    case interactionRequired

    /// User interaction is not allowed.
    case interactionNotAllowed
    
    /// User canceled the operation.
    case userCanceled
    
    /// The key size is not allowed.
    case keySizeNotAllowed

    /// The data is not available.
    case dataNotAvailable
    
    /// MAC verification failed during PKCS12 Import (wrong password?).
    case pkcs12VerifyFailure
    
    /// Function or operation not implemented.
    case unimplemented
    
    /// The underlying Security framework is unable to complete the requested action.
    /// - SeeAlso: [Security Framework Result Codes](https://developer.apple.com/documentation/security/1542001-security_framework_result_codes)
    case underlyingSecurityError(error: Int32)
}

extension SwiftSecurityError {
    public init(rawValue: Int32) {
        switch rawValue {
        case errSecMissingEntitlement: self = .missingEntitlement
        case errSecNotAvailable: self = .notAvailable
        case errSecDuplicateItem: self = .duplicateItem
        case errSecParam: self = .invalidParameter
        case errSecAuthFailed: self = .authFailed
        case errSecInteractionRequired: self = .interactionRequired
        case errSecInteractionNotAllowed: self = .interactionNotAllowed
        case errSecUserCanceled: self = .userCanceled
        case errSecKeySizeNotAllowed: self = .keySizeNotAllowed
        case errSecDataNotAvailable: self = .dataNotAvailable
        case errSecPkcs12VerifyFailure: self = .pkcs12VerifyFailure
        case errSecUnimplemented: self = .unimplemented
        default:
            self = .underlyingSecurityError(error: rawValue)
        }
    }
    
    init(error: CFError?) {
        if let error {
            self.init(rawValue: Int32(CFErrorGetCode(error)))
        } else {
            self = .invalidParameter
        }
    }
}

extension SwiftSecurityError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingEntitlement:
            return SecCopyErrorMessageString(errSecMissingEntitlement, nil) as String?
        case .notAvailable:
            return SecCopyErrorMessageString(errSecNotAvailable, nil) as String?
        case .duplicateItem:
            return SecCopyErrorMessageString(errSecDuplicateItem, nil) as String?
        case .invalidParameter:
            return SecCopyErrorMessageString(errSecParam, nil) as String?
        case .authFailed:
            return SecCopyErrorMessageString(errSecAuthFailed, nil) as String?
        case .interactionRequired:
            return SecCopyErrorMessageString(errSecInteractionRequired, nil) as String?
        case .interactionNotAllowed:
            return SecCopyErrorMessageString(errSecInteractionNotAllowed, nil) as String?
        case .userCanceled:
            return SecCopyErrorMessageString(errSecUserCanceled, nil) as String?
        case .keySizeNotAllowed:
            return SecCopyErrorMessageString(errSecKeySizeNotAllowed, nil) as String?
        case .dataNotAvailable:
            return SecCopyErrorMessageString(errSecDataNotAvailable, nil) as String?
        case .pkcs12VerifyFailure:
            return SecCopyErrorMessageString(errSecPkcs12VerifyFailure, nil) as String?
        case .unimplemented:
            return SecCopyErrorMessageString(errSecUnimplemented, nil) as String?
        case .underlyingSecurityError(let error):
            return SecCopyErrorMessageString(error, nil) as String?
        }
    }
}
