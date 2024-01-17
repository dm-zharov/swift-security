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
    
    public init(accessGroup: String? = Bundle.main.bundleIdentifier) {
        self.attributes = [
            kSecAttrAccessGroup: accessGroup as Any,
            kSecUseDataProtectionKeychain: true, // This key affects only macOS.
        ] as [String: Any]
    }
}

// MARK: - Common

public extension SecItemQuery {
    var accessGroup: String? {
        get { attributes[kSecAttrAccessGroup as String] as? String }
        set { attributes[kSecAttrAccessGroup as String] = newValue }
    }
    var synchronizable: Bool? {
        get { attributes[kSecAttrSynchronizable as String] as? Bool }
        set { attributes[kSecAttrSynchronizable as String] = newValue }
    }
    
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
    
    var label: String? {
        get { attributes[kSecAttrLabel as String] as? String }
        set { attributes[kSecAttrLabel as String] = newValue }
    }
}

// MARK: - Password

public extension SecItemQuery where Value == GenericPassword {
    // MARK: - Primary
    
    var account: String? {
        get { attributes[kSecAttrAccount as String] as? String }
        set { attributes[kSecAttrAccount as String] = newValue }
    }
    var service: String? {
        get { attributes[kSecAttrService as String] as? String }
        set { attributes[kSecAttrService as String] = newValue }
    }
    
    // MARK: - User
    
    var generic: Data? {
        get { attributes[kSecAttrGeneric as String] as? Data }
        set { attributes[kSecAttrGeneric as String] = newValue }
    }
}

public extension SecItemQuery where Value == InternetPassword {
    // MARK: - Primary
    
    var account: String? {
        get { attributes[kSecAttrAccount as String] as? String }
        set { attributes[kSecAttrAccount as String] = newValue }
    }
    
    var authenticationType: String? {
        get { attributes[kSecAttrAuthenticationType as String] as? String }
        set { attributes[kSecAttrAuthenticationType as String] = newValue }
    }
    
    var path: String? {
        get { attributes[kSecAttrPath as String] as? String }
        set { attributes[kSecAttrPath as String] = newValue }
    }
    
    var port: String? {
        get { attributes[kSecAttrPort as String] as? String }
        set { attributes[kSecAttrPort as String] = newValue }
    }
    
    var `protocol`: String? {
        get { attributes[kSecAttrProtocol as String] as? String }
        set { attributes[kSecAttrProtocol as String] = newValue }
    }
    
    var securityDomain: String? {
        get { attributes[kSecAttrSecurityDomain as String] as? String }
        set { attributes[kSecAttrSecurityDomain as String] = newValue }
    }
    
    var server: String? {
        get { attributes[kSecAttrServer as String] as? String }
        set { attributes[kSecAttrServer as String] = newValue }
    }
}

extension SecItemQuery where Value: Password {
    // MARK: - User
    
    var description: String? {
        get { attributes[kSecAttrDescription as String] as? String }
        set { attributes[kSecAttrDescription as String] = newValue }
    }
    var comment: String? {
        get { attributes[kSecAttrDescription as String] as? String }
        set { attributes[kSecAttrDescription as String] = newValue }
    }
    var creator: String? {
        get { attributes[kSecAttrDescription as String] as? String }
        set { attributes[kSecAttrDescription as String] = newValue }
    }
    var type: String? {
        get { attributes[kSecAttrType as String] as? String }
        set { attributes[kSecAttrType as String] = newValue }
    }
    var isInvisible: String? {
        get { attributes[kSecAttrIsInvisible as String] as? String }
        set { attributes[kSecAttrIsInvisible as String] = newValue }
    }
    var isNegative: String? {
        get { attributes[kSecAttrIsNegative as String] as? String }
        set { attributes[kSecAttrIsNegative as String] = newValue }
    }
}

// MARK: - Sec Key

public extension SecItemQuery where Value == SecKey {
    // MARK: - Primary
    
    var applicationLabel: String? {
        get { attributes[kSecAttrApplicationLabel as String] as? String }
        set { attributes[kSecAttrApplicationLabel as String] = newValue }
    }

    var applicationTag: String? {
        get { attributes[kSecAttrApplicationTag as String] as? String }
        set { attributes[kSecAttrApplicationTag as String] = newValue }
    }
    
    var keyClass: String? {
        get { attributes[kSecAttrKeyClass as String] as? String }
        set { attributes[kSecAttrKeyClass as String] = newValue }
    }

    var keyType: String? {
        get { attributes[kSecAttrKeyType as String] as? String }
        set { attributes[kSecAttrKeyType as String] = newValue }
    }

    var keySizeInBits: String? {
        get { attributes[kSecAttrKeySizeInBits as String] as? String }
        set { attributes[kSecAttrKeySizeInBits as String] = newValue }
    }

    var effectiveKeySize: String? {
        get { attributes[kSecAttrEffectiveKeySize as String] as? String }
        set { attributes[kSecAttrEffectiveKeySize as String] = newValue }
    }
    
    // MARK: - Security
    
    var isPermament: String? {
        get { attributes[kSecAttrIsPermanent as String] as? String }
        set { attributes[kSecAttrIsPermanent as String] = newValue }
    }
    
    var canEncrypt: Bool? {
        get { attributes[kSecAttrCanEncrypt as String] as? Bool }
        set { attributes[kSecAttrCanEncrypt as String] = newValue }
    }
    
    var canDecrypt: Bool? {
        get { attributes[kSecAttrCanDecrypt as String] as? Bool }
        set { attributes[kSecAttrCanDecrypt as String] = newValue }
    }
    
    var canDerive: Bool? {
        get { attributes[kSecAttrCanDerive as String] as? Bool }
        set { attributes[kSecAttrCanDerive as String] = newValue }
    }
    
    var canSign: Bool? {
        get { attributes[kSecAttrCanSign as String] as? Bool }
        set { attributes[kSecAttrCanSign as String] = newValue }
    }
    
    var canVerify: Bool? {
        get { attributes[kSecAttrCanVerify as String] as? Bool }
        set { attributes[kSecAttrCanVerify as String] = newValue }
    }
    
    var canWrap: Bool? {
        get { attributes[kSecAttrCanWrap as String] as? Bool }
        set { attributes[kSecAttrCanWrap as String] = newValue }
    }
    
    var canUnwrap: Bool? {
        get { attributes[kSecAttrCanUnwrap as String] as? Bool }
        set { attributes[kSecAttrCanUnwrap as String] = newValue }
    }
}

#if os(macOS)
public extension SecItemQuery where Value == SecKey {
    var prf: String? {
        get { attributes[kSecAttrPRF as String] as? String }
        set { attributes[kSecAttrPRF as String] = newValue }
    }

    var salt: Data? {
        get { attributes[kSecAttrSalt as String] as? Data }
        set { attributes[kSecAttrSalt as String] = newValue }
    }

    var rounds: Int? {
        get {
            if let number = attributes[kSecAttrSalt as String] as? NSNumber {
                return number.intValue
            } else {
                return nil
            }
        }
        set {
            if let newValue {
                attributes[kSecAttrSalt as String] = NSNumber(integerLiteral: newValue)
            } else {
                attributes[kSecAttrSalt as String] = nil
            }
        }
    }
}
#endif
