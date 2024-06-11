//
//  KeyAlgorithmType.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

@available(*, renamed: "KeyType")
public typealias KeyCipher = KeyType

public enum KeyType: Sendable {
    /// RSA.
    case rsa
    /// Elliptic curve. Suitable for `P256`, `P384`, `P521` keys from `CryptoKit`.
    case ecsecPrimeRandom
}

extension KeyType: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyTypeRSA):
            self = .rsa
        case String(kSecAttrKeyTypeECSECPrimeRandom):
            self = .ecsecPrimeRandom
        #if os(macOS)
        case String(kSecAttrKeyTypeDSA), String(kSecAttrKeyTypeAES), String(kSecAttrKeyType3DES),
             String(kSecAttrKeyTypeRC4), String(kSecAttrKeyTypeRC2), String(kSecAttrKeyTypeCAST):
            assertionFailure("No longer supported by keychain")
            fallthrough
        #endif
        default:
            return nil
        }
    }
    
    public var rawValue: String {
        switch self {
        case .rsa:
            return String(kSecAttrKeyTypeRSA)
        case .ecsecPrimeRandom:
            return String(kSecAttrKeyTypeECSECPrimeRandom)
        }
    }
    
    public var description: String {
        switch self {
        case .rsa:
            return "RSA"
        case .ecsecPrimeRandom:
            return "ECSECPrimeRandom"
        }
    }
}
