//
//  KeyCipher.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

public enum KeyCipher {
    case rsa
    case ecsecPrimeRandom
    #if os(macOS)
    case dsa
    case aes
    case des
    case tdes // 3DES
    case rc4
    case rc2
    case cast
    #endif
}

extension KeyCipher: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyTypeRSA):
            self = .rsa
        case String(kSecAttrKeyTypeECSECPrimeRandom):
            self = .ecsecPrimeRandom
        #if os(macOS)
        case String(kSecAttrKeyTypeDSA):
            self = .dsa
        case String(kSecAttrKeyTypeAES):
            self = .aes
        case String(kSecAttrKeyTypeDES):
            self = .des
        case String(kSecAttrKeyType3DES):
            self = .tdes
        case String(kSecAttrKeyTypeRC4):
            self = .rc4
        case String(kSecAttrKeyTypeRC2):
            self = .rc2
        case String(kSecAttrKeyTypeCAST):
            self = .cast
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
        #if os(macOS)
        case .dsa:
            return String(kSecAttrKeyTypeDSA)
        case .aes:
            return String(kSecAttrKeyTypeAES)
        case .des:
            return String(kSecAttrKeyTypeDES)
        case .tdes:
            return String(kSecAttrKeyType3DES)
        case .rc4:
            return String(kSecAttrKeyTypeRC4)
        case .rc2:
            return String(kSecAttrKeyTypeRC2)
        case .cast:
            return String(kSecAttrKeyTypeCAST)
        #endif
        }
    }
    
    public var description: String {
        switch self {
        case .rsa:
            return "RSA"
        case .ecsecPrimeRandom:
            return "ECSECPrimeRandom"
        #if os(macOS)
        case .dsa:
            return "DSA"
        case .aes:
            return "AES"
        case .des:
            return "DES"
        case .tdes:
            return "3DES"
        case .rc4:
            return "RC4"
        case .rc2:
            return "RC2"
        case .cast:
            return "CAST"
        #endif
        }
    }
}
