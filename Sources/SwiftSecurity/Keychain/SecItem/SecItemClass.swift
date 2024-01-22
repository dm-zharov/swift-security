//
//  SecItemClass.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation

public enum SecItemClass: CaseIterable {
    case genericPassword
    case internetPassword
    case key
    case certificate
    case identity
}

extension SecItemClass: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecClassGenericPassword):
            self = .genericPassword
        case String(kSecClassInternetPassword):
            self = .internetPassword
        case String(kSecClassKey):
            self = .key
        case String(kSecClassCertificate):
            self = .certificate
        case String(kSecClassIdentity):
            self = .identity
        default:
            return nil
        }
    }
    
    public var rawValue: String {
        switch self {
        case .genericPassword:
            return String(kSecClassGenericPassword)
        case .internetPassword:
            return String(kSecClassInternetPassword)
        case .key:
            return String(kSecClassKey)
        case .certificate:
            return String(kSecClassCertificate)
        case .identity:
            return String(kSecClassIdentity)
        }
    }
    
    public var description: String {
        switch self {
        case .genericPassword:
            return "GenericPassword"
        case .internetPassword:
            return "InternetPassword"
        case .key:
            return "Key"
        case .certificate:
            return "Certificate"
        case .identity:
            return "Identity"
        }
    }
}
