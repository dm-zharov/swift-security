//
//  KeyType.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

public enum KeyClass {
    case `public`
    case `private`
}

extension KeyClass: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyClassPublic):
            self = .public
        case String(kSecAttrKeyClassPrivate):
            self = .private
        case String(kSecAttrKeyClassSymmetric):
            assertionFailure("No longer supported by keychain")
            fallthrough
        default:
            return nil
        }
    }
    
    public var rawValue: String {
        switch self {
        case .public:
            return String(kSecAttrKeyClassPublic)
        case .private:
            return String(kSecAttrKeyClassPrivate)
        }
    }
        
    public var description: String {
        switch self {
        case .public:
            return "Public"
        case .private:
            return "Private"
        }
    }
}
