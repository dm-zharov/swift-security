//
//  SecValueType.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

enum SecValueType {
    case data
    case reference
    case persistentReference
}

extension SecValueType: RawRepresentable, CustomStringConvertible {
    init?(rawValue: String) {
        switch rawValue {
        case String(kSecValueData):
            self = .data
        case String(kSecValueRef):
            self = .reference
        case String(kSecValuePersistentRef):
            self = .persistentReference
        default:
            return nil
        }
    }
    
    var rawValue: String {
        switch self {
        case .data:
            return String(kSecValueData)
        case .reference:
            return String(kSecValueRef)
        case .persistentReference:
            return String(kSecValuePersistentRef)
        }
    }
    
    var description: String {
        switch self {
        case .data:
            return "Data"
        case .reference:
            return "Reference"
        case .persistentReference:
            return "Persistent Reference"
        }
    }
}
