//
//  SecReturnType.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

enum SecReturnType {
    case data
    case attributes
    case reference
    case persistentReference
}

extension SecReturnType: RawRepresentable {
    init?(rawValue: String) {
        switch rawValue {
        case String(kSecReturnData):
            self = .data
        case String(kSecReturnAttributes):
            self = .attributes
        case String(kSecReturnRef):
            self = .reference
        case String(kSecReturnPersistentRef):
            self = .persistentReference
        default:
            return nil
        }
    }
    
    var rawValue: String {
        switch self {
        case .data:
            return String(kSecReturnData)
        case .attributes:
            return String(kSecReturnAttributes)
        case .reference:
            return String(kSecReturnRef)
        case .persistentReference:
            return String(kSecReturnPersistentRef)
        }
    }
}
