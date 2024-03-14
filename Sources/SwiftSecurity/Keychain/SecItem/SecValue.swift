//
//  SecValue.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

enum SecValue {
    case data(Data)
    case reference(AnyObject)
    case persistentReference(Data)
}

extension SecValue: CustomStringConvertible {
    var description: String {
        switch self {
        case .data(let data):
            return "Data: \(data)"
        case .reference:
            return "Reference"
        case .persistentReference(let data):
            return "Persistent Reference: \(data)"
        }
    }
}
