//
//  SecValue.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

public enum SecValue<Value> where Value: SecItem {
    /// Item's data.
    case data(Data)
    
    /// Item attributes.
    case info(SecItemInfo<Value>)

    /// Reference to the item.
    ///
    /// The corresponding value, depending on the item class requested, is of type `SecKey`, `SecCertificate`, `SecIdentity`,  or`Data`.
    case reference(AnyObject)

    /// Persistent reference to the item.
    ///
    /// The bytes in this object can be stored by the caller and used on a subsequent invocation of the application (or even a different application)
    /// to retrieve the item referenced by it.
    case persistentReference(Data)
}

extension SecValue: CustomStringConvertible {
    public var description: String {
        switch self {
        case .data(let data):
            return "Data: \(data)"
        case .info(let info):
            return "Info: \(info)"
        case .reference:
            return "Reference"
        case .persistentReference(let data):
            return "Persistent Reference: \(data)"
        }
    }
}
