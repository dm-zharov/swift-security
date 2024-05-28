//
//  SecReturnType.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

public struct SecReturnType: OptionSet {
    /// Returns a data of an item.
    public static let data                 = SecReturnType(rawValue: 1 << 0)
    /// Returns an attributes of an item.
    public static let info                 = SecReturnType(rawValue: 1 << 1)
    /// Returns a reference to an item.
    /// - Note: `SecKey`,  `SecCertificate`, `SecIdentity`.
    public static let reference            = SecReturnType(rawValue: 1 << 2)
    /// Returns a persistent reference to an item.
    public static let persistentReference  = SecReturnType(rawValue: 1 << 3)
    
    /// Returns everything for an item.
    public static let all: SecReturnType = [.data, .info, .reference, .persistentReference]
    
    public var rawValue: UInt
    
    public init(rawValue: UInt) {
        self.rawValue = rawValue
    }
}
