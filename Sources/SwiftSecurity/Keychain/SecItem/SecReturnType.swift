//
//  SecReturnType.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

public struct SecReturnType: OptionSet {
    public static let data                 = SecReturnType(rawValue: 1 << 0)
    public static let info                 = SecReturnType(rawValue: 1 << 1)
    public static let reference            = SecReturnType(rawValue: 1 << 2)
    public static let persistentReference  = SecReturnType(rawValue: 1 << 3)
    
    public var rawValue: UInt
    
    public init(rawValue: UInt) {
        self.rawValue = rawValue
    }
}
