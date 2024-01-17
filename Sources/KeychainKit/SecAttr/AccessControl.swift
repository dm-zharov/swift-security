//
//  AccessControl.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation

public struct AccessControl: RawRepresentable {
    public let rawValue: SecAccessControl
    
    public init?(rawValue: SecAccessControl) {
        self.rawValue = rawValue
    }
}
