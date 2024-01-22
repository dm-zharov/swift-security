//
//  SwiftSecurityError.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

public struct SwiftSecurityError: RawRepresentable, Error {
    public var rawValue: OSStatus
    
    public init(rawValue: OSStatus) {
        self.rawValue = rawValue
    }
}

extension SwiftSecurityError: CustomStringConvertible {
    public var description: String {
        errorDescription ?? rawValue.description
    }
}

extension SwiftSecurityError: LocalizedError {
    public var errorDescription: String? {
        SecCopyErrorMessageString(rawValue, nil) as String?
    }
}
