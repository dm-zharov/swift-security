//
//  SwiftSecurityError.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

/**
 - SeeAlso: [Security Framework Result Codes](https://developer.apple.com/documentation/security/1542001-security_framework_result_codes)
 */
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
