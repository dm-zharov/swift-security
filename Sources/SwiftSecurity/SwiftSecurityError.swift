//
//  SwiftSecurityError.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

/**
 Security Error.
 */
public struct SwiftSecurityError: CustomStringConvertible, Error {
    /// Security Error Code.
    /// - SeeAlso: [Security Framework Result Codes](https://developer.apple.com/documentation/security/1542001-security_framework_result_codes)
    public let code: OSStatus
    /// Security Error Description.
    public let description: String
    
    private init(code: OSStatus, description: String?) {
        self.code = code
        self.description = description ?? code.description
    }
}

extension SwiftSecurityError {
    public init(error: CFError) {
        self.init(
            code: OSStatus(CFErrorGetCode(error)),
            description: CFErrorCopyDescription(error) as String?
        )
    }
}

extension SwiftSecurityError: RawRepresentable {
    public var rawValue: OSStatus {
        code
    }
    
    public init(rawValue: OSStatus) {
        self.init(
            code: rawValue,
            description: SecCopyErrorMessageString(rawValue, nil) as String?
        )
    }
}

extension SwiftSecurityError: LocalizedError {
    public var errorDescription: String? {
        description
    }
}
