//
//  SwiftSecurityError.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

enum SwiftSecurityError: Error {
    case failedToWriteItem(description: String)
    case failedToReadItem(description: String)
    case failedToRemoveItem(description: String)
    case failedAccessControlCreation(description: String)
    case failedPasswordConversion
    case failedSecKeyConversion
    case failedSecCertificateConversion(description: String)
    case missingSecKeyRepresentation
}

extension SwiftSecurityError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .failedToWriteItem(let description):
            return "The write operation failed. \(description)"
        case .failedToReadItem(let description):
            return "The read operation failed. \(description)"
        case .failedToRemoveItem(let description):
            return "The removal operaton failed. \(description)"
        case .failedAccessControlCreation(let description):
            return "Couldn't create SecAccessControl. \(description)"
        case .failedPasswordConversion:
            return "Couldn't convert password."
        case .failedSecKeyConversion:
            return "Couldn't convert key."
        case .failedSecCertificateConversion:
            return "Couldn't convert certificate"
        case .missingSecKeyRepresentation:
            return "Missing SecKey representation."
        }
    }
}
