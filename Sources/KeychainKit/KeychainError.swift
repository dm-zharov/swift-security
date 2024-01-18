//
//  KeychainError.swift
//  
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

enum KeychainError: Error {
    case failedToWriteItem(description: String)
    case failedToReadItem(description: String)
    case failedToRemoveItem(description: String)
    case failedAccessControlCreation(description: String)
    case failedSecKeyConversion
    case missingSecKeyRepresentation
}

extension KeychainError: LocalizedError {
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
        case .failedSecKeyConversion:
            return "Couldn't convert SecKey."
        case .missingSecKeyRepresentation:
            return "Missing SecKey representation."
        }
    }
}
