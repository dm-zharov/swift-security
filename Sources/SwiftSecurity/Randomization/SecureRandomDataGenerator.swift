//
//  SecureRandomDataGenerator.swift
//  
//
//  Created by Dmitriy Zharov on 29.04.2024.
//

import Security

public protocol RandomDataGenerator {

    /// Returns a value from a uniform, independent distribution of binary data.
    ///
    /// Use this method when you need random binary data to generate another value.
    ///
    /// - Returns: Random data.
    mutating func next() throws -> Data
}

/// Generates a data with cryptographically secure random bytes.
public struct SecureRandomDataGenerator: RandomDataGenerator {
    /// The number of random bytes to return in the array pointed to by the bytes parameter.
    public let count: Int
    
    /// Generates a data with cryptographically secure random bytes.
    /// - Parameter count: The number of random bytes to return in the array pointed to by the bytes parameter.
    public init(count: Int) {
        self.count = count
    }
}

extension SecureRandomDataGenerator: RandomDataGenerator {
    public func next() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        switch SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) {
        case errSecSuccess:
            return Data(bytes)
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
}
