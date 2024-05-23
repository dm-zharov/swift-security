//
//  SecDataConvertible.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import CryptoKit

public protocol SecDataConvertible {
    /// Creates a secure data from a raw representation.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
    
    /// A raw representation of the secure data.
    var rawRepresentation: Data { get }
}

// MARK: - CryptoKit

extension Curve25519.KeyAgreement.PrivateKey: SecDataConvertible {}
extension Curve25519.Signing.PrivateKey: SecDataConvertible {}

extension SymmetricKey: SecDataConvertible {
    public init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        self.init(data: data)
    }
    
    public var rawRepresentation: Data {
        return withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let contiguousBytes = bytes.bindMemory(to: UInt8.self)
            return Data(contiguousBytes)
        }
    }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecDataConvertible {
    public init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        try self.init(dataRepresentation: data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let contiguousBytes = bytes.bindMemory(to: UInt8.self)
            return Data(contiguousBytes)
        })
    }
    
    public var rawRepresentation: Data {
        dataRepresentation
    }
}

extension SecureEnclave.P256.Signing.PrivateKey: SecDataConvertible {
   public init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        try self.init(dataRepresentation: data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let contiguousBytes = bytes.bindMemory(to: UInt8.self)
            return Data(contiguousBytes)
        })
    }
    
    public var rawRepresentation: Data {
        return dataRepresentation
    }
}

// MARK: - Other Data Types

extension Data: SecDataConvertible {
    public init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        self = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let contiguousBytes = bytes.bindMemory(to: UInt8.self)
            return Data(contiguousBytes)
        }
    }
    
    public var rawRepresentation: Data {
        self
    }
}

extension String: SecDataConvertible {
    public init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        if let value = String(data: try Data(rawRepresentation: data), encoding: .utf8) {
            self = value
        } else {
            throw SwiftSecurityError.invalidParameter
        }
    }
    
    public var rawRepresentation: Data {
        data(using: .utf8) ?? Data()
    }
}
