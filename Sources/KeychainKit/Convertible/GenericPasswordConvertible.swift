//
//  GenericPasswordConvertible.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import CryptoKit

// MARK: - Other Key Types

public protocol GenericPasswordConvertible {
    /// Creates a key from a raw representation.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
    
    /// A raw representation of the key.
    var rawRepresentation: Data { get }
}

// MARK: - CryptoKit

extension Curve25519.KeyAgreement.PrivateKey: GenericPasswordConvertible {}
extension Curve25519.Signing.PrivateKey: GenericPasswordConvertible {}

extension SymmetricKey: GenericPasswordConvertible {
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

// MARK: - Other Data Types

extension Data: GenericPasswordConvertible {
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

extension String: GenericPasswordConvertible {
    public init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        if let value = String(data: try Data(rawRepresentation: data), encoding: .utf8) {
            self = value
        } else {
            throw KeychainError.failedSecKeyConversion
        }
    }
    
    public var rawRepresentation: Data {
        data(using: .utf8) ?? Data()
    }
}
