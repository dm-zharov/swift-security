//
//  GenericPasswordConvertible.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import CryptoKit

// MARK: - Other Key Types

protocol GenericPasswordConvertible {
    /// Creates a key from a raw representation.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
    
    /// A raw representation of the key.
    var rawRepresentation: Data { get }
}

extension Curve25519.KeyAgreement.PrivateKey: GenericPasswordConvertible {}
extension Curve25519.Signing.PrivateKey: GenericPasswordConvertible {}

// Secure Enclave does not allow exporting private keys in any form.
// Data representation is a "pointer" for Secure Enclave, not the key itself.
// That pointer is valid only for the current device and application that generated the key.
// Considering the above information, it's safe to store pointer in the keychain.
extension SecureEnclave.P256.KeyAgreement.PrivateKey: GenericPasswordConvertible {
    init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        try self.init(dataRepresentation: data.withUnsafeBytes { Data($0) })
    }
    
    var rawRepresentation: Data {
        dataRepresentation
    }
}

// MARK: - Other Data Types

extension Data: GenericPasswordConvertible {
    init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        self = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let contiguousBytes = bytes.bindMemory(to: UInt8.self)
            return Data(contiguousBytes)
        }
    }
    
    var rawRepresentation: Data {
        self
    }
}

extension AES.GCM.SealedBox: GenericPasswordConvertible {
    init<D>(rawRepresentation data: D) throws where D : ContiguousBytes {
        try self.init(combined: data.withUnsafeBytes { Data($0) })
    }
    
    var rawRepresentation: Data {
        combined!
    }
}
