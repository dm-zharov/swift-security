//
//  SecKeyConvertible.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import CryptoKit

// MARK: - NIST Key

public protocol SecKeyConvertible: SecKeyRepresentable {
    /// Creates a key from an X9.63 representation.
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    
    /// Creates a key from a Distinguished Encoding Rules (DER) encoded representation.
    init<Bytes>(derRepresentation: Bytes) throws where Bytes : RandomAccessCollection, Bytes.Element == UInt8
    
    /// An X9.63 representation of the key.
    var x963Representation: Data { get }
    
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
    var derRepresentation: Data { get }
}

// MARK: - CryptoKit

/// NIST P-256 (also known as `secp256r1` /  `prime256r1` / `prime256v1`).

extension P256.Signing.PrivateKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P256.Signing.PublicKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

extension P256.KeyAgreement.PrivateKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P256.KeyAgreement.PublicKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

/// NIST P-384 (also known as `secp384r1` ).

extension P384.Signing.PrivateKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}

extension P384.Signing.PublicKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

extension P384.KeyAgreement.PrivateKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}

extension P384.KeyAgreement.PublicKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

/// NIST P-521 (also known as `secp521r1` ).

extension P521.Signing.PrivateKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P521.Signing.PublicKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

extension P521.KeyAgreement.PrivateKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P521.KeyAgreement.PublicKey: SecKeyConvertible {
    public static var keyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

// MARK: - SecKey

public protocol SecKeyRepresentable {
    /// A key descriptor for storage.
    static var keyDescriptor: SecKeyDescriptor { get }
    
    /// A key reference.
    var secKey: SecKey { get throws }
}

extension SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            let keyData: Data
            switch keyType {
            case .ecsecPrimeRandom:
                // X9.63
                keyData = x963Representation
            case .rsa:
                // PCKS #1, DER-Encoded
                keyData = derRepresentation
            }

            var error: Unmanaged<CFError>?
            guard let secKey: SecKey = SecKeyCreateWithData(keyData as CFData, [
                kSecAttrKeyType: keyType.rawValue,
                kSecAttrKeyClass: keyClass.rawValue
            ] as CFDictionary, &error) else {
                if let error = error?.takeRetainedValue() {
                    throw SwiftSecurityError(error: error)
                }
                throw SwiftSecurityError.invalidParameter
            }
            return secKey
        }
    }
    
    /// The type of the key.
    public var keyType: KeyType {
        Self.keyDescriptor.keyType
    }
    
    /// The role of the key.
    public var keyClass: KeyClass {
        Self.keyDescriptor.keyClass
    }
}

public struct SecKeyDescriptor: Sendable {
    public let keyType: KeyType
    public let keyClass: KeyClass
    
    /// A private key for elliptic curve cryptography. Suitable for `P256`/`P384`/`P521` keys from `CryptoKit`.
    public static let ecPrivateKey = SecKeyDescriptor(keyType: .ecsecPrimeRandom, keyClass: .private)
    /// A public key for elliptic curve cryptography. Suitable for `P256`/`P384`/`P521` keys from `CryptoKit`.
    public static let ecPublicKey = SecKeyDescriptor(keyType: .ecsecPrimeRandom, keyClass: .public)
    
    /// A private key for `RSA` cryptography.
    public static let rsaPrivateKey = SecKeyDescriptor(keyType: .rsa, keyClass: .private)
    /// A public key for `RSA` cryptography.
    public static let rsaPublicKey = SecKeyDescriptor(keyType: .rsa, keyClass: .public)
    
    /// A descriptor that defines the properties of the key.
    public init(keyType: KeyType, keyClass: KeyClass) {
        self.keyType = keyType
        self.keyClass = keyClass
    }
}
