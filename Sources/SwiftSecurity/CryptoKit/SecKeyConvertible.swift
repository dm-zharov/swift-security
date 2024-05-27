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
    
    /// An X9.63 representation of the key.
    var x963Representation: Data { get }
}

// MARK: - CryptoKit

/// NIST P-256 (also known as `secp256r1` /  `prime256r1` / `prime256v1`).

extension P256.Signing.PrivateKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P256.Signing.PublicKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

extension P256.KeyAgreement.PrivateKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P256.KeyAgreement.PublicKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

/// NIST P-384 (also known as `secp384r1` ).

extension P384.Signing.PrivateKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}

extension P384.Signing.PublicKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

extension P384.KeyAgreement.PrivateKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}

extension P384.KeyAgreement.PublicKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

/// NIST P-521 (also known as `secp521r1` ).

extension P521.Signing.PrivateKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P521.Signing.PublicKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

extension P521.KeyAgreement.PrivateKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPrivateKey }
}
extension P521.KeyAgreement.PublicKey: SecKeyConvertible {
    public var secKeyDescriptor: SecKeyDescriptor { .ecPublicKey }
}

// MARK: - SecKey

public protocol SecKeyRepresentable {
    /// A key descriptor for storage.
    var secKeyDescriptor: SecKeyDescriptor { get }
    
    /// A key reference.
    var secKey: SecKey { get throws }
}

extension SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            let keyData: Data
            switch secKeyDescriptor.keyType {
            case .ecsecPrimeRandom:
                keyData = x963Representation
            case .rsa:
                // override and use data in PKCS #1 format
                throw SwiftSecurityError.unimplemented
            }

            var error: Unmanaged<CFError>?
            guard let secKey: SecKey = SecKeyCreateWithData(keyData as CFData, [
                kSecAttrKeyType: secKeyDescriptor.keyType.rawValue,
                kSecAttrKeyClass: secKeyDescriptor.keyClass.rawValue
            ] as CFDictionary, &error) else {
                if let error = error?.takeRetainedValue() {
                    throw SwiftSecurityError(error: error)
                }
                throw SwiftSecurityError.invalidParameter
            }
            return secKey
        }
    }
}

public struct SecKeyDescriptor {
    public var keyType: KeyType
    public var keyClass: KeyClass
    
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
