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

extension P256.Signing.PrivateKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.private) }
}

extension P256.Signing.PublicKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.public) }
}

extension P256.KeyAgreement.PrivateKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.private) }
}

extension P256.KeyAgreement.PublicKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.public) }
}

extension P384.Signing.PrivateKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.private) }
}

extension P384.Signing.PublicKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.public) }
}

extension P384.KeyAgreement.PrivateKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.private) }
}

extension P384.KeyAgreement.PublicKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.public) }
}

extension P521.Signing.PrivateKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.private) }
}

extension P521.Signing.PublicKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.public) }
}

extension P521.KeyAgreement.PrivateKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.private) }
}

extension P521.KeyAgreement.PublicKey: SecKeyConvertible {
    public var descriptor: SecKeyDescriptor { .ecsecPrimeRandom(.public) }
}

// MARK: - SecKey

public protocol SecKeyRepresentable {
    /// A key descriptor for storage.
    var descriptor: SecKeyDescriptor { get }
    
    /// A key reference.
    var secKey: SecKey { get throws }
}

extension SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            guard descriptor.keyType == .ecsecPrimeRandom else {
                // RSA use is discouraged. If necessary, override and use ASN.1 format as external representation
                throw SwiftSecurityError.unimplemented
            }
            var error: Unmanaged<CFError>?
            guard let secKey: SecKey = SecKeyCreateWithData(x963Representation as CFData, [
                kSecAttrKeyType: descriptor.keyType.rawValue,
                kSecAttrKeyClass: descriptor.keyClass.rawValue
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
    
    public static func rsa(_ keyClass: KeyClass) -> SecKeyDescriptor {
        switch keyClass {
        case .public:
            SecKeyDescriptor(keyType: .rsa, keyClass: .public)
        case .private:
            SecKeyDescriptor(keyType: .rsa, keyClass: .private)
        }
    }
    
    public static func ecsecPrimeRandom(_ keyClass: KeyClass) -> SecKeyDescriptor {
        switch keyClass {
        case .public:
            SecKeyDescriptor(keyType: .ecsecPrimeRandom, keyClass: .public)
        case .private:
            SecKeyDescriptor(keyType: .ecsecPrimeRandom, keyClass: .private)
        }
    }
}
