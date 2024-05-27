//
//  SecCertificateConvertible.swift
//  
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation
import Security

// MARK: - DER-Encoded X.509 Certificate

public protocol SecCertificateConvertible: SecCertificateRepresentable {
    /// Creates a certificate from an DER-encoded X.509 data representation.
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: ContiguousBytes
    
    /// A DER-Encoded X.509 data representation.
    var derRepresentation: Data { get }
}

extension SwiftSecurity.Certificate: SecCertificateConvertible { }

#if canImport(X509)
import X509
import SwiftASN1

extension X509.Certificate: SecCertificateConvertible {
    public init<D>(derRepresentation data: D) throws where D: ContiguousBytes {
        try self.init(derEncoded: data.withUnsafeBytes { bytes in
            let contiguousBytes = bytes.bindMemory(to: UInt8.self)
            return Array(contiguousBytes)
        })
    }

    public var derRepresentation: Data {
        var serializer = DER.Serializer()
        do {
            try serialize(into: &serializer)
            return Data(serializer.serializedBytes)
        } catch {
            preconditionFailure(error.localizedDescription)
            return Data()
        }
    }
}
#endif

// MARK: - SecCertificate

public protocol SecCertificateRepresentable {
    /// Creates a certificate from a reference.
    init(certificate secCertificate: SecCertificate)
    
    /// A certificate reference.
    var secCertificate: SecCertificate { get }
}

extension SecCertificateConvertible {
    public init(certificate secCertificate: SecCertificate) {
        do {
            try self.init(derRepresentation: SecCertificateCopyData(secCertificate) as Data)
        } catch{
            fatalError(error.localizedDescription)
        }
    }

    public var secCertificate: SecCertificate {
        if let secCertificate = SecCertificateCreateWithData(nil, derRepresentation as CFData) {
            return secCertificate
        } else {
            fatalError("derRepresentation is not a valid DER-encoded data")
        }
    }
}
