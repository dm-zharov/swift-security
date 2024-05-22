//
//  SecCertificateConvertible.swift
//  
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

// MARK: - DER-Encoded X.509 Certificate

public protocol SecCertificateConvertible {
    /// Creates a certificate from an DER-encoded X.509 data representation.
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: ContiguousBytes
    
    /// An DER-Encoded X.509 data representation.
    var derRepresentation: Data { get }
}

#if canImport(X509)
import X509
import SwiftASN1

extension Certificate: SecCertificateConvertible {
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
            assertionFailure(error.localizedDescription)
            return Data()
        }
    }
}
#endif
