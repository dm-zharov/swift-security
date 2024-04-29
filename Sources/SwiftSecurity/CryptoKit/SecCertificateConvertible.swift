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

extension X509.DER.Data: SecCertificateConvertible {
    public init<Bytes>(derRepresentation data: Bytes) throws where Bytes : ContiguousBytes {
        self.init(
            rawValue: try Data(rawRepresentation: data)
        )
    }
    
    public var derRepresentation: Data {
        rawValue
    }
}
