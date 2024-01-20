//
//  SecIdentityConvertible.swift
//
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

// MARK: - PKCS #12 Certificate

public protocol SecIdentityConvertible {
    /// Creates a certificate from an PKCS #12 blob representation.
    init<Bytes>(pkcs12Representation: Bytes) throws where Bytes: ContiguousBytes
    
    /// An PKCS #12 blob representation.
    var pkcs12Representation: Data { get }
}

extension PKCS12.Blob: SecIdentityConvertible {
    public init<Bytes>(pkcs12Representation data: Bytes) throws where Bytes : ContiguousBytes {
        self.init(
            rawValue: try Data(rawRepresentation: data)
        )
    }
    
    public var pkcs12Representation: Data {
        rawValue
    }
}
