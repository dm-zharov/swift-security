//
//  SecIdentityConvertible.swift
//
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

public protocol SecIdentityConvertible {
    /// Creates an identity from a raw representation.
    init(rawRepresentation: SecIdentity)
    
    /// A raw representation of the identity.
    var rawRepresentation: SecIdentity { get throws }
}

public struct Identity: SecIdentityConvertible {
    /// Creates an identity from a raw representation.
    public init(rawRepresentation identityRef: SecIdentity) {
        self.rawRepresentation = identityRef
    }
    
    /// Creates an identity from a raw representation.
    public let rawRepresentation: SecIdentity
}

#if os(macOS)
import Security

extension Identity {
    public init?<T: SecCertificateConvertible>(certificate: T) {
        var identityRef: SecIdentity?
        SecIdentityCreateWithCertificate(nil, certificate.rawRepresentation, &identityRef)
        if let identityRef {
            self.rawRepresentation = identityRef
        } else {
            return nil
        }
    }
}
#endif
