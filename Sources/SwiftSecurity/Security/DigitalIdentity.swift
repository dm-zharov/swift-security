//
//  DigitalIdentity.swift
//
//
//  Created by Dmitriy Zharov on 26.05.2024.
//

import Foundation
import Security

@available(*, renamed: "DigitalIdentity")
public typealias Identity = DigitalIdentity

public struct DigitalIdentity {
    /// Creates an identity from a raw representation.
    public init(rawRepresentation secIdentity: SecIdentity) {
        self.rawRepresentation = secIdentity
    }
    
    /// Creates an identity from a raw representation.
    public let rawRepresentation: SecIdentity
}

extension DigitalIdentity {
    /// Retrieves the certificate.
    public var certificate: Certificate {
        get throws {
            var secCertificate: SecCertificate?
            switch SecIdentityCopyCertificate(rawRepresentation, &secCertificate) {
            case errSecSuccess:
                guard let secCertificate else {
                    throw SwiftSecurityError.invalidParameter
                }

                return Certificate(rawRepresentation: secCertificate)
            case let status:
                throw SwiftSecurityError.underlyingSecurityError(error: status)
            }
        }
    }
    
    /// Retrieves the private key associated with the certificate.
    /// - Note: Exports SecKey type to an external representation suitable to key type.
    @available(macOS, unavailable, message: "Not implemented")
    public var privateKey: Data {
        get throws {
            var secKey: SecKey?
            switch SecIdentityCopyPrivateKey(rawRepresentation, &secKey) {
            case errSecSuccess:
                guard let secKey else {
                    throw SwiftSecurityError.invalidParameter
                }
                
                var error: Unmanaged<CFError>?
                guard let privateKey = SecKeyCopyExternalRepresentation(secKey, &error) as Data?, error == nil else {
                    if let error = error?.takeRetainedValue() {
                        throw SwiftSecurityError(error: error)
                    }
                    throw SwiftSecurityError.invalidParameter
                }

                return privateKey
            case let status:
                throw SwiftSecurityError.underlyingSecurityError(error: status)
            }
        }
    }
}

#if os(macOS)
extension DigitalIdentity {
    init?<T: SecCertificateConvertible>(certificate: T) throws {
        var secIdentity: SecIdentity?
        switch SecIdentityCreateWithCertificate(nil, certificate.rawRepresentation, &secIdentity) {
        case errSecSuccess:
            if let secIdentity {
                self.init(rawRepresentation: secIdentity)
            } else {
                return nil
            }
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
}
#endif
