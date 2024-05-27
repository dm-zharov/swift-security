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
    /// Creates an identity from a reference.
    public init(identity secIdentity: SecIdentity) {
        self.secIdentity = secIdentity
    }
    
    /// An identity reference.
    public let secIdentity: SecIdentity
}

extension DigitalIdentity {
    /// Retrieves the certificate.
    public var certificate: Certificate {
        get throws {
            var secCertificate: SecCertificate?
            switch SecIdentityCopyCertificate(secIdentity, &secCertificate) {
            case errSecSuccess:
                guard let secCertificate else {
                    throw SwiftSecurityError.invalidParameter
                }

                return Certificate(certificate: secCertificate)
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
            switch SecIdentityCopyPrivateKey(secIdentity, &secKey) {
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
    init?(certificate: Certificate) throws {
        var secIdentity: SecIdentity?
        switch SecIdentityCreateWithCertificate(nil, certificate.secCertificate, &secIdentity) {
        case errSecSuccess:
            if let secIdentity {
                self.init(identity: secIdentity)
            } else {
                return nil
            }
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
}
#endif
