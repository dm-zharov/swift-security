//
//  Certificate.swift
//
//
//  Created by Dmitriy Zharov on 26.05.2024.
//

import Foundation

public struct Certificate {
    public let derRepresentation: Data
    /// The certificate reference.
    public let secCertificate: SecCertificate
    
    public init<Bytes>(derRepresentation data: Bytes) throws where Bytes : ContiguousBytes {
        let derRepresentation = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            return Data(bytes)
        }
        guard let secCertificate = SecCertificateCreateWithData(nil, derRepresentation as CFData) else {
            throw SwiftSecurityError.invalidParameter
        }
        self.derRepresentation = derRepresentation
        self.secCertificate = secCertificate
    }

    public init(certificate secCertificate: SecCertificate) {
        self.derRepresentation = SecCertificateCopyData(secCertificate) as Data
        self.secCertificate = secCertificate
    }
}

extension Certificate {
    /// Return a string representing summary.
    ///
    /// - Returns: If found, a string representing the Summary.
    public var subjectSummary: String? {
        return SecCertificateCopySubjectSummary(secCertificate) as String?
    }
    
    /// Returns the common name of the subject of a given certificate.
    ///
    /// - Returns: If found, returns a String representing the common name, or nil.
    /// - Throws: If is not found, throws an error.
    public var commonName: String? {
        get throws {
            var commonName: CFString?
            switch SecCertificateCopyCommonName(secCertificate, &commonName) {
            case errSecSuccess:
                return commonName as String?
            case let status:
                throw SwiftSecurityError(rawValue: status)
            }
        }
    }
    
    /// Returns an array of zero or more email addresses for the subject of a given certificate.
    ///
    /// - Returns: Returns an array of 0 or more email addresses.
    /// - Throws: If is not found, throws an error.
    public var emailAddresses: [String] {
        get throws {
            var emailAddresses: CFArray?
            switch SecCertificateCopyEmailAddresses(secCertificate, &emailAddresses) {
            case errSecSuccess:
                return emailAddresses as! [String]
            case let status:
                throw SwiftSecurityError(rawValue: status)
            }
        }
    }
    
    /// Return the certificate's normalized issuer. The content returned is a DER-encoded X.509 distinguished name.
    ///
    /// - Returns: If found, returns a DER-encoded X.509 distinguished name.
    /// - Throws: If is not found, throws an error.
    public var normalizedIssuerSequence: Data? {
        get throws {
            guard let nis = SecCertificateCopyNormalizedIssuerSequence(secCertificate) as Data? else {
                throw SwiftSecurityError.invalidCertificate
            }
            return nis
        }
    }
    
    /// Return the certificate's normalized subject
    ///
    /// - Returns: If found, returns a DER-encoded X.509 distinguished name
    /// - Throws: If is not found, throws an error.
    public var normalizedSubjectSequence: Data? {
        get throws {
            guard let nss = SecCertificateCopyNormalizedSubjectSequence(secCertificate) as Data? else {
                throw SwiftSecurityError.invalidCertificate
            }
            return nss
        }
    }
    
    /// Return the certificate's serial number.
    /// - Returns: If found, returns the public key
    /// - Throws: If is not found, throws an error.
    public var serialNumberData: Data? {
        get throws {
            var error: Unmanaged<CFError>?
            guard let serial = SecCertificateCopySerialNumberData(secCertificate, &error) as Data?, error == nil else {
                if let error = error?.takeRetainedValue() {
                    throw SwiftSecurityError(error: error)
                }
                throw SwiftSecurityError.invalidCertificate
            }
            return serial
        }
    }
    
    /// Retrieves the public key for a given certificate.
    /// - Note: Exports SecKey type to an external representation suitable to key type.
    /// - Returns: If found, returns the pubic key.
    /// - Throws: If is not found, throws an error.
    public var publicKey: Data {
        get throws {
            guard let secKey = SecCertificateCopyKey(secCertificate) else {
                throw SwiftSecurityError.invalidCertificate
            }
            
            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCopyExternalRepresentation(secKey, &error) as Data?, error == nil else {
                if let error = error?.takeRetainedValue() {
                    throw SwiftSecurityError(error: error)
                }
                throw SwiftSecurityError.invalidCertificate
            }
            return publicKey
        }
    }
}
