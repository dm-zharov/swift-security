//
//  SecIdentityConvertible.swift
//
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

public protocol SecIdentityConvertible<Certificate>: SecIdentityRepresentable {
    associatedtype Certificate: SecCertificateConvertible
}

// MARK: - SwiftSecurity

extension DigitalIdentity: SecIdentityConvertible {
    public typealias Certificate = SwiftSecurity.Certificate
}

// MARK: - SecIdentity

public protocol SecIdentityRepresentable {
    /// Creates an identity from a raw representation.
    init(identity secIdentity: SecIdentity)
    
    /// An identity reference.
    var secIdentity: SecIdentity { get throws }
}
