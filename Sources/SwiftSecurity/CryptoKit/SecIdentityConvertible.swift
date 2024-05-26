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

extension DigitalIdentity: SecIdentityConvertible {}
