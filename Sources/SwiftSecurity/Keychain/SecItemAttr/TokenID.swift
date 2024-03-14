//
//  TokenID.swift
//
//
//  Created by Dmitriy Zharov on 23.01.2024.
//

import Security

public enum TokenID {
    /**
     Specifies an item should be stored in the device's Secure Enclave.

     - Note: The only keychain items supported by the Secure Enclave are 256-bit elliptic curve private keys (those that have key type kSecAttrKeyTypeEC).
     Such keys must be generated directly on the Secure Enclave using the ``SecKeyGeneratePair(_:_:_:)`` function
     with the ``tokenID`` key set to ``.secureEnclave`` in the query.
     - Important: It is not possible to import pre-existing keys into the Secure Enclave.
     */
    case secureEnclave
}

extension TokenID: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrTokenIDSecureEnclave):
            self = .secureEnclave
        default:
            return nil
        }
    }
    
    public var rawValue: String {
        switch self {
        case .secureEnclave:
            return String(kSecAttrTokenIDSecureEnclave)
        }
    }
    
    public var description: String {
        switch self {
        case .secureEnclave:
            return String("SecureEnclave")
        }
    }
}
