//
//  AuthenticationMethod.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation

public enum AuthenticationMethod: Sendable {
    case ntlm
    case msn
    case dpa
    case rpa
    case httpBasic
    case httpDigest
    case htmlForm
    case `default`
}

extension AuthenticationMethod: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrAuthenticationTypeNTLM):
            self = .ntlm
        case String(kSecAttrAuthenticationTypeMSN):
            self = .msn
        case String(kSecAttrAuthenticationTypeDPA):
            self = .dpa
        case String(kSecAttrAuthenticationTypeRPA):
            self = .rpa
        case String(kSecAttrAuthenticationTypeHTTPBasic):
            self = .httpBasic
        case String(kSecAttrAuthenticationTypeHTTPDigest):
            self = .httpDigest
        case String(kSecAttrAuthenticationTypeHTMLForm):
            self = .htmlForm
        case String(kSecAttrAuthenticationTypeDefault):
            self = .`default`
        default:
            return nil
        }
    }

    public var rawValue: String {
        switch self {
        case .ntlm:
            return String(kSecAttrAuthenticationTypeNTLM)
        case .msn:
            return String(kSecAttrAuthenticationTypeMSN)
        case .dpa:
            return String(kSecAttrAuthenticationTypeDPA)
        case .rpa:
            return String(kSecAttrAuthenticationTypeRPA)
        case .httpBasic:
            return String(kSecAttrAuthenticationTypeHTTPBasic)
        case .httpDigest:
            return String(kSecAttrAuthenticationTypeHTTPDigest)
        case .htmlForm:
            return String(kSecAttrAuthenticationTypeHTMLForm)
        case .`default`:
            return String(kSecAttrAuthenticationTypeDefault)
        }
    }

    public var description: String {
        switch self {
        case .ntlm:
            return "NTLM"
        case .msn:
            return "MSN"
        case .dpa:
            return "DPA"
        case .rpa:
            return "RPA"
        case .httpBasic:
            return "HTTPBasic"
        case .httpDigest:
            return "HTTPDigest"
        case .htmlForm:
            return "HTMLForm"
        case .`default`:
            return "Default"
        }
    }
}
