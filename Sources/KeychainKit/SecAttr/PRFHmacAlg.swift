//
//  PRFHmacAlg.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

#if os(macOS)
public enum PRFHmacAlg {
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
}

extension PRFHmacAlg: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrPRFHmacAlgSHA1):
            self = .sha1
        case String(kSecAttrPRFHmacAlgSHA224):
            self = .sha224
        case String(kSecAttrPRFHmacAlgSHA256):
            self = .sha256
        case String(kSecAttrPRFHmacAlgSHA384):
            self = .sha384
        case String(kSecAttrPRFHmacAlgSHA512):
            self = .sha512
        default:
            return nil
        }
    }
    
    public var rawValue: String {
        switch self {
        case .sha1:
            return String(kSecAttrPRFHmacAlgSHA1)
        case .sha224:
            return String(kSecAttrPRFHmacAlgSHA224)
        case .sha256:
            return String(kSecAttrPRFHmacAlgSHA256)
        case .sha384:
            return String(kSecAttrPRFHmacAlgSHA384)
        case .sha512:
            return String(kSecAttrPRFHmacAlgSHA512)
        }
    }
    
    public var description: String {
        switch self {
        case .sha1:
            return "SHA1"
        case .sha224:
            return "SHA224"
        case .sha256:
            return "SHA256"
        case .sha384:
            return "SHA384"
        case .sha512:
            return "SHA512"
        }
    }
}
#endif
