//
//  SecImportItemKey.swift
//
//
//  Created by Dmitriy Zharov on 23.05.2024.
//

import Foundation

struct SecImportItemKey: Equatable, RawRepresentable {
    let rawValue: String
}

extension SecImportItemKey {
    static let label     = SecImportItemKey(rawValue: kSecImportItemLabel as String)
    static let keyID     = SecImportItemKey(rawValue: kSecImportItemKeyID as String)
    static let trust     = SecImportItemKey(rawValue: kSecImportItemTrust as String)
    static let certChain = SecImportItemKey(rawValue: kSecImportItemCertChain as String)
    static let identity  = SecImportItemKey(rawValue: kSecImportItemIdentity as String)
}

extension SecImportItemKey: CustomStringConvertible {
    var description: String {
        switch self {
        case .label:
            return "Label"
        case .keyID:
            return "Key ID"
        case .trust:
            return "Trust"
        case .certChain:
            return "Cert Chain"
        case .identity:
            return "Identity"
        default:
            return rawValue
        }
    }
}
