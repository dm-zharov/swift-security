//
//  SecItemSearchKey.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

/**
 Search Attribute Keys and Values
 - SeeAlso: https://developer.apple.com/documentation/security/keychain_services/keychain_items/search_attribute_keys_and_values
 */
struct SecItemSearchKey: Equatable, RawRepresentable {
    let rawValue: String
}

// MARK: - Item Search Matching Keys

extension SecItemSearchKey {
    static let matchPolicy                = SecItemSearchKey(rawValue: kSecMatchPolicy as String)
    static let matchItemList              = SecItemSearchKey(rawValue: kSecMatchItemList as String)
    static let matchIssuers               = SecItemSearchKey(rawValue: kSecMatchIssuers as String)
    static let matchEmailAddressIfPresent = SecItemSearchKey(rawValue: kSecMatchEmailAddressIfPresent as String)
    static let matchSubjectContains       = SecItemSearchKey(rawValue: kSecMatchSubjectContains as String)
    static let matchMatchCaseInsensitive  = SecItemSearchKey(rawValue: kSecMatchCaseInsensitive as String)
    static let matchTrustedOnly           = SecItemSearchKey(rawValue: kSecMatchTrustedOnly as String)
    static let matchValidOnDate           = SecItemSearchKey(rawValue: kSecMatchValidOnDate as String)
    static let matchLimit                 = SecItemSearchKey(rawValue: kSecMatchLimit as String)
}
