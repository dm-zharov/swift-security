//
//  SecItemSearch.swift
//
//
//  Created by Dmitriy Zharov on 14.03.2024.
//

import Foundation

/**
 Search Attribute Keys and Values
 - SeeAlso: https://developer.apple.com/documentation/security/keychain_services/keychain_items/search_attribute_keys_and_values
 */
struct SecItemSearch: Equatable, RawRepresentable {
    var rawValue: String
}

// MARK: - Item Search Matching Keys

extension SecItemSearch {
    static let matchPolicy                = SecItemSearch(rawValue: kSecMatchPolicy as String)
    static let matchItemList              = SecItemSearch(rawValue: kSecMatchItemList as String)
    static let matchSearchList            = SecItemSearch(rawValue: kSecMatchSearchList as String)
    static let matchIssuers               = SecItemSearch(rawValue: kSecMatchIssuers as String)
    static let matchEmailAddressIfPresent = SecItemSearch(rawValue: kSecMatchEmailAddressIfPresent as String)
    static let matchSubjectContains       = SecItemSearch(rawValue: kSecMatchSubjectContains as String)
    static let matchMatchCaseInsensitive  = SecItemSearch(rawValue: kSecMatchCaseInsensitive as String)
    static let matchTrustedOnly           = SecItemSearch(rawValue: kSecMatchTrustedOnly as String)
    static let matchValidOnDate           = SecItemSearch(rawValue: kSecMatchValidOnDate as String)
    static let matchLimit                 = SecItemSearch(rawValue: kSecMatchLimit as String)
    
    #if os(macOS)
    static let matchSubjectWholeString    = SecItemSearch(rawValue: kSecMatchSubjectWholeString as String)
    static let matchDiacriticInsensitive  = SecItemSearch(rawValue: kSecMatchDiacriticInsensitive as String)
    static let matchWidthInsensitive      = SecItemSearch(rawValue: kSecMatchWidthInsensitive as String)
    #endif
}

extension Dictionary where Key == String {
    subscript(search attribute: SwiftSecurity.SecItemSearch) -> Value? {
        get { self[attribute.rawValue] }
        set { self[attribute.rawValue] = newValue }
    }
}
