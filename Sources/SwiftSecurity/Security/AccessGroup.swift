//
//  AccessGroup.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

public enum AccessGroup {
    /**
     The system considers the first item in the list of access groups to be the app’s default access group. The list of an app’s access groups consists of the following string identifiers, in this order:
     - The strings in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string.
     - The strings in the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     - SeeAlso: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    */
    case `default`
    
    /**
     The string from the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
     - Note: `$(teamID).com.example.app`
     - Parameters:
        - teamID: ${TeamIdentifierPrefix}. For example, `S4Z89HZ24E`.
        - nameID: Bundle identifier. For example, `com.example.app`.
     */
    case keychainGroup(teamID: String, nameID: String)
    
    /**
     The string from the [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     - Note: `group.com.example.app`
     - Parameters:
        - groupID: App Group. For example, `group.com.example.app`.
     */
    @available(macOS, unavailable, message: "Use `keychainGroup(teamID:nameID:)`")
    case appGroupID(_ groupID: String)
    
    
    /**
     Use this access group to access external tokens such as smart cards.
     - Note: Access to this group is granted by default and does not require an explicit entry in your app's [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups).
     */
    case token
}
