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
     - The strings in the app’s [Keychain Access Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/keychain-access-groups)
     - The app ID string.
     - The strings in the [App Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     
     - SeeAlso: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    */
    case `default`
    
    /**
     The string from the app’s [Keychain Access Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/keychain-access-groups)
     - Example: `$(teamID).com.example.app`
     */
    case keychainGroup(teamID: String, groupID: String)
    
    /**
     The app ID string.
     - Note: `Bundle.main.bundleIdentifier`
     */
    case application
    
    /**
     The string from the [App Groups Entitlement](doc://com.apple.documentation/documentation/bundleresources/entitlements/com_apple_security_application-groups)
     - Example: `group.com.example.app`
     */
    case applicationGroup(_ groupID: String)
}
