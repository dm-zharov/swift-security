//
//  AccessGroup.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

public enum AccessGroup {
    /**
     The system considers the first item in the list of access groups to be the app’s default access group.
     
     - If `Keychain Sharing` capability is enabled, that's the first keychain group (e.g. `$(teamID).com.example.app`).
     - If `Keychain Sharing` capability is not enabled or empty, that's the application ID (e.g. `com.example.app`).
     - If `App Group` capability is enabled, that's suitable access group. However app group can’t ever be the default, because the application ID is always present and appears earlier in the list.
     
     - SeeAlso: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    */
    case `default`
    
    case keychainGroupID(teamID: String, groupID: String)
    
    case applicationID // Bundle.main.bundleIdentifier
    
    case applicationGroupID(_ groupID: String)
}
