//
//  Accessibility.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation

public enum Accessibility {
    /**
     If the user hasn’t set a passcode, you can’t store an item with this setting.
     If the user removes the passcode from a device, any items with this setting are automatically deleted from the keychain.
     You can only access items with this setting if the device is unlocked. Use this setting if your app only needs access to items while running in the foreground.
     - Note: The item can be restored to the same device that created a backup, but it isn’t migrated when restoring another device’s backup data.
     */
    case whenPasscodeSetThisDeviceOnly
    
    /**
     Items with this setting are only accessible when the device is unlocked. A device without a passcode is considered to always be unlocked.
     - Note: The item can be restored to the same device that created a backup, but it isn’t migrated when restoring another device’s backup data.
     */
    case whenUnlockedThisDeviceOnly
    
    /**
     Items with this setting are only accessible when the device is unlocked.  A device without a passcode is considered to always be unlocked.
     - Remark: This is the default accessibility when you don’t otherwise specify a setting.
     */
    case whenUnlocked

    /**
     This condition becomes true once the user unlocks the device for the first time after a restart, or if the device does not have a passcode.
     It remains true until the device restarts again.Use this level of accessibility when your app needs to access the item while running in the background.
     - Note: The item can be restored to the same device that created a backup, but it isn’t migrated when restoring another device’s backup data.
     */

    case afterFirstUnlockThisDeviceOnly

    /**
     This condition becomes true once the user unlocks the device for the first time after a restart, or if the device does not have a passcode.
     It remains true until the device restarts again.Use this level of accessibility when your app needs to access the item while running in the background.
     */
    case afterFirstUnlock
}

extension Accessibility: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly):
            self = .whenPasscodeSetThisDeviceOnly
        case String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly):
            self = .whenUnlockedThisDeviceOnly
        case String(kSecAttrAccessibleWhenUnlocked):
            self = .whenUnlocked
        case String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly):
            self = .afterFirstUnlockThisDeviceOnly
        case String(kSecAttrAccessibleAfterFirstUnlock):
            self = .afterFirstUnlock
        default:
            return nil
        }
    }

    public var rawValue: String {
        switch self {
        case .whenPasscodeSetThisDeviceOnly:
            return String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        case .whenUnlockedThisDeviceOnly:
            return String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        case .whenUnlocked:
            return String(kSecAttrAccessibleWhenUnlocked)
        case .afterFirstUnlockThisDeviceOnly:
            return String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        case .afterFirstUnlock:
            return String(kSecAttrAccessibleAfterFirstUnlock)
        }
    }

    public var description: String {
        switch self {
        case .whenPasscodeSetThisDeviceOnly:
            return "WhenPasscodeSetThisDeviceOnly"
        case .whenUnlockedThisDeviceOnly:
            return "WhenUnlockedThisDeviceOnly"
        case .whenUnlocked:
            return "WhenUnlocked"
        case .afterFirstUnlockThisDeviceOnly:
            return "AfterFirstUnlockThisDeviceOnly"
        case .afterFirstUnlock:
            return "AfterFirstUnlock"
        }
    }
}
