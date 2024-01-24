//
//  SecAccessPolicy.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/**
 - SeeAlso: [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility)
 */
public struct SecAccessPolicy {
    /// The corresponding value specifies when the item can be accessed.
    public var protection: Accessibility
    /// The corresponding value specifies what type of authentication is needed.
    public var options: Options?
    
    /// Keychain item access policy.
    /// - Parameters:
    ///   - protection: Protection level for the item.
    ///   - options: Authentication requirements for the item.
    public init(_ protection: Accessibility, options: Options? = nil) {
        self.protection = protection
        self.options = options
    }
}

public extension SecAccessPolicy {
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    /// - Note: After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to be accessed by background applications. Items with this attribute migrate to a new device when using encrypted backups.
    static var `default`: SecAccessPolicy {
        SecAccessPolicy(.afterFirstUnlock)
    }
}

extension SecAccessPolicy {
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
}

extension SecAccessPolicy {
    public struct Options: OptionSet {
        // MARK: - Constraints
        
        /**
         Constraint to access an item with either biometry or passcode.
         
         Biometry doesn’t have to be available or enrolled.
         The item is still accessible by Touch ID even if fingers are added or removed, or by Face ID if the user is re-enrolled.
         
         This option is equivalent to specifying ``biometryAny``, ``or``, and ``devicePasscode``.
         */
        public static let userPresence = Options(rawValue: 1 << 0)
        
        /**
         Constraint to access an item with Touch ID for any enrolled fingers, or Face ID.
         
         Touch ID must be available and enrolled with at least one finger, or Face ID must be available and enrolled.
         The item is still accessible by Touch ID if fingers are added or removed, or by Face ID if the user is re-enrolled.
         */
        public static let biometryAny = Options(rawValue: 1 << 1)
        
        /**
         Constraint to access an item with Touch ID for currently enrolled fingers, or from Face ID with the currently enrolled user.
         
         Touch ID must be available and enrolled with at least one finger, or Face ID available and enrolled.
         The item is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID.
         */
        public static let biometryCurrentSet = Options(rawValue: 1 << 3)
        
        /**
         Constraint to access an item with a passcode.
         */
        public static let devicePasscode = Options(rawValue: 1 << 4)

        /**
         Constraint: Watch
         */
        @available(iOS, unavailable)
        @available(macOS 10.15, *)
        @available(macCatalyst 13.0, *)
        @available(watchOS, unavailable)
        @available(tvOS, unavailable)
        public static let watch = Options(rawValue: 1 << 5)
        
        // MARK: - Conjunctions

        /**
         Indicates that all constraints must be satisfied.
         */
        public static let or = Options(rawValue: 1 << 14)

        /**
         Indicates that at least one constraint must be satisfied.
         */
        public static let and = Options(rawValue: 1 << 15)
        
        // MARK: - Additional Options

        /**
         Enable a private key to be used in signing a block of data or verifying a signed block.
         
         This option can be combined with any other access control option.
         
         - SeeAlso: [Developer Documentation](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1617983-privatekeyusage)
         */
        public static let privateKeyUsage = Options(rawValue: 1 << 30)

        /**
         Option to use an application-provided password for data encryption key generation.

         This may be specified in addition to any constraints.
         */
        public static let applicationPassword = Options(rawValue: 1 << 31)

        public let rawValue: UInt

        public init(rawValue: UInt) {
            self.rawValue = rawValue
        }
    }
}

extension SecAccessPolicy.Accessibility: RawRepresentable, CustomStringConvertible {
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


internal extension SecAccessPolicy {
    /// The corresponding value containing access control conditions for the item.
    var accessControl: SecAccessControl? {
        get throws {
            guard let options else {
                return nil
            }
            
            var error: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                protection.rawValue as CFTypeRef,
                SecAccessControlCreateFlags(rawValue: CFOptionFlags(options.rawValue)),
                &error
            ) else {
                if let error = error?.takeUnretainedValue() {
                    throw SwiftSecurityError(error: error)
                } else {
                    throw SwiftSecurityError(rawValue: errSecBadReq)
                }
            }
            
            return accessControl
        }
    }
    
    /// The corresponding value indicates when your app needs access to the data in a keychain item.
    var accessibility: String? {
        guard options == nil else {
            return nil
        }
        return protection.rawValue
    }
}
