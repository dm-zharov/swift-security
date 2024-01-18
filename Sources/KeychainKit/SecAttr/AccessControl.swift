//
//  AccessControl.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation
import Security

/**
 - SeeAlso: [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility)
 */
public struct AccessControl: RawRepresentable {
    public let rawValue: SecAccessControl
    
    public init(rawValue: SecAccessControl) {
        self.rawValue = rawValue
    }
}

extension AccessControl {
    public init(_ protection: Accessibility, with flags: Flags) throws {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            protection.rawValue as CFTypeRef,
            SecAccessControlCreateFlags(rawValue: CFOptionFlags(flags.rawValue)),
            &error
        ) else {
            if let error = error?.takeUnretainedValue() {
                throw KeychainError.failedAccessControlCreation(description: error.localizedDescription)
            } else {
                throw KeychainError.failedAccessControlCreation(description: "")
            }
        }
        self = AccessControl(rawValue: accessControl)
    }
}

extension AccessControl {
    public struct Flags: OptionSet {
        // MARK: - Constraints
        
        /**
         Constraint to access an item with either biometry or passcode.
         
         Biometry doesn’t have to be available or enrolled.
         The item is still accessible by Touch ID even if fingers are added or removed, or by Face ID if the user is re-enrolled.
         
         This option is equivalent to specifying ``biometryAny``, ``or``, and ``devicePasscode``.
         */
        public static let userPresence = Flags(rawValue: 1 << 0)
        
        /**
         Constraint to access an item with Touch ID for any enrolled fingers, or Face ID.
         
         Touch ID must be available and enrolled with at least one finger, or Face ID must be available and enrolled.
         The item is still accessible by Touch ID if fingers are added or removed, or by Face ID if the user is re-enrolled.
         */
        public static let biometryAny = Flags(rawValue: 1 << 1)
        
        /**
         Constraint to access an item with Touch ID for currently enrolled fingers, or from Face ID with the currently enrolled user.
         
         Touch ID must be available and enrolled with at least one finger, or Face ID available and enrolled.
         The item is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID.
         */
        public static let biometryCurrentSet = Flags(rawValue: 1 << 3)
        
        /**
         Constraint to access an item with a passcode.
         */
        public static let devicePasscode = Flags(rawValue: 1 << 4)

        /**
         Constraint: Watch
         */
        @available(iOS, unavailable)
        @available(macOS 10.15, *)
        @available(macCatalyst 13.0, *)
        @available(watchOS, unavailable)
        @available(tvOS, unavailable)
        public static let watch = Flags(rawValue: 1 << 5)
        
        // MARK: - Conjunctions

        /**
         Indicates that all constraints must be satisfied.
         */
        public static let or = Flags(rawValue: 1 << 14)

        /**
         Indicates that at least one constraint must be satisfied.
         */
        public static let and = Flags(rawValue: 1 << 15)

        /**
         Enable a private key to be used in signing a block of data or verifying a signed block.
         
         This option can be combined with any other access control flags.
         
         - SeeAlso: [Developer Documentation](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1617983-privatekeyusage)
         */
        public static let privateKeyUsage = Flags(rawValue: 1 << 30)

        /**
         Option to use an application-provided password for data encryption key generation.

         This may be specified in addition to any constraints.
         */
        public static let applicationPassword = Flags(rawValue: 1 << 31)

        public let rawValue: UInt

        public init(rawValue: UInt) {
            self.rawValue = rawValue
        }
    }

}
