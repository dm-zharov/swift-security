//
//  SharedWebCredential.swift
//
//
//  Created by Dmitriy Zharov on 22.01.2024.
//

import Foundation

@available(watchOS, unavailable)
@available(tvOS, unavailable)
public struct SharedWebCredential {
    /// Stores a shared password item that will be accessible by Safari and apps that have the specified fully qualified domain name in their [Associated Domains Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_associated-domains). If a shared password item already exists, it is updated with the provided password.
    /// - Parameters:
    ///   - fqdn: The fully qualified domain name of the website requiring the password.
    ///   - account: The account name associated with this password.
    ///   - password: The password.
    ///   - completion: A block invoked when the function has completed.
    /// - Note: Because a request involving shared web credentials may potentially require user interaction or other verification to be approved, this function is dispatched asynchronously; your code provides a completion handler that is called as soon as the results (if any) are available.
    static func store(_ fqdn: String, account: String, password: String, completion: @escaping (Result<Void, Error>) -> Void) {
        #if !os(watchOS) && !os(tvOS)
        SecAddSharedWebCredential(
            fqdn as CFString,
            account as CFString,
            password as CFString
        ) { error in
            if let error {
                completion(.failure(error))
            } else {
                completion(.success(()))
            }
        }
        #else
        completion(.failure(SwiftSecurityError.unimplemented))
        #endif
    }
    
    /// Removes a shared password item that will be accessible by Safari and apps that have the specified fully qualified domain name in their [Associated Domains Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_associated-domains).
    /// - Parameter completion: A block invoked when the function has completed.
    static func remove(_ fqdn: String, account: String, completion: @escaping (Result<Void, Error>) -> Void) {
        #if !os(watchOS) && !os(tvOS)
        SecAddSharedWebCredential(
            fqdn as CFString,
            account as CFString,
            nil
        ) { error in
            if let error {
                completion(.failure(error))
            } else {
                completion(.success(()))
            }
        }
        #else
        completion(.failure(SwiftSecurityError.unimplemented))
        #endif
    }
}

@available(watchOS, unavailable)
@available(tvOS, unavailable)
public extension SharedWebCredential {
    /// Password in the form xxx-xxx-xxx-xxx where x is taken from the sets "abcdefghkmnopqrstuvwxy", "ABCDEFGHJKLMNPQRSTUVWXYZ", "3456789" with at least one character from each set being present.
    /// - Returns: Returns a randomly generated password.
    static func generatePassword() -> String {
        #if os(tvOS) || os(watchOS)
        fatalError("generatePassword() is not available")
        #else
        return SecCreateSharedWebCredentialPassword()! as String
        #endif
    }
}
