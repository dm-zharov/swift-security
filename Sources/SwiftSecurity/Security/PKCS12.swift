//
//  PKCS12.swift
//
//
//  Created by Dmitriy Zharov on 28.05.2024.
//

import Foundation

// MARK: PKCS #12 Blob

public enum PKCS12 {
    /// Imports the contents of PKCS #12 file (also known as PKCS12, PFX, .p12, and .pfx).
    /// - Parameters:
    ///   - data: The PKCS #12 data you wish to decode.
    ///   - passphrase: A passphrase to be used when importing from PKCS#12 data.
    /// - Note: On macOS, automatically imports identity and certificate chain to the keychain.
    /// See [SecImportExport.c](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecImportExport.c#L139)
    /// - Important: Do not bundle passwords with your app in any form. Doing so is insecure, because no matter how carefully you try to obscure a password,
    /// a motivated attacker will find a way to mimic the operations you use to reveal it for your own purposes.
    /// Instead, prompt the user for a password when you need it, or read it from the secure storage offered by a keychain.
    /// - Returns: On return, the list of each item (identity or certificate) in the PKCS #12 blob.
    public static func `import`(_ data: Data, passphrase: String) throws -> [SecImportItemInfo] {
        var result: CFArray?
        switch SecPKCS12Import(data as CFData, [
            // The data protection key makes macOS use modern keychain implementation.
            kSecUseDataProtectionKeychain as String: true,
            kSecImportExportPassphrase as String: passphrase
        ] as CFDictionary, &result) {
        case errSecSuccess:
            if let items = result as? Array<[String: Any]> {
                return items.map { item in
                    SecImportItemInfo(rawValue: item)
                }
            } else {
                return []
            }
        case let status:
            throw SwiftSecurityError(rawValue: status)
        }
    }
}
