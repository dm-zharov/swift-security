//
//  SymmetricKey+Derivation.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import Foundation
import CryptoKit

extension SymmetricKey {
    static func derived(from privateKey: PrivateKey, info: Data) throws -> SymmetricKey {
        try derived(from: privateKey, with: privateKey.publicKey, sharedInfo: info)
    }
    
    static func derived(
        from privateKey: PrivateKey,
        with publicKey: PublicKey,
        sharedInfo: Data
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: sharedInfo,
            outputByteCount: 32 // 256 Bit
        )
        return derivedKey
    }
}
