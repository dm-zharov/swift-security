//
//  AsymmetricKey.swift
//
//
//  Created by Dmitriy Zharov on 05.06.2023.
//

import CryptoKit

typealias PublicKey = P256.KeyAgreement.PublicKey
#if targetEnvironment(simulator)
typealias PrivateKey = P256.KeyAgreement.PrivateKey
#else
typealias PrivateKey = SecureEnclave.P256.KeyAgreement.PrivateKey
#endif
