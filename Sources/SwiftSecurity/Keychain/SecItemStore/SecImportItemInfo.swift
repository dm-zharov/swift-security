//
//  SecImportItemInfo.swift
//
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

public struct SecImportItemInfo {
    private(set) var rawValue: [String: Any]
}

public extension SecImportItemInfo {
    /// The corresponding value is item label. The format of the label is implementation specific.
    var label: String? {
        get { self[.label] as? String }
    }
    
    /// The corresponding value is key ID. This unique ID is often the SHA-1 digest of the public encryption key.
    var keyID: Data? {
        get { self[.keyID] as? Data }
    }
    
    /**
     The corresponding value i evaluated against the basic X.509 policy and includes as complete a certificate chain as could be constructed from the certificates in the PKCS #12 blob,
     certificates on the keychain, and any other certificates available to the system.
    
     You can use the `SecTrustEvaluate(_:_:)` function if you want to know whether the certificate chain is complete and valid (according to the basic X.509 policy). There is no guarantee that the evaluation will succeed.
     */
    var trust: SecTrust? {
        get { self[.trust] as! SecTrust? }
    }
    
    /**
     The corresponding value is list of all the certificates in the PKCS #12 blob.
    
     This list might differ from that in the trust management object if there is more than one identity in the blob or if the blob contains extra certificates
     (for example, an intermediate certificate that is not yet valid but might be needed to establish validity in the near future).
     */
    var certChain: [SecCertificate]? {
        get { self[.certChain] as! [SecCertificate]? }
    }

    /// The corresponding value represents one identity contained in the PKCS #12 blob and contains the certificate and private key wrapped together.
    var identity: SecIdentity? {
        get { self[.identity] as! SecIdentity?  }
    }
}

extension SecImportItemInfo {
    public subscript(attribute: String) -> Any? {
        get { rawValue[attribute] }
        set { rawValue[attribute] = newValue }
    }
}

extension SecImportItemInfo {
    subscript(key: SecImportItemKey) -> Any? {
        get { self[key.rawValue] }
        set { self[key.rawValue] = newValue }
    }
}
