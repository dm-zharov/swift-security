//
//  PKCS12.swift
//
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

public enum PKCS12 {
    public struct SecImportItem {
        private(set) var rawValue: [String: Any]
    }
    
    /// PKCS #12–formatted blob (a file with extension .p12)
    public struct Data: RawRepresentable {
        public let rawValue: Foundation.Data
        
        public init(rawValue: Foundation.Data) {
            self.rawValue = rawValue
        }
    }
}

public extension PKCS12.SecImportItem {
    /// The corresponding value is item label. The format of the label is implementation specific.
    var label: String? {
        get { self[kSecImportItemLabel as String] as? String }
    }
    
    /// The corresponding value is key ID. This unique ID is often the SHA-1 digest of the public encryption key.
    var itemKeyID: String? {
        get { self[kSecImportItemKeyID as String] as? String }
    }
    
    /**
     The corresponding value i evaluated against the basic X.509 policy and includes as complete a certificate chain as could be constructed from the certificates in the PKCS #12 blob,
     certificates on the keychain, and any other certificates available to the system.
    
     You can use the `SecTrustEvaluate(_:_:)` function if you want to know whether the certificate chain is complete and valid (according to the basic X.509 policy). There is no guarantee that the evaluation will succeed.
     */
    var trust: SecTrust? {
        get { self[kSecImportItemTrust as String] as! SecTrust? }
    }
    
    /**
     The corresponding value is list of all the certificates in the PKCS #12 blob.
    
     This list might differ from that in the trust management object if there is more than one identity in the blob or if the blob contains extra certificates
     (for example, an intermediate certificate that is not yet valid but might be needed to establish validity in the near future).
     */
    var certChain: [SecCertificate]? {
        get { self[kSecImportItemCertChain as String] as! [SecCertificate]? }
    }
    
    /// The corresponding value represents one identity contained in the PKCS #12 blob.
    var identity: SecIdentity? {
        get { self[kSecImportItemIdentity as String] as! SecIdentity?  }
    }
}

extension PKCS12.SecImportItem {
    subscript(attribute: String) -> Any? {
        rawValue[attribute]
    }
}
