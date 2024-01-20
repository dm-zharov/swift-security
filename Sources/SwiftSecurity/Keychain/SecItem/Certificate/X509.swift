//
//  X509.swift
//
//
//  Created by Dmitriy Zharov on 20.01.2024.
//

import Foundation

public enum X509 {
    /// Distinguished Encoding Rules (DER) encoded data.
    public enum DER {
        public struct Data: RawRepresentable {
            public let rawValue: Foundation.Data
            
            public init(rawValue: Foundation.Data) {
                self.rawValue = rawValue
            }
        }
    }
}
