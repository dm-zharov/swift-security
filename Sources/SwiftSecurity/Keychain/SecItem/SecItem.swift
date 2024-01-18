//
//  GenericPassword.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Security

public protocol SecItem { }
public protocol Password: SecItem { }

public class GenericPassword: Password {
    private init() { }
}
public class InternetPassword: Password {
    private init() { }
}

extension SecKey: SecItem { }
extension SecCertificate: SecItem { }
extension SecIdentity: SecItem { }
