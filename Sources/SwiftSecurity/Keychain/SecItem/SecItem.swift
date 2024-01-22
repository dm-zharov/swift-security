//
//  GenericPassword.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Security

public protocol SecItem { }
public protocol Password: SecItem { }

public struct GenericPassword: Password { }
public struct InternetPassword: Password { }

extension SecKey: SecItem { }
extension SecCertificate: SecItem { }
extension SecIdentity: SecItem { }
