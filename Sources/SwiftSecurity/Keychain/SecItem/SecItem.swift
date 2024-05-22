//
//  GenericPassword.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Security

public protocol SecItem { }
public protocol SecData: SecItem { }

public struct GenericPassword: SecData { }
public struct InternetPassword: SecData { }

extension SecKey: SecItem { }
extension SecCertificate: SecItem { }
extension SecIdentity: SecItem { }
