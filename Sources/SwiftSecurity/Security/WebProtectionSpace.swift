//
//  WebProtectionSpace.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

/**
 A server or an area on a server, that requires authentication.
 
 The only minimum and required attribute is the host.
 Other attributes help characterize the password to distinguish it from other internet passwords that apply to the same attributes; for example the same ``host`` and ``username``.
    
 - Note: If you need to store distinct FTP and HTTP credentials for the same user working on the same server, you might set the ``protocol`` attribute to distinguish between them.
 */
public struct WebProtectionSpace: Equatable, Sendable {
    /// The host name, typically the domain name or IP address.
    public private(set) var host: String
    /// The port number.
    public private(set) var port: Int?
    /// The path, typically the path component of the URL.
    public private(set) var path: String?
    /// The value of protocol is equivalent to the scheme. For example: “http”, “https”, “ftp”, etc.
    public private(set) var `protocol`: ProtocolType?
    /// The security domain.
    public private(set) var securityDomain: String?
    /// The type of authentication.
    public private(set) var authenticationType: AuthenticationType?
    
    /// Creates a protection space object from the given host, port, protocol, realm, and authentication method.
    /// - Parameters:
    ///   - server: The host; for example, `apple.com`.
    ///   - port: The port number; for example: `443`.
    ///   - protocol: The protocol; for example `https`, `ftp`.
    ///   - authentication: The type of authentication; for example: `.httpBasic`.
    ///   - path: The path, typically the path component of the URL.
    ///   - securityDomain: The security domain.
    public init(
        host: String,
        port: Int? = nil,
        protocol: ProtocolType? = nil,
        authenticationType: AuthenticationType? = nil,
        path: String? = nil,
        securityDomain: String? = nil
    ) {
        self.host = host
        self.port = port
        self.path = path
        self.protocol = `protocol`
        self.securityDomain = securityDomain
        self.authenticationType = authenticationType
    }
}

public extension WebProtectionSpace {
    /// Creates a protection space object for the given website.
    /// - Parameter fqdn: The fully qualified domain name of the website, for example `subdomain.apple.com`.
    static func website(_ fqdn: String) -> WebProtectionSpace {
        WebProtectionSpace(host: fqdn)
    }
}
