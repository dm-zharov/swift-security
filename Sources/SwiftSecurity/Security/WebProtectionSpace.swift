//
//  WebProtectionSpace.swift
//
//
//  Created by Dmitriy Zharov on 18.01.2024.
//

import Foundation

/**
 A server or an area on a server, that requires authentication.
 
 - Note: The only minimum and required attribute is the host.
    Other attributes help characterize the password to distinguish it from other internet passwords that apply to the same ``host`` and ``username``.
    For example, if you need to store distinct FTP and HTTP credentials for the same user working on the same server, you might set the `'protocol'` attribute to distinguish between them.
 */
public struct WebProtectionSpace {
    /// The host name for the protection space object.
    public private(set) var host: String
    /// The port for the protection space object.
    public private(set) var port: Int?
    /// The receiver’s port.
    public private(set) var path: String?
    /// The protocol for the protection space object. The value of protocol is equivalent to the scheme for a URL in the protection space, for example, “http”, “https”, “ftp”, etc.
    public private(set) var `protocol`: ProtocolType?
    /// The security domain.
    public private(set) var securityDomain: String?
    /// The type of authentication.
    public private(set) var authenticationMethod: AuthenticationMethod?
    
    /// Creates a protection space object from the given host, port, protocol, realm, and authentication method.
    /// - Parameters:
    ///   - server: Host (e.g. `apple.com`)
    ///   - port: Port (e.g. `443`).
    ///   - protocol: Protocol (e.g. `https`).
    ///   - authentication: Authentication method (e.g. ".httpBasic")
    ///   - path: Path (e.g. path component of the URL).
    ///   - securityDomain: Security domain.
    public init(
        host: String,
        port: Int? = nil,
        protocol: ProtocolType? = nil,
        authenticationMethod: AuthenticationMethod? = nil,
        path: String? = nil,
        securityDomain: String? = nil
    ) {
        self.host = host
        self.port = port
        self.path = path
        self.protocol = `protocol`
        self.securityDomain = securityDomain
        self.authenticationMethod = authenticationMethod
    }
}

public extension WebProtectionSpace {
    /// Creates a protection space object for the given server.
    /// - Parameter string: Server (e. g. `https://apple.com`).
    static func server(_ string: String) -> WebProtectionSpace {
        WebProtectionSpace(host: string)
    }
}
