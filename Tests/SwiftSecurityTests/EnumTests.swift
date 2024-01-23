//
//  EnumTests.swift
//  SwiftSecurityTests
//
//  Created by Dmitriy Zharov on 24.01.2024.
//

import XCTest
import Security

@testable import SwiftSecurity

final class EnumTests: XCTestCase {
    func testItemClass() {
        do {
            let itemClass = SecItemClass(rawValue: kSecClassGenericPassword as String)
            XCTAssertEqual(itemClass, .genericPassword)
        }
        do {
            let itemClass = SecItemClass(rawValue: kSecClassInternetPassword as String)
            XCTAssertEqual(itemClass, .internetPassword)
        }
        do {
            let itemClass = SecItemClass(rawValue: kSecClassCertificate as String)
            XCTAssertEqual(itemClass, .certificate)
        }
        do {
            let itemClass = SecItemClass(rawValue: kSecClassKey as String)
            XCTAssertEqual(itemClass, .key)
        }
        do {
            let itemClass = SecItemClass(rawValue: kSecClassIdentity as String)
            XCTAssertEqual(itemClass, .identity)
        }
    }
    
    func testAuthenticationMethod() {
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeNTLM as String)
            XCTAssertEqual(authenticationMethod, .ntlm)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeMSN as String)
            XCTAssertEqual(authenticationMethod, .msn)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeDPA as String)
            XCTAssertEqual(authenticationMethod, .dpa)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeRPA as String)
            XCTAssertEqual(authenticationMethod, .rpa)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeHTTPBasic as String)
            XCTAssertEqual(authenticationMethod, .httpBasic)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeHTTPDigest as String)
            XCTAssertEqual(authenticationMethod, .httpDigest)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeHTMLForm as String)
            XCTAssertEqual(authenticationMethod, .htmlForm)
        }
        do {
            let authenticationMethod = AuthenticationMethod(rawValue: kSecAttrAuthenticationTypeDefault as String)
            XCTAssertEqual(authenticationMethod, .default)
        }
    }
    
    func testProtocolType() {
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolFTP as String)
            XCTAssertEqual(protocolType, .ftp)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolFTPAccount as String)
            XCTAssertEqual(protocolType, .ftpAccount)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolHTTP as String)
            XCTAssertEqual(protocolType, .http)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolIRC as String)
            XCTAssertEqual(protocolType, .irc)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolNNTP as String)
            XCTAssertEqual(protocolType, .nntp)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolPOP3 as String)
            XCTAssertEqual(protocolType, .pop3)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolSMTP as String)
            XCTAssertEqual(protocolType, .smtp)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolSOCKS as String)
            XCTAssertEqual(protocolType, .socks)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolIMAP as String)
            XCTAssertEqual(protocolType, .imap)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolLDAP as String)
            XCTAssertEqual(protocolType, .ldap)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolAppleTalk as String)
            XCTAssertEqual(protocolType, .appleTalk)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolAFP as String)
            XCTAssertEqual(protocolType, .afp)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolTelnet as String)
            XCTAssertEqual(protocolType, .telnet)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolSSH as String)
            XCTAssertEqual(protocolType, .ssh)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolFTPS as String)
            XCTAssertEqual(protocolType, .ftps)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolHTTPS as String)
            XCTAssertEqual(protocolType, .https)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolHTTPProxy as String)
            XCTAssertEqual(protocolType, .httpProxy)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolHTTPSProxy as String)
            XCTAssertEqual(protocolType, .httpsProxy)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolFTPProxy as String)
            XCTAssertEqual(protocolType, .ftpProxy)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolSMB as String)
            XCTAssertEqual(protocolType, .smb)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolRTSP as String)
            XCTAssertEqual(protocolType, .rtsp)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolRTSPProxy as String)
            XCTAssertEqual(protocolType, .rtspProxy)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolDAAP as String)
            XCTAssertEqual(protocolType, .daap)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolEPPC as String)
            XCTAssertEqual(protocolType, .eppc)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolIPP as String)
            XCTAssertEqual(protocolType, .ipp)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolNNTPS as String)
            XCTAssertEqual(protocolType, .nntps)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolLDAPS as String)
            XCTAssertEqual(protocolType, .ldaps)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolTelnetS as String)
            XCTAssertEqual(protocolType, .telnetS)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolIMAPS as String)
            XCTAssertEqual(protocolType, .imaps)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolIRCS as String)
            XCTAssertEqual(protocolType, .ircs)
        }
        do {
            let protocolType = ProtocolType(rawValue: kSecAttrProtocolPOP3S as String)
            XCTAssertEqual(protocolType, .pop3S)
        }
    }
}
