//
//  ProtocolType.swift
//
//
//  Created by Dmitriy Zharov on 17.01.2024.
//

import Foundation

public enum ProtocolType: Sendable {
    case ftp
    case ftpAccount
    case http
    case irc
    case nntp
    case pop3
    case smtp
    case socks
    case imap
    case ldap
    case appleTalk
    case afp
    case telnet
    case ssh
    case ftps
    case https
    case httpProxy
    case httpsProxy
    case ftpProxy
    case smb
    case rtsp
    case rtspProxy
    case daap
    case eppc
    case ipp
    case nntps
    case ldaps
    case telnetS
    case imaps
    case ircs
    case pop3S
}

extension ProtocolType: RawRepresentable, CustomStringConvertible {
    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrProtocolFTP):
            self = .ftp
        case String(kSecAttrProtocolFTPAccount):
            self = .ftpAccount
        case String(kSecAttrProtocolHTTP):
            self = .http
        case String(kSecAttrProtocolIRC):
            self = .irc
        case String(kSecAttrProtocolNNTP):
            self = .nntp
        case String(kSecAttrProtocolPOP3):
            self = .pop3
        case String(kSecAttrProtocolSMTP):
            self = .smtp
        case String(kSecAttrProtocolSOCKS):
            self = .socks
        case String(kSecAttrProtocolIMAP):
            self = .imap
        case String(kSecAttrProtocolLDAP):
            self = .ldap
        case String(kSecAttrProtocolAppleTalk):
            self = .appleTalk
        case String(kSecAttrProtocolAFP):
            self = .afp
        case String(kSecAttrProtocolTelnet):
            self = .telnet
        case String(kSecAttrProtocolSSH):
            self = .ssh
        case String(kSecAttrProtocolFTPS):
            self = .ftps
        case String(kSecAttrProtocolHTTPS):
            self = .https
        case String(kSecAttrProtocolHTTPProxy):
            self = .httpProxy
        case String(kSecAttrProtocolHTTPSProxy):
            self = .httpsProxy
        case String(kSecAttrProtocolFTPProxy):
            self = .ftpProxy
        case String(kSecAttrProtocolSMB):
            self = .smb
        case String(kSecAttrProtocolRTSP):
            self = .rtsp
        case String(kSecAttrProtocolRTSPProxy):
            self = .rtspProxy
        case String(kSecAttrProtocolDAAP):
            self = .daap
        case String(kSecAttrProtocolEPPC):
            self = .eppc
        case String(kSecAttrProtocolIPP):
            self = .ipp
        case String(kSecAttrProtocolNNTPS):
            self = .nntps
        case String(kSecAttrProtocolLDAPS):
            self = .ldaps
        case String(kSecAttrProtocolTelnetS):
            self = .telnetS
        case String(kSecAttrProtocolIMAPS):
            self = .imaps
        case String(kSecAttrProtocolIRCS):
            self = .ircs
        case String(kSecAttrProtocolPOP3S):
            self = .pop3S
        default:
            return nil
        }
    }

    public var rawValue: String {
        switch self {
        case .ftp:
            return String(kSecAttrProtocolFTP)
        case .ftpAccount:
            return String(kSecAttrProtocolFTPAccount)
        case .http:
            return String(kSecAttrProtocolHTTP)
        case .irc:
            return String(kSecAttrProtocolIRC)
        case .nntp:
            return String(kSecAttrProtocolNNTP)
        case .pop3:
            return String(kSecAttrProtocolPOP3)
        case .smtp:
            return String(kSecAttrProtocolSMTP)
        case .socks:
            return String(kSecAttrProtocolSOCKS)
        case .imap:
            return String(kSecAttrProtocolIMAP)
        case .ldap:
            return String(kSecAttrProtocolLDAP)
        case .appleTalk:
            return String(kSecAttrProtocolAppleTalk)
        case .afp:
            return String(kSecAttrProtocolAFP)
        case .telnet:
            return String(kSecAttrProtocolTelnet)
        case .ssh:
            return String(kSecAttrProtocolSSH)
        case .ftps:
            return String(kSecAttrProtocolFTPS)
        case .https:
            return String(kSecAttrProtocolHTTPS)
        case .httpProxy:
            return String(kSecAttrProtocolHTTPProxy)
        case .httpsProxy:
            return String(kSecAttrProtocolHTTPSProxy)
        case .ftpProxy:
            return String(kSecAttrProtocolFTPProxy)
        case .smb:
            return String(kSecAttrProtocolSMB)
        case .rtsp:
            return String(kSecAttrProtocolRTSP)
        case .rtspProxy:
            return String(kSecAttrProtocolRTSPProxy)
        case .daap:
            return String(kSecAttrProtocolDAAP)
        case .eppc:
            return String(kSecAttrProtocolEPPC)
        case .ipp:
            return String(kSecAttrProtocolIPP)
        case .nntps:
            return String(kSecAttrProtocolNNTPS)
        case .ldaps:
            return String(kSecAttrProtocolLDAPS)
        case .telnetS:
            return String(kSecAttrProtocolTelnetS)
        case .imaps:
            return String(kSecAttrProtocolIMAPS)
        case .ircs:
            return String(kSecAttrProtocolIRCS)
        case .pop3S:
            return String(kSecAttrProtocolPOP3S)
        }
    }

    public var description: String {
        switch self {
        case .ftp:
            return "FTP"
        case .ftpAccount:
            return "FTPAccount"
        case .http:
            return "HTTP"
        case .irc:
            return "IRC"
        case .nntp:
            return "NNTP"
        case .pop3:
            return "POP3"
        case .smtp:
            return "SMTP"
        case .socks:
            return "SOCKS"
        case .imap:
            return "IMAP"
        case .ldap:
            return "LDAP"
        case .appleTalk:
            return "AppleTalk"
        case .afp:
            return "AFP"
        case .telnet:
            return "Telnet"
        case .ssh:
            return "SSH"
        case .ftps:
            return "FTPS"
        case .https:
            return "HTTPS"
        case .httpProxy:
            return "HTTPProxy"
        case .httpsProxy:
            return "HTTPSProxy"
        case .ftpProxy:
            return "FTPProxy"
        case .smb:
            return "SMB"
        case .rtsp:
            return "RTSP"
        case .rtspProxy:
            return "RTSPProxy"
        case .daap:
            return "DAAP"
        case .eppc:
            return "EPPC"
        case .ipp:
            return "IPP"
        case .nntps:
            return "NNTPS"
        case .ldaps:
            return "LDAPS"
        case .telnetS:
            return "TelnetS"
        case .imaps:
            return "IMAPS"
        case .ircs:
            return "IRCS"
        case .pop3S:
            return "POP3S"
        }
    }
}

extension ProtocolType {
    init?(scheme: String) {
        switch scheme {
        case "ftp":
            self = .ftp
        case "http":
            self = .http
        case "irc":
            self = .irc
        case "nntp":
            self = .nntp
        case "pop3":
            self = .pop3
        case "smtp":
            self = .smtp
        case "imap":
            self = .imap
        case "ldap":
            self = .ldap
        case "telnet":
            self = .telnet
        case "ssh":
            self = .ssh
        case "ftps":
            self = .ftps
        case "https":
            self = .https
        case "smb":
            self = .smb
        case "rtsp":
            self = .rtsp
        case "daap":
            self = .daap
        case "ipp":
            self = .ipp
        case "nntps":
            self = .nntps
        case "ldaps":
            self = .ldaps
        case "telnetS":
            self = .telnetS
        case "imaps":
            self = .imaps
        case "ircs":
            self = .ircs
        case "pop3S":
            self = .pop3S
        default:
            return nil
        }
    }
}
