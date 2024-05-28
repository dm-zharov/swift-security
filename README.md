# SwiftSecurity

[![Platforms](https://img.shields.io/badge/platforms-_iOS_|_macOS_|_watchOS_|_tvOS_|_visionOS-lightgrey.svg?style=flat)](https://developer.apple.com/resources/)
[![SPM supported](https://img.shields.io/badge/SPM-supported-DE5C43.svg?style=flat)](https://swift.org/package-manager)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://mit-license.org)

SwiftSecurity is a modern Swift API for Apple [Security](https://developer.apple.com/documentation/security) framework (Keychain API, SharedWebCredentials API, Cryptography, etc). Secure the data your app manages in a much easier way with compile-time checks. 

## Features

How does SwiftSecurity differ from other popular frameworks?

* Supports every [Keychain item](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_class_keys_and_values) (Generic & Internet Password, Key, Certificate and Identity).
* Provides consistent behavior across platforms. Verified through [apple-oss-distributions/Security](https://github.com/apple-oss-distributions/Security).
* Follows recommendations from [DTS Engineer](https://forums.developer.apple.com/forums/thread/707279). Excludes legacy from OS X.
* Prevents usage of an incorrect set of [attributes](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values) for Keychain items.
* Compatible with [CryptoKit](https://developer.apple.com/documentation/cryptokit/), [SwiftUI](https://developer.apple.com/documentation/swiftui/) and [apple/swift-certificates](https://github.com/apple/swift-certificates).

## Installation

#### Requirements

* iOS 14.0+ / macOS 11.0+ / Mac Catalyst 14.0+ / watchOS 7.0+ / tvOS 14.0+ / visionOS 1.0+
* Swift 5.9

#### Swift Package Manager

To use the `SwiftSecurity`, add the following dependency in your `Package.swift`:
```swift
.package(url: "https://github.com/dm-zharov/swift-security.git", from: "2.0.0")
```

Finally, add `import SwiftSecurity` to your source code.

## Quick Start

####  Basic

```swift
// Choose Keychain
let keychain = Keychain.default

// Store secret
try keychain.store("8e9c0a7f", query: .credential(for: "OpenAI"))

// Retrieve secret
let token: String? = try keychain.retrieve(.credential(for: "OpenAI"))

// Remove secret
try keychain.remove(.credential(for: "OpenAI"))
```

#### Basic (SwiftUI)

```swift
struct AuthView: View {
    @Credential("OpenAI") private var token: String?

    var body: some View {
        VStack {
            Button("Save") {
                // Store secret
                try? _token.store("8e9c0a7f")
            }
            Button("Delete") {
                // Remove secret
                try? _token.remove()
            }
        }
        .onChange(of: token) {
            if let token {
                // Use secret
            }
        }
    }
} 
```

#### Web Credential

A password for a website or an area on a server, that requires authentication.

```swift
// Store password for a website
try keychain.store(
    password, query: .credential(for: "username", space: .website("https://example.com"))
)

// Retrieve password for a website
let password: String? = try keychain.retrieve(
    .credential(for: "username", space: .website("https://example.com"))
)
```

For example, if you need to store distinct ports credentials for the same user working on the same server, you might further characterize the query by specifying protection space.

```swift
let space1 = WebProtectionSpace(host: "example.com", port: 443)
try keychain.store(password1, query: .credential(for: user, space: space1))

let space2 = WebProtectionSpace(host: "example.com", port: 8443)
try keychain.store(password2, query: .credential(for: user, space: space2))
```

#### Get Attributes

```swift
if let info = try keychain.info(for: .credential(for: "OpenAI")) {
    // Creation date
    print(info.creationDate)
    // Comment
    print(info.comment)
    ...
}
```

#### Error Handling

`SwiftSecurityError` offers values for the most common issues. 

```swift
do {
    try keychain.store("8e9c0a7f", query: .credential(for: "OpenAI"))
} catch {
    switch error as? SwiftSecurityError {
    case .duplicateItem:
        // handle duplicate
    default:
        // unhandled
    }
}
```

If case of the rare issue, you'll receive `.underlyingSecurityError(error:)` with an `OSStatus` code that can be matched with underlying [Security Framework Result Codes](https://developer.apple.com/documentation/security/1542001-security_framework_result_codes).

#### Remove All

```swift
// Removes everything from a keychain
try keychain.removeAll()

// Removes everything from a keychain, including distributed to other devices credentials through iCloud
try keychain.removeAll(includingSynchronizableCredentials: true)
```

## 🛠️ Usage

#### Get Data & Persistent Reference

If you're working with `NEVPNProtocol`, you likely need to access persistent reference to `password` or `identity`.

```swift
// Retrieve multiple values at once
if case let .dictionary(info) = try keychain.retrieve([.data, .persistentReference], query: .credential(for: "OpenAI")) {
    // Data
    info.data
    // Persistent Reference
    info.persistentReference
}

// Retrieve persistent reference right after storing the secret
if case let .persistentReference(data) = try keychain.store(
    "8e9c0a7f",
    returning: .persistentReference, /* OptionSet */
    query: .credential(for: "OpenAI")
) {
    // Persistent Reference
    data
}
```

#### CryptoKit

`SwiftSecurity` lets you natively store `CryptoKit` keys as native `SecKey` instances. [Key types supporting such conversion](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain#3369556), like `P256`/`P384`/`P521`, conform to `SecKeyConvertible` protocol.

```swift
// Store private key
let privateKey = P256.KeyAgreement.PrivateKey()
try keychain.store(privateKey, query: .key(for: "Alice"))

// Retrieve private key (+ public key)
let privateKey: P256.KeyAgreement.PrivateKey? = try keychain.retrieve(.privateKey(for: "Alice"))
let publicKey = privateKey.publicKey /* Recommended */

// Store public key. Not recommended, as you can generate it
try keychain.store(
    publicKey,
    query: .key(for: "Alice", descriptor: .ecPublicKey)
)
```

Other key types, like `SymmetricKey`, `Curve25519`, `SecureEnclave.P256`, have no direct keychain corollary. In particular, `SecureEnclave.P256.PrivateKey` is an encrypted block that only the same `Secure Enclave` can later use to restore the key, not the key itself. These types conform to `SecDataConvertible`, so store them as follows:

```swift
// Store symmetric key
let symmetricKey = SymmetricKey(size: .bits256)
try keychain.store(symmetricKey, query: .credential(for: "Chat"))
```

> [!NOTE]
> `SecKey` supports only `P-256, P-384, P-521 Elliptic Curve` and `RSA` keys. For more details, see [On Cryptographic Key Formats](https://developer.apple.com/forums/thread/680554).

#### Certificate

DER-Encoded X.509 Certificate.

```swift
// Prepare certificate
let certificateData: Data // Content of file, often with `cer`/`der` extension 
try certificate = Certificate(derRepresentation: certificateData)

// Store certificate
try keychain.store(certificate, query: .certificate(for: "Root CA"))
```

You could use `SwiftSecurity` simultaneously with `X509` package from [apple/swift-certificates](https://github.com/apple/swift-certificates). In case of `Swift Package Manager` dependency resolve issues, copy `SecCertificateConvertible` conformance directly to your project.

#### Digital Identity

A digital identity is the combination of a certificate and the private key that matches the public key within certificate.

```swift
// Import digital identity from `PKCS #12` data
let pkcs12Data: Data // Content of file, often with `p12` extension
for importItem in try PKCS12.import(pkcs12Data, passphrase: "8e9c0a7f") {
    if let identity = importItem.identity {
        // Store digital identity
        try keychain.store(identity, query: .identity(for: "Apple Development"))
    }
}

// Retrieve digital identity
if let identity = try keychain.retrieve(.identity(for: "Apple Development")) {
    identity.rawRepresentation // SecIdentity
}
```

The system stores certificate and private key separately.

#### Custom Query

```swift
// Create query
var query = SecItemQuery<GenericPassword>()

// Customize query
query.synchronizable = true
query.service = "OpenAI"
query.label = "OpenAI Access Token"

// Perform query
try keychain.store(secret, query: query, accessPolicy: AccessPolicy(.whenUnlocked, options: .biometryAny))
_ = try keychain.retrieve(query, authenticationContext: LAContext())
try keychain.remove(query)
```

Query prevents the creation of an incorrect set of attributes for item:

```swift
var query = SecItemQuery<InternetPassword>()
query.synchronizable = true  // ✅ Common
query.server = "example.com" // ✅ Only for `InternetPassword`
query.service = "OpenAI"     // ❌ Only for `GenericPassword`, so not accessible
query.keySizeInBits = 2048   // ❌ Only for `SecKey`, so not accessible
```

Possible queries:

```swift
SecItemQuery<GenericPassword>  // kSecClassGenericPassword
SecItemQuery<InternetPassword> // kSecClassInternetPassword
SecItemQuery<SecKey>           // kSecClassSecKey
SecItemQuery<SecCertificate>   // kSecClassSecCertificate
SecItemQuery<SecIdentity>      // kSecClassSecIdentity
```

#### Debug

```swift
// Print Keychain (or use LLDB `po` command)
print(keychain.debugDescription)

// Print Query
print(query.debugDescription)

// Output -> ["Class: GenericPassword", ..., "Service: OpenAI"]
```

## 🔑 How to Choose Keychain

#### Default

```swift
let keychain = Keychain.default
```

The system considers the first item in the list of [keychain access groups](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps/) to be the app’s default access group, evaluated in this order:
- The optional [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups) holds an array of strings, each of which names an access group.
- Application identifier, formed as the team identifier (team ID) plus the bundle identifier (bundle ID). For example, `J42EP42PB2.com.example.app`.

If the [Keychain Sharing](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing#Specify-the-default-keychain-group) capability is not enabled, the default access group is `app ID`.

> [!NOTE]
> To enable macOS support, make sure to include the [Keychain Sharing (macOS)](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing#Specify-the-default-keychain-group) capability and create a group `${TeamIdentifierPrefix}com.example.app`, to prevent errors in operations. This sharing group is [automatically generated](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps/#2974917) for other platforms and accessible without capability. You could refer to [TestHost](https://github.com/dm-zharov/swift-security/tree/main/Tests/TestHost.xcodeproj) for information regarding project configuration.

#### Sharing within Keychain Group

If you prefer not to rely on the automatic behavior of default storage selection, you have the option to explicitly specify a keychain sharing group.

```swift
let keychain = Keychain(accessGroup: .keychainGroup(teamID: "J42EP42PB2", nameID: "com.example.app"))
```

#### Sharing within App Group

Sharing could also be achieved by using [App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups) capability. Unlike a keychain sharing group, the app group can’t automatically became the default storage for keychain items. You might already be using an app group, so it's probably would be the most convenient choice.

```swift
let keychain = Keychain(accessGroup: .appGroupID("group.com.example.app"))
```

> [!NOTE]
> Use `Sharing within Keychain Group` for sharing on macOS, as the described behavior is not present on this platform. There's no issue with using one sharing solution on one platform and a different one on another.

## 🔓 Protection with Face ID (Touch ID) and Passcode

#### Store protected item

```swift
// Store with specified `AccessPolicy`
try keychain.store(
    secret,
    query: .credential(for: "FBI"),
    accessPolicy: AccessPolicy(.whenUnlocked, options: .userPresence) // Requires biometry/passcode authentication
)
```

#### Retrieve protected item

If you request the protected item, an authentication screen will automatically appear.

```swift
// Retrieve value
try keychain.retrieve(.credential(for: "FBI"))
```

If you want to manually authenticate before making a request or customize authentication screen, provide [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext) to the retrieval method.

```swift
// Create an LAContext
var context = LAContext()

// Authenticate
do {
    let success = try await context.evaluatePolicy(
        .deviceOwnerAuthentication,
        localizedReason: "Authenticate to proceed." // Authentication prompt
    )
} else {
    // Handle LAError error
}

// Check authentication result 
if success {
    // Retrieve value
    try keychain.retrieve(.credential(for: "FBI"), authenticationContext: context)
}

```

> [!WARNING]
> Include the [NSFaceIDUsageDescription](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW75) key in your app’s Info.plist file. Otherwise, authentication request may fail.

## ℹ️ Data Types

You can store, retrieve, and remove various types of values.

```swift
Foundation:
    - Data /* GenericPassword, InternetPassword */
    - String /* GenericPassword, InternetPassword */
CryptoKit:
    - SymmetricKey /* GenericPassword */
    - Curve25519 -> PrivateKey /* GenericPassword */
    - SecureEnclave.P256 -> PrivateKey /* GenericPassword (SE's Key Data is Persistent Reference) */
    - P256, P384, P521 -> PrivateKey /* SecKey (ANSI x9.63 Elliptic Curves) */
X509 (external package `apple/swift-certificates`):
    - Certificate /* SecCertificate */
SwiftSecurity:
    - Certificate /* SecCertificate */
    - PKCS12.Blob: /* Import as SecIdentity */
        - DigitalIdentity /* SecIdentity (The Pair of SecCertificate and SecKey) */
```

To add support for custom types, you can extend them by conforming to the following protocols.

```swift
// Store as Data (GenericPassword, InternetPassword)
extension CustomType: SecDataConvertible {}

// Store as Key (ANSI x9.63 Elliptic Curves or RSA Keys)
extension CustomType: SecKeyConvertible {}

// Store as Certificate (X.509)
extension CustomType: SecCertificateConvertible {}

// Store as Identity (The Pair of Certificate and Private Key)
extension CustomType: SecIdentityConvertible {}
```

These protocols are inspired by Apple's sample code from the [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain) article.

## 🔑 Shared Web Credential

> [!TIP]
> [SharedWebCredentials API](https://developer.apple.com/documentation/security/shared_web_credentials) makes it possible to share credentials with the website counterpart. For example, a user may log in to a website in Safari and save credentials to the iCloud Keychain. Later, the user may run an app from the same developer, and instead of asking the user to reenter a username and password, it could access the existing credentials. The user can create new accounts, update passwords, or delete account from within the app. These changes should be saved from the app to be used by Safari.

```swift
// Store
SharedWebCredential.store("https://example.com", account: "username", password: "secret") { result in
    switch result {
    case .failure(let error):
        // Handle error
    case .success:
        // Handle success
    }
}

// Remove
SharedWebCredential.remove("https://example.com", account: "username") { result in
    switch result {
    case .failure(let error):
        // Handle error
    case .success:
        // Handle success
    }
}

// Retrieve
// - Use `ASAuthorizationController` to make an `ASAuthorizationPasswordRequest`.
```

## 🔒 Secure Data Generator

```swift
// Data with 20 uniformly distributed random bytes
let randomData = try SecureRandomDataGenerator(count: 20).next()
```

## Security

The framework’s default behavior provides a reasonable balance between convenience and accessibility.

- `kSecUseDataProtectionKeychain: true` helps to achieve [consistent behavior across platforms](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain), so it shouldn't and cannot be changed.
- `kSecAttrAccessibleAfterFirstUnlock` makes keychain items [accessible from background state](https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlock), yet changeable by using `AccessPolicy`.

## Communication

- If you **found a bug**, open an issue.
- If you **have a feature request**, open an issue.
- If you **want to contribute**, submit a pull request.

## Knowledge

* [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps/)
* [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain)
* [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
* [On Cryptographic Key Formats](https://developer.apple.com/forums/thread/680554)
* [SecItem: Fundamentals](https://developer.apple.com/forums/thread/724023)
* [SecItem: Pitfalls and Best Practices](https://developer.apple.com/forums/thread/724013)

## Author

Dmitriy Zharov, contact@zharov.dev

## License

SwiftSecurity is available under the MIT license. See the [LICENSE file](https://github.com/dm-zharov/swift-security/blob/master/LICENSE) for more info.
