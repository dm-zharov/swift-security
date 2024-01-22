# SwiftSecurity

[![Platforms](https://img.shields.io/badge/platform-iOS_|_macOS_|_watchOS_|_tvOS_|_visionOS-lightgrey.svg?style=flat)](https://developer.apple.com/resources/)
[![SPM supported](https://img.shields.io/badge/SPM-supported-DE5C43.svg?style=flat)](https://swift.org/package-manager)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://mit-license.org)

SwiftSecurity is a modern Swift wrapper for Security API (Keychain Services, SharedWebCredentials). Use value types and get safety and convenient compile-time checks.

## 🌟 Features

What the difference between **SwiftSecurity** and any other wrapper?

* Support for every [Keychain item class](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_class_keys_and_values): Generic & Internet Password, Key, Certificate and Identity
* Generic code prevents the creation of an incorrect set of attributes for items
* Compatability with [CryptoKit](https://developer.apple.com/documentation/cryptokit/)
* Compatability with [SwiftUI](https://developer.apple.com/documentation/swiftui/)
* Native-like API experience

## ⚙️ Installation

### Swift Package Manager

```swift
let package = Package(
    dependencies: [
        .package(url: "https://github.com/dm-zharov/SwiftSecurity.git", from: "1.0.0")
    ]
)
```

##  📖 Quick Start

###  Basic

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

### Basic (SwiftUI)

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

### 🕸️ Web Credential

```swift
// Store value
try keychain.store(
    password, query: .credential(for: "login", space: .website("https://example.com")
)

// Retrieve value
let password: String? = try keychain.retrieve(
    .credential(for: "login", space: .website("https://example.com")
)
```

For example, if you need to store distinct ports credentials for the same user working on the same server, you might further characterize the query by specifying protection space.

```swift
let space1 = WebProtectionSpace(host: "https://example.com", port: 443)
try keychain.store(password1, query: .credential(for: user, space: space1))

let space2 = WebProtectionSpace(host: "https://example.com", port: 8443)
try keychain.store(password2, query: .credential(for: user, space: space2))
```

### 👨‍💻 Advanced

```swift
// Create query
var query = SecItemQuery<GenericPassword>()

// Customize
query.synchronizable = true
query.service = "OpenAI"
query.label = "OpenAI Access Token"

// Perform query
try keychain.store(secret, query: query, accessPolicy: .init(.whenUnlocked, options: .biometryAny))
try keychain.retrieve(query, authenticationContext: LAContext())
try keychain.remove(query)
```

The generics system prevents API misuses at compile time:

```swift
var query = SecItemQuery<InternetPassword>()
query.synchronizable = true  // ✅ Common
query.server = "example.com" // ✅ Only for `InternetPassword`
query.service = "OpenAI"     // ❌ Only for `GenericPassword`, so not accessible
query.keySizeInBits = 2048   // ❌ Only for `SecKey`, so not accessible
```

Queries:
```swift
SecItemQuery<GenericPassword>   // kSecClassGenericPassword
SecItemQuery<InternetPassword>  // kSecClassInternetPassword
SecItemQuery<SecKey>.           // kSecClassSecKey
SecItemQuery<SecCertificate>    // kSecClassSecCertificate
SecItemQuery<SecIdentity>       // kSecClassSecIdentity
```

### ✍️ Other

#### Get Attribute

```swift
// Get attributes
if let info = try keychain.info(for: .credential(for: "OpenAI")) {
    // Creation date
    print(info.creationDate)
    // Comment
    print(info.comment)
    ...
}
```

#### Remove All

```swift
try keychain.removeAll()
```

#### Debug

```swift
// Print all attributes
print(query.debugDescription)

// Print all items
print(keychain.debugDescription)
```

## 🤔 Choose Keychain

### Default
```swift
let keychain = Keychain.default
```

The system considers the default storage by list of [access groups](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps/) in this order:
- If [Keychain Sharing](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing) capability enabled, then by the first entry in the app’s [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups).
- Otherwise, by the application bundle identifier.

### Sharing within Keychain Group

[Keychain Sharing](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing) capability makes it possible to share keychain items between multiple apps belonging to the same developer (or between an app and extensions).

If you don't want to rely on the automatic behavior of default storage selection, you could explicitly specify a keychain sharing group.

```swift
let keychain = Keychain(accessGroup: .keychainGroup(teamID: "J42EP42PB2", nameID: "com.example.app"))
```

### Sharing within App Group

The same sharing behavior could also be achieved by using [App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups) capability. Unlike a keychain sharing group, the app group can’t automatically became the default storage for keychain items. You might already be using an app group, so it's probably the most convenient choice.

```swift
let keychain = Keychain(accessGroup: .appGroupID("group.com.example.app"))
```

## 🔓 Protection with Face ID (Touch ID) and Passcode

### Store protected item

```swift
try keychain.store(
    secret,
    query: .credential(for: "FBI"),
    accessPolicy: AccessPolicy(.whenUnlocked, options: .userPresence) // Requires biometry/passcode authentication
)
```

### Retrieve protected item

If you requested the protected item, an authentication screen will appear automatically.

```swift
// Retrieve value
try keychain.retrieve(.credential(for: "FBI"), authenticationContext: context)
```

If you want manually perform authentication before making a request, provide an evaluated [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext) to the `retrieve()` and `info()` methods.

```swift
// Create an LAContext
var context = LAContext()

// Authenticate
do {
    let success = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate to proceed.")
} else {
    // Handle LAError error
}

// Check authentication result 
if success {
    // Retrieve value
    try keychain.retrieve(.credential(for: "FBI"), authenticationContext: context)
}

```

Include the [NSFaceIDUsageDescription](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW75) key in your app’s Info.plist file if your app allows biometric authentication. Otherwise, authorization requests may fail.

## 🔖 Custom Type

You you could store and retrieve different types of data.

```swift
Foundation:
    - Data // GenericPassword, InternetPassword
    - String // GenericPassword, InternetPassword
CryptoKit:
    - SymmetricKey // GenericPassword
    - Curve25519 // GenericPassword
    - P256, P384, P521 // SecKey (Elliptic Curves)
SwiftSecurity:
    - X509.DER.Data // SecCertificate (DER-Encoded X.509 Data)
    - PKCS12.Data // SecIdentity  (PKCS #12 Blob)
```

If you need to support your own types, you could extend them by implementing next protocols:

```swift
// Store as Data (GenericPassword, InternetPassword)
extension CustomType: SecDataConvertible {}

// Store as Key (SecKey)
extension CustomType: SecKeyConvertible {}

// Store as Certificate (X.509)
extension CustomType: SecCertificateConvertible {}

// Import as Identity (PKCS #12)
extension CustomType: SecIdentityConvertible {}
```

This protocols are inspired by Apple's sample code [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain).

## Security

The framework’s default behavior provides a reasonable trade-off between security and accessibility.

- `kSecUseDataProtectionKeychain: true`. This attribute helps to improve the portability of code across platforms.
- `kSecAttrAccessibleWhenUnlocked`. This attribute makes keychain items accessible from `background` processes.

## Knowledge

* [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps/)
* [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain)
* [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

## Requirements

* iOS 14.0
* macOS 11.0
* macCatalyst 14.0
* watchOS 7.0
* tvOS 14.0
* visionOS 1.0

## Author

Dmitriy Zharov, contact@zharov.dev

## License

SwiftSecurity is available under the MIT license. See the [LICENSE file](https://github.com/dm-zharov/SwiftSecurity/blob/master/LICENSE) for more info.
