# SwiftSecurity

![Platforms](https://img.shields.io/badge/platforms-ios%20-lightgrey.svg)
[![SPM supported](https://img.shields.io/badge/SPM-supported-DE5C43.svg?style=flat)](https://swift.org/package-manager)

SwiftSecurity is a modern wrapper for Keychain Services API. Use value types easily, and get extra safety and convenient compile-time checks for free. Securely store small chunks of data on behalf of the user.

## Features

* Compatability with [CryptoKit](https://developer.apple.com/documentation/cryptokit/)
* Support of Generic Password, Internet Password, SecKey and SecCertificate
* [Accessibility](#accessibility)

## Installation

### Swift Package Manager

```swift
let package = Package(
    dependencies: [
        .package(url: "https://github.com/dm-zharov/SwiftSecurity.git", from: "0.1.0")
    ]
)
```

## Usage

### Basic

```swift
// Choose Keychain
let keychain = Keychain.default

// Store secret
try keychain.store("8e9c0a7f", query: .credential(for: "OpenAI"))

// Get secret
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
                // Store value
                try? _token.store("8e9c0a7f")
            }
            Button("Delete") {
                // Remove value
                try? _token.remove()
            }
        }
        .onChange(of: token) {
            if let token {
                // Get value
            }
        }
    }
} 
```

### Web Credential

```swift
// Store value
try keychain.store(password, query: .credential(for: "login", space: .website("https://example.com"))

// Get value
let password: String? = try keychain.retrieve(query: .credential(for: "login", space: .website("https://example.com"))
```

For example, if you need to store distinct ports credentials for the same user working on the same server, you might further characterize the query by specifying protection space.

```swift
let space1 = WebProtectionSpace(host: "https://example.com", port: 443)
try keychain.store(password1, query: .credential(for: user, space: space1))

let space2 = WebProtectionSpace(host: "https://example.com", port: 8443)
try keychain.store(password2, query: .credential(for: user, space: space2))
```

## Advanced

```swift
// Create query
var query = SecItemQuery<GenericPassword>()

// Customize
query.synchronizable = true
query.service = "OpenAI"

// Perform query
try keychain.store(secret, query: query)
try keychain.retrieve(query)
try keychain.remove(query)
```

The generics system prevents API misuses at compile time:

```swift
var query = SecItemQuery<InternetPassword>()
query.synchronizable = true  // ✅ Common
query.server = "example.com" // ✅ Only for `InternetPassword`
query.service = "OpenAI"     // ❌ Only for `SecItemQuery<GenericPassword>`, so not accessible
query.keySizeInBits = 2048   // ❌ Only for `SecItemQuery<SecKey>`, so not accessible
```

Queries:
```swift
let genericPassword = SecItemQuery<GenericPassword>
let internetPassword = SecItemQuery<InternetPassword>
let secKey = SecItemQuery<SecKey>
let secCertificate = SecItemQuery<SecCertificate>
```

### Data Types

You you could store and retrieve different types of data.

```swift
Foundation:
    - Data // GenericPassword, InternetPassword
    - String // GenericPassword, InternetPassword
CryptoKit:
    - SymmetricKey, Curve25519 // GenericPassword
    - P256, P384, P521 (Elliptic Curves) // SecKey
```

If you need to support your own types, you could extend them by implementing next protocols:

```swift
// Store as Data (GenericPassword, InternetPassword)
extension CustomType: SecDataConvertible {}

// Store as Key (SecKey)
extension CustomType: SecKeyConvertible {}
```

This protocol implementation is inspired by Apple's sample code [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain) 

## Choose Keychain

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

## <a name="accessibility"> Accessibility

Default accessibility is suitable for background running applications (`.afterFirstUnlock`, `kSecAttrAccessibleAfterFirstUnlock`). That is not the most secure way to store items, so you might consider to change it.

### Store

```swift
try keychain.store(
    secret,
    query: .credential(for: "FBI"),
    accessControl: .init(.whenUnlocked)
)

try keychain.store(
    secret,
    query: .credential(for: "FBI"),
    accessControl: .init(.whenUnlocked, options: .biometryAny) // Requires user authentication
)

```

### Get

```swift
// Create an LAContext
var context = LAContext()

// Authenticate
do {
    let success = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Log in with Biometrics")
} else {
    // Handle LAError error
}

// Check for authentication 
if success {
    // Get value
    try keychain.retrieve(.credential(for: "FBI"), authenticationContext: context)
}

```

Include the [NSFaceIDUsageDescription](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW75) key in your app’s Info.plist file if your app allows biometric authentication. Otherwise, authorization requests may fail.


## Defaults

The framework’s default behavior provides a reasonable trade-off between security and accessibility.

- `kSecUseDataProtectionKeychain == true`. This attribute helps to improve the portability of code across platforms.
- `kSecAttrAccessibleWhenUnlocked`. This attribute makes keychain items accessible from `background` by default.

## Knowledge

* [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain)
* [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

## Author

Dmitriy Zharov, contact@zharov.dev

## License

SwiftSecurity is available under the MIT license. See the [LICENSE file](https://github.com/dm-zharov/SwiftSecurity/blob/master/LICENSE) for more info.
