# SwiftSecurity

![Platforms](https://img.shields.io/badge/platforms-ios%20-lightgrey.svg)
[![SPM supported](https://img.shields.io/badge/SPM-supported-DE5C43.svg?style=flat)](https://swift.org/package-manager)

SwiftSecurity is a modern wrapper for Keychain Services API. Use value types easily, and get extra safety and convenient compile-time checks for free.

## Features

* Simple
* Static typing and compile-time checks
* Seamless compatability with [CryptoKit](https://developer.apple.com/documentation/cryptokit/)
* Support Generic & Internet passwords, Keys
* Easy way to implement support for custom types
* [Accessibility](#accessibility)

Securely store small chunks of data on behalf of the user.

The framework’s default behavior provides a reasonable trade-off between security and accessibility.

## Installation

### Swift Package Manager

```swift
let package = Package(
    dependencies: [
        .Package(url: "https://github.com/dm-zharov/SwiftSecurity.git")
    ]
)
```

## Usage

### Basic

```swift
// 
let keychain = Keychain.default

// Store value
try Keychain.default.store("8e9c0a7f", query: .credential(for: "OpenAI"))

// Get value
let token: String? = try Keychain.default.retrieve(.credential(for: "OpenAI"))

// Remove value
try Keychain.default.remove(.credential(for: "OpenAI"))
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

### Keychain

```swift
Keychain.default // == Keychain(accessGroup: .application)
Keychain(accessGroup: .applicationGroup("group.com.example.app"))
```

## Instantiation

```swift
// Generic password
let secret: Data? = try keychain.retrieve(.credential(for: "Messaging"))
let key: SymmetricKey? = try keychain.retrieve(.credential(for: "Messaging"))

// Internet password
let password: String? = try keychain.retrieve(.credential(for: "mymail@gmail.com", space: .server("http://google.com")))
```

#### Retrieve Secret

```swift
let token: String? = try? Keychain.default.retrieve(.credential(for: "OpenAI"))
```

## <a name="accessibility"> Access Control

```swift
try keychain.store(secret, query: .credential(for: "FBI", accessControl: .init(.whenUnlocked)))
try keychain.store(secret, query: .credential(for: "FBI", accessControl: .init(.whenUnlocked, options: .biometryAny)))

```

Default accessibility matches background application (`kSecAttrAccessibleAfterFirstUnlock`).

## Advanced

```swift
var query = SecItemQuery<InternetPassword>()
query.synchronizable = true // ✅ Common attribute
query.protocol = .https // ✅ `InternetPassword` attribute
query.service = "Some label" // ❌ Compile error. Only `GenericPassword` has this attribute
...
query.keySizeInBits // ❌ Compile error. Only `SecKey` has this attribute.

try keychain.store(secret, query: query)
```

## Custom Types

In order to store/retrieve your own custom type that isn't supported, you need to conform `SecDataConvertible` for generic data (could be stored as `Generic or Internet Password`).

```swift
// `SecDataConvertible` -> Generic or Internet password
Foundation:
    - String
    - Data
CryptoKit: 
    - SymmetricKey
    - Curve25519.KeyAgreement.PrivateKey
    - Curve25519.Signing.PrivateKey
    - SecureEnclave.P256.KeyAgreement.PrivateKey
    - SecureEnclave.P256.Signing.PrivateKey

// `SecKeyConvertible` -> SecKey
CryptoKit:
    P256.KeyAgreement.PrivateKey
    P256.Signing.PrivateKey
    P384.KeyAgreement.PrivateKey
    P384.Signing.PrivateKey
    P521.KeyAgreement.PrivateKey
    P521.Signing.PrivateKey
```

This protocol implementation is inspired by Apple's sample code [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain) 

## Defaults

- `kSecUseDataProtectionKeychain == true`. This key helps to improve the portability of your code across platforms.
- `kSecAttrAccessibleWhenUnlocked`.

## Privacy Manifest

[TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

## License

SwiftSecurity is available under the MIT license. See the [LICENSE file](https://github.com/dm-zharov/SwiftSecurity/blob/master/LICENSE) for more info.
