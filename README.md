# SwiftSecurity

SwiftSecurity is a modern wrapper for Keychain Services API

## Features

* Static typing and compile-time checks
* Seamless compatability with CryptoKit
* Support Generic & Internet passwords, Keys
* Easy way to implement support for custom types

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
// Store value
try Keychain.default.store("8e9c0a7f", query: .credential(for: "OpenAI"))

// Get value
let token: String? = try Keychain.default.retrieve(.credential(for: "OpenAI"))

// Remove value
try Keychain.default.remove(.credential(for: "OpenAI"))
```

#### Basic (SwiftUI)

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

## Keychain

```swift
Keychain.default // Keychain(accessGroup: .application)
Keychain(accessGroup: .applicationGroup("group.com.example.app"))
```

## Custom Types

In order to store/retrieve your own custom type that isn't supported, you need to conform `SecDataConvertible` for generic data (could be stored as `Generic or Internet Password`).

```swift
// `SecDataConvertible` -> Generic or Internet password
* Foundation
    * `String`
    * `Data`
* CryptoKit: 
    * SymmetricKey
    * Curve25519.KeyAgreement.PrivateKey
    * Curve25519.Signing.PrivateKey
    * SecureEnclave.P256.KeyAgreement.PrivateKey
    * SecureEnclave.P256.Signing.PrivateKey

// `SecKeyConvertible` -> SecKey
* CryptoKit:
    * P256.KeyAgreement.PrivateKey
    * P256.Signing.PrivateKey
    * P384.KeyAgreement.PrivateKey
    * P384.Signing.PrivateKey
    * P521.KeyAgreement.PrivateKey
    * P521.Signing.PrivateKey
```

You could extend types by conforming `SecDataConvertible` (for `Generic or Internet Password`)

## Privacy Manifest

[TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

## License

SwiftSecurity is available under the MIT license. See the [LICENSE file](https://github.com/dm-zharov/SwiftSecurity/blob/master/LICENSE) for more info.
