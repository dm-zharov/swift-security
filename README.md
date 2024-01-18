# SwiftSecurity

Securely store small chunks of data on behalf of the user.

The framework’s default behavior provides a reasonable trade-off between security and accessibility.

## Swift

```swift

```

## SwiftUI

```swift
struct AuthView: View {
    @Credential("OpenAI") private var token: String?

    var body: some View {
        VStack {
            TextField("Access Token", text: $someText)

            Button("Confirm") {
                token = someText
            }
        }
        .onChange(of: token) {
            if let token {
                // perform authorization
            }
        }
    }
} 
```

[TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
