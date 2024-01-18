//
//  SecStorage.swift
//
//
//  Created by Dmitriy Zharov on 16.01.2024.
//

import SwiftUI
import Security

/// A property wrapper type that reflects a value from secure storage and invalidates a view on a change in value.
@available(iOS 14.0, *)
@propertyWrapper public struct SecStorage<Value>: DynamicProperty where Value: GenericPasswordConvertible {
    @StateObject private var provider: SecItemProvider<Value>
    
    /// The value from the secure storage.
    public var wrappedValue: Value? {
        get { provider() }
        nonmutating set { provider(newValue) }
    }
    
    /// An error encountered during the most recent operation on secure storage.
    public var secError: Error? {
        provider.error
    }
    
    /// Creates a property that can read and write to a secure storage.
    /// - Parameters:
    ///   - account: A string indicating the item's account name.
    ///   - synchronizable: A string indicating whether the item synchronizes through iCloud.
    ///   - store: The secure store to read and write to. A value of nil will use the default.
    public init(_ account: String, synchronizable: Bool = false, store: GenericPasswordStore = Keychain.default) {
        var query = SecItemQuery<GenericPassword>()
        query.account = account
        query.synchronizable = synchronizable

        self.init(query: query, store: store)
    }
    
    public init(_ server: String, )
    
    /// Creates a property that can read and write to a secure storage.
    /// - Parameters:
    ///   - query: A query to the secure storage.
    ///   - store: The secure store to read and write to. A value of nil will use the default.
    public init(query: SecItemQuery<GenericPassword>, store: GenericPasswordStore = Keychain.default) {
        _provider = StateObject(
            wrappedValue: SecItemProvider(query: query, store: store)
        )
    }
}

@available(iOS 14.0, *)
final private class SecItemProvider<Value>: ObservableObject where Value: GenericPasswordConvertible {
    private let query: SecItemQuery<GenericPassword>
    private let store: GenericPasswordStore
    
    private var value: Value?
    private(set) var error: Error?
    
    func callAsFunction() -> Value? {
        guard value == nil else {
            return value
        }
        
        do {
            self.value = try store.retrieve(query)
        } catch {
            self.error = error
        }
        
        return value
    }
    
    func callAsFunction(_ newValue: Value?) {
        objectWillChange.send()
        
        do {
            if let newValue {
                try store.store(newValue, query: query)
            } else {
                _ = try store.remove(query: query)
            }
            
            self.value = newValue
        } catch {
            self.error = error
        }
        
        self.error = nil
    }
    
    init(query: SecItemQuery<GenericPassword>, store: GenericPasswordStore) {
        self.query = query
        self.store = store
    }
}
