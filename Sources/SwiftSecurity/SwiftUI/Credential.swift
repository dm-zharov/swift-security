//
//  Credential.swift
//
//
//  Created by Dmitriy Zharov on 16.01.2024.
//

import SwiftUI
import Security

/// A property wrapper type that reflects a value from secure storage and invalidates a view on a change in value.
@propertyWrapper public struct Credential<Value>: DynamicProperty where Value: SecDataConvertible {
    @StateObject private var provider: SecItemProvider<Value>
    
    /// The value from the secure storage.
    public var wrappedValue: Value? {
        get { provider() }
    }
    
    /// An error encountered during the most recent operation on secure storage.
    public var fetchError: Error? {
        provider.fetchError
    }
    
    public func store(_ value: Value) throws {
        try provider(set: value)
    }
    
    public func remove() throws {
        try provider(set: nil)
    }
    
    /// Creates a property that can read and write to a secure storage.
    /// - Parameters:
    ///   - account: A string indicating the item's account name.
    ///   - synchronizable: A string indicating whether the item synchronizes through iCloud.
    ///   - store: The secure store to read and write to. A value of nil will use the default.
    public init(_ service: String, store: Keychain = .default) {
        self.init(query: .credential(for: service), store: store)
    }
    
    /// Creates a property that can read and write to a secure storage.
    /// - Parameters:
    ///   - query: A query to the secure storage.
    ///   - store: The secure store to read and write to. A value of nil will use the default.
    public init(query: SecItemQuery<GenericPassword>, store: Keychain = .default) {
        _provider = StateObject(
            wrappedValue: SecItemProvider(query: query, store: store)
        )
    }
}

final private class SecItemProvider<Value>: ObservableObject where Value: SecDataConvertible {
    private let query: SecItemQuery<GenericPassword>
    private let store: SecDataStore
    
    private var value: Value?
    private(set) var fetchError: Error?
    
    func callAsFunction() -> Value? {
        guard value == nil else {
            return value
        }
        
        do {
            self.value = try store.retrieve(query, authenticationContext: nil)
            self.fetchError = nil
        } catch {
            self.fetchError = error
        }
        
        return value
    }
    
    func callAsFunction(set newValue: Value?) throws {
        objectWillChange.send()
        
        if let newValue {
            try store.store(newValue, query: query, accessPolicy: .default)
        } else {
            _ = try store.remove(query)
        }
        
        self.value = nil
    }
    
    init(query: SecItemQuery<GenericPassword>, store: SecDataStore) {
        self.query = query
        self.store = store
    }
}
