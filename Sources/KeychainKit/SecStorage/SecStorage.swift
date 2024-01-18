//
//  SecStorage.swift
//
//
//  Created by Dmitriy Zharov on 16.01.2024.
//

import SwiftUI
import Security

@available(iOS 14.0, *)
@propertyWrapper public struct SecStorage<Value>: DynamicProperty where Value: GenericPasswordConvertible {
    @StateObject private var provider: SecItemProvider<Value>
    
    public var wrappedValue: Value? {
        get { provider() }
        nonmutating set { provider(newValue) }
    }
    
    public var secError: Error? {
        provider.error
    }
    
    public init(_ account: String, synchronizable: Bool = false, store: GenericPasswordStore? = nil) {
        var query = SecItemQuery<GenericPassword>()
        query.account = account
        query.synchronizable = synchronizable

        self.init(query: query, store: store)
    }
    
    public init(query: SecItemQuery<GenericPassword>, store: GenericPasswordStore? = nil) {
        _provider = StateObject(
            wrappedValue: SecItemProvider(query: query, store: store ?? Keychain())
        )
    }
}

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
            self.error = nil
        } catch {
            self.error = error
        }
    }
    
    init(query: SecItemQuery<GenericPassword>, store: GenericPasswordStore) {
        self.query = query
        self.store = store
    }
}
